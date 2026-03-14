package main

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

// AutoScanner periodically tests resolvers using HMAC challenge-response
// verification and selects the top N verified resolvers for the active pool.
//
// On startup it signals readiness as soon as topN verified resolvers are found,
// allowing the tunnel to start early without waiting for the full scan.
// When a resolver goes down, TriggerRescan() can be called to immediately
// search for a replacement.
type AutoScanner struct {
	pool         *ResolverPool
	allResolvers []Resolver // full list for re-scanning (never filtered)
	scanDomain   string
	doh          bool
	pubkey       []byte // server public key for HMAC verify
	interval     time.Duration
	topN         int // target count of verified resolvers to keep
	maxSteps     int // max resolvers to test per scan round (0 = all)
	workers      int // scan concurrency
	stopCh       chan struct{}
	rescanCh     chan struct{} // trigger rescan when a resolver fails
	readyCh      chan struct{} // closed when first batch of resolvers is ready
	readyOnce    sync.Once
}

func NewAutoScanner(pool *ResolverPool, allResolvers []Resolver, scanDomain string, doh bool,
	pubkey []byte, interval time.Duration, topN, maxSteps, workers int) *AutoScanner {
	return &AutoScanner{
		pool:         pool,
		allResolvers: allResolvers,
		scanDomain:   scanDomain,
		doh:          doh,
		pubkey:       pubkey,
		interval:     interval,
		topN:         topN,
		maxSteps:     maxSteps,
		workers:      workers,
		stopCh:       make(chan struct{}),
		rescanCh:     make(chan struct{}, 1),
		readyCh:      make(chan struct{}),
	}
}

// Start launches the initial scan and periodic rescanning in the background.
// Use WaitReady() to block until the first batch of resolvers is available.
func (as *AutoScanner) Start() {
	slog.Info("Auto-scanner: starting",
		"resolvers", len(as.allResolvers),
		"domain", as.scanDomain,
		"workers", as.workers,
		"top_n", as.topN,
		"max_steps", as.maxSteps,
	)
	go as.run()
}

// WaitReady blocks until the initial scan has found enough resolvers
// (or the initial scan completes with whatever it found).
func (as *AutoScanner) WaitReady() {
	<-as.readyCh
}

// TriggerRescan requests a background rescan to find replacement resolvers.
// Non-blocking: drops the request if a rescan is already pending.
func (as *AutoScanner) TriggerRescan() {
	select {
	case as.rescanCh <- struct{}{}:
		slog.Info("Auto-scanner: rescan triggered by resolver failure")
	default:
		// rescan already pending
	}
}

func (as *AutoScanner) Stop() {
	close(as.stopCh)
}

func (as *AutoScanner) run() {
	as.initialScan()
	as.loop()
}

func (as *AutoScanner) loop() {
	ticker := time.NewTicker(as.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			as.scanAndUpdate()
		case <-as.rescanCh:
			as.scanAndUpdate()
		case <-as.stopCh:
			return
		}
	}
}

// shuffledResolvers returns a shuffled copy of allResolvers, capped at maxSteps.
func (as *AutoScanner) shuffledResolvers() []Resolver {
	shuffled := make([]Resolver, len(as.allResolvers))
	copy(shuffled, as.allResolvers)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	if as.maxSteps > 0 && as.maxSteps < len(shuffled) {
		shuffled = shuffled[:as.maxSteps]
	}
	return shuffled
}

// initialScan runs the first scan with early-ready support.
// It signals readyCh as soon as topN verified resolvers are found.
func (as *AutoScanner) initialScan() {
	shuffled := as.shuffledResolvers()
	start := time.Now()
	slog.Info("Auto-scan: initial verify scan starting", "testing", len(shuffled), "workers", as.workers)

	results := verifyResolversWithEarlyReady(shuffled, as.scanDomain, as.doh, as.workers,
		as.topN, as.pubkey, func(ready []Resolver) {
			as.pool.UpdateResolvers(ready)
			slog.Info("Auto-scan: reached target, services can start", "verified", len(ready))
			as.readyOnce.Do(func() { close(as.readyCh) })
		})

	elapsed := time.Since(start)
	as.processResults(results, elapsed)

	// Ensure ready is signaled even if we didn't reach target
	as.readyOnce.Do(func() {
		slog.Warn("Auto-scan: initial scan complete without reaching target, starting with available resolvers")
		close(as.readyCh)
	})
}

// scanAndUpdate runs a rescan round: shuffle, scan up to maxSteps, update pool.
func (as *AutoScanner) scanAndUpdate() {
	shuffled := as.shuffledResolvers()
	start := time.Now()
	slog.Info("Auto-scan starting", "testing", len(shuffled), "workers", as.workers)

	results := verifyResolversQuiet(shuffled, as.scanDomain, as.doh, as.workers, as.pubkey)
	elapsed := time.Since(start)

	as.processResults(results, elapsed)
}

// processResults sorts results, selects the best verified resolvers, and updates the pool.
func (as *AutoScanner) processResults(results []VerifyResult, elapsed time.Duration) {
	// Sort: verified first, then by latency ascending
	sort.Slice(results, func(i, j int) bool {
		if results[i].Verified != results[j].Verified {
			return results[i].Verified
		}
		return results[i].LatencyMs < results[j].LatencyMs
	})

	// Collect verified resolvers, capped at topN
	var qualified []Resolver
	for _, r := range results {
		if r.Verified {
			qualified = append(qualified, r.Resolver)
			if as.topN > 0 && len(qualified) >= as.topN {
				break
			}
		}
	}

	// Fall back: if no verified resolvers, take the best working ones
	if len(qualified) == 0 {
		for _, r := range results {
			if r.Status == "WORKING" {
				qualified = append(qualified, r.Resolver)
				if as.topN > 0 && len(qualified) >= as.topN {
					break
				}
			}
		}
	}

	if len(qualified) == 0 {
		slog.Warn("Auto-scan: no working resolvers found, keeping current pool")
		return
	}

	as.pool.UpdateResolvers(qualified)

	// Count statuses
	var working, verified, timeouts, errors int
	for _, r := range results {
		switch r.Status {
		case "WORKING":
			working++
			if r.Verified {
				verified++
			}
		case "TIMEOUT":
			timeouts++
		default:
			errors++
		}
	}

	// Log the top resolvers
	limit := len(qualified)
	if limit > 10 {
		limit = 10
	}
	var topList []string
	for i := 0; i < limit && i < len(results); i++ {
		r := results[i]
		if r.Verified {
			topList = append(topList, fmt.Sprintf("%s(%dms)", r.Resolver, r.LatencyMs))
		}
	}

	slog.Info("Auto-scan complete",
		"elapsed", elapsed.Round(time.Second),
		"working", working,
		"verified", verified,
		"timeout", timeouts,
		"error", errors,
		"selected", len(qualified),
	)
	if len(topList) > 0 {
		slog.Info("Top verified resolvers", "list", strings.Join(topList, ", "))
	}
}
