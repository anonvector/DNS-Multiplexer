package main

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// AutoScanner periodically tests all resolvers for tunnel compatibility
// and selects the top N resolvers for the active pool.
type AutoScanner struct {
	pool         *ResolverPool
	allResolvers []Resolver // full list for re-scanning (never filtered)
	scanDomain   string
	doh          bool
	interval     time.Duration
	minScore     int
	topN         int // max resolvers to keep in active pool
	workers      int // scan concurrency
	stopCh       chan struct{}
}

func NewAutoScanner(pool *ResolverPool, allResolvers []Resolver, scanDomain string, doh bool, interval time.Duration, minScore, topN, workers int) *AutoScanner {
	return &AutoScanner{
		pool:         pool,
		allResolvers: allResolvers,
		scanDomain:   scanDomain,
		doh:          doh,
		interval:     interval,
		minScore:     minScore,
		topN:         topN,
		workers:      workers,
		stopCh:       make(chan struct{}),
	}
}

// Start runs the initial scan synchronously, then launches periodic scanning.
func (as *AutoScanner) Start() {
	slog.Info("Auto-scanner: running initial scan",
		"resolvers", len(as.allResolvers),
		"domain", as.scanDomain,
		"workers", as.workers,
		"top_n", as.topN,
	)
	as.scanAndUpdate()
	go as.loop()
}

func (as *AutoScanner) Stop() {
	close(as.stopCh)
}

func (as *AutoScanner) loop() {
	ticker := time.NewTicker(as.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			as.scanAndUpdate()
		case <-as.stopCh:
			return
		}
	}
}

func (as *AutoScanner) scanAndUpdate() {
	start := time.Now()
	slog.Info("Auto-scan starting", "resolvers", len(as.allResolvers), "workers", as.workers)

	results := scanResolversQuiet(as.allResolvers, as.scanDomain, as.doh, as.workers)
	elapsed := time.Since(start)

	// Sort by score desc, latency asc
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].LatencyMs < results[j].LatencyMs
	})

	// Collect resolvers that meet the minimum score, capped at topN
	var qualified []Resolver
	for _, r := range results {
		if r.Status == "WORKING" && r.Score >= as.minScore {
			qualified = append(qualified, r.Resolver)
			if as.topN > 0 && len(qualified) >= as.topN {
				break
			}
		}
	}

	// Fall back: if none met the score threshold, take the best working ones
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
	var working, timeouts, errors int
	for _, r := range results {
		switch r.Status {
		case "WORKING":
			working++
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
	for _, r := range results[:limit] {
		topList = append(topList, fmt.Sprintf("%s(%d/6 %dms)", r.Resolver, r.Score, r.LatencyMs))
	}

	slog.Info("Auto-scan complete",
		"elapsed", elapsed.Round(time.Second),
		"working", working,
		"timeout", timeouts,
		"error", errors,
		"selected", len(qualified),
	)
	slog.Info("Top resolvers", "list", strings.Join(topList, ", "))
}
