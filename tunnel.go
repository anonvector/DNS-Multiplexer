package main

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// TunnelConfig holds configuration for the managed tunnel client.
type TunnelConfig struct {
	Binary     string // path to slipnet binary (default: "slipnet")
	Profile    string // slipnet:// URI (if provided, Domain/PublicKey/TunnelType are ignored)
	Domain     string // tunnel domain (used when Profile is empty)
	PublicKey  string // server public key hex (used when Profile is empty)
	TunnelType string // "dnstt" or "noizdns" (used when Profile is empty)
	ListenAddr string // SOCKS5 listen address for users (host:port)
	DNSAddr    string // DNS resolver for the client (the multiplexer's listen addr)
}

// TunnelManager manages a slipnet tunnel client subprocess.
type TunnelManager struct {
	config  TunnelConfig
	mu      sync.Mutex
	cmd     *exec.Cmd
	stopped bool
}

func NewTunnelManager(config TunnelConfig) *TunnelManager {
	if config.Binary == "" {
		config.Binary = "slipnet"
	}
	if config.ListenAddr == "" {
		config.ListenAddr = "0.0.0.0:1080"
	}
	return &TunnelManager{
		config: config,
	}
}

func (tm *TunnelManager) Start() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.cmd != nil {
		return fmt.Errorf("tunnel already running")
	}

	// Check binary exists
	if _, err := exec.LookPath(tm.config.Binary); err != nil {
		return fmt.Errorf("tunnel binary %q not found in PATH: %w", tm.config.Binary, err)
	}

	return tm.startLocked()
}

func (tm *TunnelManager) startLocked() error {
	args := tm.buildArgs()

	cmd := exec.Command(tm.config.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting tunnel: %w", err)
	}

	tm.cmd = cmd
	slog.Info("Tunnel client started",
		"binary", tm.config.Binary,
		"pid", cmd.Process.Pid,
		"socks", tm.config.ListenAddr,
		"dns", tm.config.DNSAddr,
	)

	go tm.monitor(cmd)

	return nil
}

func (tm *TunnelManager) monitor(cmd *exec.Cmd) {
	err := cmd.Wait()

	tm.mu.Lock()
	if tm.cmd == cmd {
		tm.cmd = nil
	}
	stopped := tm.stopped
	tm.mu.Unlock()

	if stopped {
		return
	}

	slog.Warn("Tunnel process exited, restarting in 3s", "err", err)
	time.Sleep(3 * time.Second)

	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.stopped {
		return
	}
	if tm.cmd != nil {
		return // already restarted
	}
	if err := tm.startLocked(); err != nil {
		slog.Error("Failed to restart tunnel", "err", err)
	}
}

func (tm *TunnelManager) buildArgs() []string {
	var args []string

	if tm.config.DNSAddr != "" {
		args = append(args, "--dns", tm.config.DNSAddr)
	}

	if tm.config.ListenAddr != "" {
		_, port, err := net.SplitHostPort(tm.config.ListenAddr)
		if err == nil && port != "" {
			args = append(args, "--port", port)
		}
	}

	if tm.config.Profile != "" {
		args = append(args, tm.patchProfileHost(tm.config.Profile))
	} else {
		args = append(args, tm.generateProfileURI())
	}

	return args
}

// patchProfileHost rewrites the host field (index 9) in a slipnet:// profile
// to match the configured ListenAddr. The slipnet CLI reads the host from the
// profile and has no --host flag, so we must patch it here.
func (tm *TunnelManager) patchProfileHost(uri string) string {
	if tm.config.ListenAddr == "" {
		return uri
	}
	host, _, err := net.SplitHostPort(tm.config.ListenAddr)
	if err != nil || host == "" {
		return uri
	}

	const scheme = "slipnet://"
	if !strings.HasPrefix(uri, scheme) {
		return uri
	}

	encoded := strings.TrimPrefix(uri, scheme)
	encoded = strings.Join(strings.Fields(encoded), "")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try with padding
		padded := encoded
		for len(padded)%4 != 0 {
			padded += "="
		}
		decoded, err = base64.StdEncoding.DecodeString(padded)
		if err != nil {
			return uri
		}
	}

	fields := strings.Split(string(decoded), "|")
	if len(fields) < 10 {
		return uri
	}

	fields[9] = host // host field
	patched := strings.Join(fields, "|")
	return scheme + base64.StdEncoding.EncodeToString([]byte(patched))
}

func (tm *TunnelManager) generateProfileURI() string {
	tunnelType := tm.config.TunnelType
	switch tunnelType {
	case "noizdns":
		tunnelType = "sayedns"
	case "":
		tunnelType = "dnstt"
	}

	// v16 pipe-delimited format: indices 0-22
	// Parser requires at least 12 fields (indices 0-11)
	fields := make([]string, 23)
	fields[0] = "16"                 // version
	fields[1] = tunnelType           // tunnelType
	fields[2] = "auto"               // name
	fields[3] = tm.config.Domain     // domain
	fields[4] = "127.0.0.1:53:0"    // resolvers (overridden by --dns)
	fields[5] = "0"                  // authMode
	fields[6] = "5000"               // keepAlive
	fields[7] = "bbr"               // cc
	fields[8] = "1080"               // port (overridden by --port)
	fields[9] = "0.0.0.0"           // host
	fields[10] = "0"                 // gso
	fields[11] = tm.config.PublicKey // publicKey
	fields[22] = "udp"              // dnsTransport

	profile := strings.Join(fields, "|")
	encoded := base64.StdEncoding.EncodeToString([]byte(profile))
	return "slipnet://" + encoded
}

func (tm *TunnelManager) Stop() {
	tm.mu.Lock()
	tm.stopped = true
	cmd := tm.cmd
	tm.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return
	}

	slog.Info("Stopping tunnel client", "pid", cmd.Process.Pid)
	_ = cmd.Process.Signal(syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("Tunnel client stopped")
	case <-time.After(5 * time.Second):
		slog.Warn("Tunnel shutdown timeout, killing")
		_ = cmd.Process.Kill()
	}
}

func (tm *TunnelManager) IsRunning() bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.cmd != nil
}
