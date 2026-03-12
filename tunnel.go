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

	// SSH chaining (parsed from _ssh profiles)
	SSHEnabled  bool
	SSHUsername string
	SSHPassword string
	SSHPort     int
}

// TunnelManager manages slipnet + optional SSH subprocess.
type TunnelManager struct {
	config     TunnelConfig
	mu         sync.Mutex
	tunnelCmd  *exec.Cmd // slipnet process
	sshCmd     *exec.Cmd // ssh -D process (only for _ssh profiles)
	stopped    bool
	tunnelPort string // internal port slipnet listens on (SSH mode only)
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

	if tm.tunnelCmd != nil {
		return fmt.Errorf("tunnel already running")
	}

	if _, err := exec.LookPath(tm.config.Binary); err != nil {
		return fmt.Errorf("tunnel binary %q not found in PATH: %w", tm.config.Binary, err)
	}

	return tm.startLocked()
}

func (tm *TunnelManager) startLocked() error {
	if tm.config.SSHEnabled {
		return tm.startWithSSH()
	}
	return tm.startDirect()
}

// startDirect starts slipnet binding directly to the user-facing SOCKS5 port.
func (tm *TunnelManager) startDirect() error {
	args := tm.buildSlipnetArgs(tm.config.ListenAddr)

	cmd := exec.Command(tm.config.Binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting tunnel: %w", err)
	}

	tm.tunnelCmd = cmd
	slog.Info("Tunnel started (direct SOCKS5)",
		"pid", cmd.Process.Pid,
		"socks", tm.config.ListenAddr,
	)

	go tm.monitorTunnel(cmd)
	return nil
}

// startWithSSH starts slipnet on an internal port, then chains SSH -D for SOCKS5.
func (tm *TunnelManager) startWithSSH() error {
	// Find a free port for the internal tunnel
	internalPort, err := freePort()
	if err != nil {
		return fmt.Errorf("finding free port: %w", err)
	}
	tm.tunnelPort = fmt.Sprintf("%d", internalPort)
	internalAddr := fmt.Sprintf("127.0.0.1:%d", internalPort)

	// Start slipnet on internal port
	args := tm.buildSlipnetArgs(internalAddr)
	tunnelCmd := exec.Command(tm.config.Binary, args...)
	tunnelCmd.Stdout = os.Stdout
	tunnelCmd.Stderr = os.Stderr

	if err := tunnelCmd.Start(); err != nil {
		return fmt.Errorf("starting tunnel: %w", err)
	}
	tm.tunnelCmd = tunnelCmd
	slog.Info("Tunnel started (internal)",
		"pid", tunnelCmd.Process.Pid,
		"internal", internalAddr,
	)

	go tm.monitorTunnel(tunnelCmd)

	// Wait for slipnet to be ready
	if !waitForPort(internalAddr, 30*time.Second) {
		return fmt.Errorf("tunnel did not start listening on %s", internalAddr)
	}

	// Start SSH dynamic forwarding through the tunnel
	if err := tm.startSSH(internalAddr); err != nil {
		return fmt.Errorf("starting SSH: %w", err)
	}

	return nil
}

func (tm *TunnelManager) startSSH(tunnelAddr string) error {
	_, tunnelPort, _ := net.SplitHostPort(tunnelAddr)

	sshArgs := []string{
		"-N",                              // no remote command
		"-D", tm.config.ListenAddr,        // SOCKS5 dynamic forwarding
		"-p", tunnelPort,                  // connect through tunnel port
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ConnectTimeout=30",
		fmt.Sprintf("%s@127.0.0.1", tm.config.SSHUsername),
	}

	sshCmd := exec.Command("sshpass", append([]string{"-p", tm.config.SSHPassword}, append([]string{"ssh"}, sshArgs...)...)...)
	sshCmd.Stdout = os.Stdout
	sshCmd.Stderr = os.Stderr

	// Fall back to ssh with SSH_ASKPASS if sshpass not available
	if _, err := exec.LookPath("sshpass"); err != nil {
		slog.Warn("sshpass not found, trying SSH_ASKPASS")
		sshCmd = exec.Command("ssh", sshArgs...)
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr
		sshCmd.Env = append(os.Environ(),
			fmt.Sprintf("SSH_ASKPASS_REQUIRE=force"),
			fmt.Sprintf("DISPLAY=:0"),
		)
	}

	if err := sshCmd.Start(); err != nil {
		return fmt.Errorf("starting ssh: %w", err)
	}

	tm.sshCmd = sshCmd
	slog.Info("SSH SOCKS5 started",
		"pid", sshCmd.Process.Pid,
		"socks", tm.config.ListenAddr,
		"via_tunnel", tunnelAddr,
		"user", tm.config.SSHUsername,
	)

	go tm.monitorSSH(sshCmd)
	return nil
}

func (tm *TunnelManager) monitorTunnel(cmd *exec.Cmd) {
	err := cmd.Wait()

	tm.mu.Lock()
	if tm.tunnelCmd == cmd {
		tm.tunnelCmd = nil
	}
	stopped := tm.stopped
	tm.mu.Unlock()

	if stopped {
		return
	}

	// If tunnel dies, kill SSH too
	tm.stopSSH()

	slog.Warn("Tunnel process exited, restarting in 3s", "err", err)
	time.Sleep(3 * time.Second)

	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.stopped || tm.tunnelCmd != nil {
		return
	}
	if err := tm.startLocked(); err != nil {
		slog.Error("Failed to restart tunnel", "err", err)
	}
}

func (tm *TunnelManager) monitorSSH(cmd *exec.Cmd) {
	err := cmd.Wait()

	tm.mu.Lock()
	if tm.sshCmd == cmd {
		tm.sshCmd = nil
	}
	stopped := tm.stopped
	tunnelRunning := tm.tunnelCmd != nil
	tm.mu.Unlock()

	if stopped {
		return
	}

	slog.Warn("SSH process exited, restarting in 2s", "err", err)
	time.Sleep(2 * time.Second)

	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.stopped || tm.sshCmd != nil || !tunnelRunning {
		return
	}

	internalAddr := fmt.Sprintf("127.0.0.1:%s", tm.tunnelPort)
	if err := tm.startSSH(internalAddr); err != nil {
		slog.Error("Failed to restart SSH", "err", err)
	}
}

func (tm *TunnelManager) buildSlipnetArgs(listenAddr string) []string {
	var args []string

	if tm.config.DNSAddr != "" {
		args = append(args, "--dns", tm.config.DNSAddr)
	}

	if listenAddr != "" {
		_, port, err := net.SplitHostPort(listenAddr)
		if err == nil && port != "" {
			args = append(args, "--port", port)
		}
	}

	if tm.config.Profile != "" {
		args = append(args, tm.patchProfile(tm.config.Profile, listenAddr))
	} else {
		args = append(args, tm.generateProfileURI(listenAddr))
	}

	return args
}

// patchProfile rewrites the slipnet:// profile to:
// - Strip _ssh suffix from tunnel type — SSH is handled separately
// - Set host field to match the given listen address
func (tm *TunnelManager) patchProfile(uri string, listenAddr string) string {
	const scheme = "slipnet://"
	if !strings.HasPrefix(uri, scheme) {
		return uri
	}

	encoded := strings.TrimPrefix(uri, scheme)
	encoded = strings.Join(strings.Fields(encoded), "")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
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

	// Strip _ssh — we handle SSH chaining separately
	fields[1] = strings.TrimSuffix(fields[1], "_ssh")

	// Set host for SOCKS5 binding
	if listenAddr != "" {
		if host, _, err := net.SplitHostPort(listenAddr); err == nil && host != "" {
			fields[9] = host
		}
	}

	patched := strings.Join(fields, "|")
	return scheme + base64.StdEncoding.EncodeToString([]byte(patched))
}

func (tm *TunnelManager) generateProfileURI(listenAddr string) string {
	tunnelType := tm.config.TunnelType
	switch tunnelType {
	case "noizdns":
		tunnelType = "sayedns"
	case "":
		tunnelType = "dnstt"
	}

	listenHost := "0.0.0.0"
	if listenAddr != "" {
		if h, _, err := net.SplitHostPort(listenAddr); err == nil && h != "" {
			listenHost = h
		}
	}

	fields := make([]string, 23)
	fields[0] = "16"
	fields[1] = tunnelType
	fields[2] = "auto"
	fields[3] = tm.config.Domain
	fields[4] = "127.0.0.1:53:0"
	fields[5] = "0"
	fields[6] = "5000"
	fields[7] = "bbr"
	fields[8] = "1080"
	fields[9] = listenHost
	fields[10] = "0"
	fields[11] = tm.config.PublicKey
	fields[22] = "udp"

	profile := strings.Join(fields, "|")
	encoded := base64.StdEncoding.EncodeToString([]byte(profile))
	return "slipnet://" + encoded
}

func (tm *TunnelManager) stopSSH() {
	tm.mu.Lock()
	cmd := tm.sshCmd
	tm.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
}

func (tm *TunnelManager) Stop() {
	tm.mu.Lock()
	tm.stopped = true
	tunnelCmd := tm.tunnelCmd
	sshCmd := tm.sshCmd
	tm.mu.Unlock()

	// Stop SSH first, then tunnel
	if sshCmd != nil && sshCmd.Process != nil {
		slog.Info("Stopping SSH", "pid", sshCmd.Process.Pid)
		_ = sshCmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { sshCmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = sshCmd.Process.Kill()
		}
	}

	if tunnelCmd != nil && tunnelCmd.Process != nil {
		slog.Info("Stopping tunnel", "pid", tunnelCmd.Process.Pid)
		_ = tunnelCmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { tunnelCmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = tunnelCmd.Process.Kill()
		}
	}

	slog.Info("Tunnel stopped")
}

func (tm *TunnelManager) IsRunning() bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.tunnelCmd != nil
}

// freePort finds an available TCP port.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}

// waitForPort waits until something is listening on addr.
func waitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
