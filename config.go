package main

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// SlipNetProfile holds parsed fields from a slipnet:// URI.
type SlipNetProfile struct {
	Version      string
	TunnelType   string // "dnstt", "dnstt_ssh", "sayedns", "sayedns_ssh"
	Name         string
	Domain       string
	Resolvers    string // e.g. "8.8.8.8:53:0"
	AuthMode     bool
	KeepAlive    int
	CC           string
	Port         int
	Host         string
	GSO          bool
	PublicKey    string
	DNSTransport string // udp, tcp, tls, https
	DoHURL       string
}

// DisplayTunnelType returns a human-friendly tunnel type name.
func (p *SlipNetProfile) DisplayTunnelType() string {
	switch p.TunnelType {
	case "sayedns", "sayedns_ssh":
		return "noizdns"
	case "dnstt", "dnstt_ssh":
		return "dnstt"
	default:
		return p.TunnelType
	}
}

// IsSSH returns true if the profile chains SSH through the tunnel.
func (p *SlipNetProfile) IsSSH() bool {
	return strings.HasSuffix(p.TunnelType, "_ssh")
}

// ParseSlipNetURI parses a slipnet://BASE64... URI into a SlipNetProfile.
func ParseSlipNetURI(uri string) (*SlipNetProfile, error) {
	const scheme = "slipnet://"
	if !strings.HasPrefix(uri, scheme) {
		return nil, fmt.Errorf("invalid URI scheme, expected slipnet://")
	}

	encoded := strings.TrimPrefix(uri, scheme)
	encoded = strings.Join(strings.Fields(encoded), "")

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try with padding
		for len(encoded)%4 != 0 {
			encoded += "="
		}
		decoded, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %v", err)
		}
	}

	fields := strings.Split(string(decoded), "|")
	if len(fields) < 12 {
		return nil, fmt.Errorf("not enough fields in profile (got %d, need at least 12)", len(fields))
	}

	p := &SlipNetProfile{
		Version:    fields[0],
		TunnelType: fields[1],
		Name:       fields[2],
		Domain:     fields[3],
		Resolvers:  fields[4],
		Host:       "127.0.0.1",
		Port:       1080,
	}

	if fields[5] == "1" {
		p.AuthMode = true
	}
	if v, err := strconv.Atoi(fields[6]); err == nil {
		p.KeepAlive = v
	}
	p.CC = fields[7]
	if v, err := strconv.Atoi(fields[8]); err == nil && v > 0 {
		p.Port = v
	}
	if fields[9] != "" {
		p.Host = fields[9]
	}
	if fields[10] == "1" {
		p.GSO = true
	}
	p.PublicKey = fields[11]

	if len(fields) > 22 && fields[22] != "" {
		p.DNSTransport = fields[22]
	}
	if len(fields) > 21 && fields[21] != "" {
		p.DoHURL = fields[21]
	}

	return p, nil
}
