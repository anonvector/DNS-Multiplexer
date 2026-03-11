# DNS Multiplexer for DNSTT/NoizDNS

A middle proxy that distributes DNS tunnel queries across multiple upstream resolvers, bypassing DPI restrictions on mobile ISP networks.

## Architecture

```
                              ┌─────────────────────────┐
                              │   Middle Proxy VPS       │
                              │   (Iran or datacenter)   │
                              │                          │
┌──────────┐    DNS query     │  ┌────────────────────┐  │    ┌──────────────┐
│  Client   │ ───────────────>│  │  DNS Multiplexer   │──│──> │  8.8.8.8     │──┐
│ (Mobile   │                 │  │  (dns-mux.py)      │  │    └──────────────┘  │
│  ISP)     │ <───────────────│  │                    │──│──> │  1.1.1.1     │──│──> ┌────────────┐
│           │    DNS response  │  │  Round-robin /     │  │    └──────────────┘  │    │ dnstt-     │
│  dnstt-   │                 │  │  random across     │──│──> │  9.9.9.9     │──│──> │ server     │
│  client   │                 │  │  resolvers         │  │    └──────────────┘  │    │ (tunnel    │
│           │                 │  └────────────────────┘  │    │  ...         │──┘    │  endpoint) │
└──────────┘                  │                          │    └──────────────┘       └────────────┘
                              └─────────────────────────┘
```

## Why?

- **Multiplexing across resolvers** makes DPI detection much harder — traffic takes different paths
- **Auto-select** probes all resolvers at startup and only uses working ones
- **Cover traffic** blends tunnel queries with legitimate DNS lookups
- **Health monitoring** automatically routes around failed resolvers
- **96 built-in resolvers** including Iranian DNS servers (Shecan, Electro, Begzar, etc.)

## One-Line Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main/deploy.sh)
```

Or non-interactive with defaults:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main/deploy.sh) --auto
```

## Setup Guide: UDP DNS on Port 443 (Recommended for Iran)

This is the recommended setup for Iran. The multiplexer runs on a VPS **inside Iran**, listens on port 443, and distributes tunnel queries across many DNS resolvers.

### Step 1: Install on your Iranian VPS

```bash
# SSH into your Iranian VPS
ssh root@YOUR_IRAN_VPS_IP

# Install with one command (UDP mode, port 443)
bash <(curl -Ls https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main/deploy.sh) --auto --port 443
```

This will:
- Install `dns-mux.py` and the `dns-mux` management command
- Probe all 96 resolvers and keep only working ones
- Start listening on UDP/TCP port 443
- Enable cover traffic and health monitoring

### Step 2: Verify it's working

```bash
# Check status
dns-mux --status

# Test locally
dig @127.0.0.1 -p 443 google.com +short +timeout=5

# Watch live logs
dns-mux --logs
```

You should see `Using X/96 working resolvers` and health checks showing resolvers UP.

### Step 3: Configure your client

**SlipNet Android app:**
Set the DNS resolver in your profile to:
```
YOUR_IRAN_VPS_IP:443
```

**SlipNet CLI:**
```bash
slipnet --dns YOUR_IRAN_VPS_IP:443 slipnet://YOUR_PROFILE
```

**dnstt-client directly:**
```bash
dnstt-client -udp YOUR_IRAN_VPS_IP:443 -pubkey-file server.pub t.example.com 127.0.0.1:1080
```

### Step 4: Management

```bash
dns-mux --status      # Show status and recent logs
dns-mux --restart     # Restart the service
dns-mux --stop        # Stop the service
dns-mux --start       # Start the service
dns-mux --logs        # Follow live logs
dns-mux --uninstall   # Remove everything
```

## Setup Guide: DoH Mode (When Outbound Port 53 is Blocked)

If your VPS blocks outbound DNS (port 53), use DoH mode. The proxy forwards queries via HTTPS to DoH providers like `dns.google` and `cloudflare-dns.com`.

```bash
bash <(curl -Ls https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main/deploy.sh) --auto --doh --port 443
```

## Manual Deployment (SCP)

If your server can't reach GitHub (e.g., during an internet shutdown), you can copy the files manually.

### From your local machine to the server:

```bash
# Copy the entire dns-multiplexer folder
scp -r dns-multiplexer/ root@YOUR_VPS_IP:/opt/dns-multiplexer/

# Or copy individual files
scp dns-mux.py deploy.sh resolvers.txt root@YOUR_VPS_IP:/opt/dns-multiplexer/
```

### With a custom SSH port:

```bash
scp -P 2222 -r dns-multiplexer/ root@YOUR_VPS_IP:/opt/dns-multiplexer/
```

### Then install on the server:

```bash
ssh root@YOUR_VPS_IP
cd /opt/dns-multiplexer
bash deploy.sh --auto --port 443
```

### Copy from server to local (backup):

```bash
# Backup the config
scp root@YOUR_VPS_IP:/etc/dns-multiplexer/resolvers.txt ./resolvers-backup.txt

# Backup logs
scp root@YOUR_VPS_IP:/var/log/dns-multiplexer/dns-mux.log ./dns-mux.log
```

## DNS Tunnel Scanner

Scan resolvers for tunnel compatibility (same tests as SlipNet app):

```bash
# Scan default UDP resolvers
dns-mux --scan --scan-domain t.example.com -f /etc/dns-multiplexer/resolvers.txt

# Scan DoH resolvers
dns-mux --scan --doh --scan-domain t.example.com

# Scan specific resolvers
dns-mux --scan --scan-domain t.example.com -r 8.8.8.8 -r 1.1.1.1 -r 178.22.122.100
```

Each resolver gets a score out of 6:

| Test | What it checks |
|------|---------------|
| NS | NS delegation + glue record resolution |
| TXT | TXT record query support |
| RND | Random nested subdomain resolution |
| DPI | Tunnel realism — base32 payload like real dnstt |
| EDNS | EDNS0 payload size (512/900/1232) |
| NXD | NXDOMAIN correctness (DNS hijacking detection) |

## Tunnel Mode (Integrated dnstt/noizdns Client)

Tunnel mode manages the complete stack: DNS proxy + periodic resolver scanning + slipnet tunnel client. Users connect via SOCKS5 or SSH.

```
[Users] --> SOCKS5 :1080 --> [slipnet client] --> DNS --> [multiplexer :53] --> [best resolver] --> [dnstt-server]
```

The tunnel client uses the multiplexer as its DNS resolver. When the auto-scanner finds better resolvers, the pool is updated seamlessly -- no tunnel restart needed.

### With a slipnet:// config

```bash
dns-multiplexer -tunnel \
  -tunnel-profile "slipnet://BASE64..." \
  -f resolvers-30k.txt
```

The profile is parsed automatically to extract domain, public key, and tunnel type.

### With a config file

```bash
dns-multiplexer -tunnel \
  -tunnel-profile ./my-server.conf \
  -f resolvers-30k.txt
```

### With individual flags

```bash
dns-multiplexer -tunnel \
  -tunnel-type noizdns \
  -tunnel-domain t.example.com \
  -tunnel-pubkey 0123456789abcdef... \
  -f resolvers.txt
```

### Large resolver lists (30K+)

```bash
dns-multiplexer -tunnel \
  -tunnel-profile "slipnet://..." \
  -f resolvers-30k.txt \
  -scan-workers 200 \
  -scan-top 20 \
  -scan-min-score 4 \
  -scan-interval 10m \
  -health-check -stats -cache
```

- 200 concurrent workers scan all 30K resolvers in ~5-8 minutes
- Only the top 20 (by score + latency) go into the active pool
- Re-scans every 10 minutes to adapt to resolver changes
- Resolvers scoring below 4/6 are excluded

### User access

SOCKS5 proxy:

```bash
curl --socks5-hostname SERVER:1080 https://ifconfig.me
```

SSH through the tunnel:

```bash
ssh -o ProxyCommand="nc -x SERVER:1080 %h %p" user@remote
```

## Files

| File | Description |
|------|-------------|
| `main.go` | CLI entry point, flag parsing, mode routing |
| `proxy.go` | UDP and TCP DNS proxy implementations |
| `pool.go` | Resolver pool with health tracking and round-robin/random selection |
| `transport.go` | UDP and DoH DNS transport |
| `scanner.go` | 6-point tunnel compatibility scanner |
| `cache.go` | LRU DNS response cache with TTL expiry |
| `cover.go` | Cover traffic generator |
| `config.go` | slipnet:// profile URI parser |
| `autoscan.go` | Periodic scanning and top-N resolver selection |
| `tunnel.go` | slipnet subprocess management with auto-restart |
| `deploy.sh` | Deployment script + `dns-mux` management command |
| `resolvers.txt` | DNS resolvers (public + Iranian) |

## All Flags

### General

| Flag | Default | Description |
|------|---------|-------------|
| `-listen`, `-l` | `0.0.0.0:53` | DNS proxy listen address |
| `-resolver`, `-r` | | Upstream resolver (repeatable) |
| `-resolvers-file`, `-f` | | File with resolver list (one per line, `#` comments) |
| `-doh` | `false` | Use DoH for upstream resolvers |
| `-mode`, `-m` | `round-robin` | Distribution: `round-robin` or `random` |
| `-no-auto-select` | `false` | Skip startup probe |
| `-tcp` | `false` | Also listen for TCP DNS queries |
| `-cache` | `false` | Enable DNS response cache |
| `-cache-size` | `10000` | Max cache entries |
| `-health-check` | `false` | Periodic health checks (every 30s) |
| `-stats` | `false` | Log query statistics (every 60s) |
| `-cover` | `false` | Generate cover traffic |
| `-cover-min` | `5.0` | Min cover traffic interval (seconds) |
| `-cover-max` | `15.0` | Max cover traffic interval (seconds) |
| `-log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Scan Mode

| Flag | Default | Description |
|------|---------|-------------|
| `-scan` | `false` | Run one-shot tunnel compatibility scan |
| `-scan-domain` | | Tunnel domain for testing |

### Tunnel Mode

| Flag | Default | Description |
|------|---------|-------------|
| `-tunnel` | `false` | Enable tunnel mode |
| `-tunnel-profile` | | `slipnet://` URI or path to file containing one |
| `-tunnel-type` | `dnstt` | Tunnel type: `dnstt` or `noizdns` |
| `-tunnel-domain` | | Tunnel domain (auto-filled from profile) |
| `-tunnel-pubkey` | | Server public key hex (auto-filled from profile) |
| `-tunnel-listen` | `0.0.0.0:1080` | SOCKS5 listen address for users |
| `-tunnel-binary` | `slipnet` | Path to slipnet CLI binary |
| `-scan-interval` | `5m` | Auto-scan interval (e.g. `5m`, `10m`, `1h`) |
| `-scan-min-score` | `3` | Minimum score (0-6) for a resolver to be used |
| `-scan-top` | `20` | Keep only top N resolvers in active pool |
| `-scan-workers` | `200` | Concurrent workers for scanning |

## Build

```bash
cd dns-multiplexer
go build -o bin/dns-multiplexer .
```

## deploy.sh Options

```
--auto, -a           Non-interactive install
--doh                Use DoH upstream (when port 53 is blocked)
--port, -p PORT      Custom listen port (default: 53)
--mode, -m MODE      Distribution mode
--no-tcp             Disable TCP proxy
--no-cover           Disable cover traffic
--with-dnstt         Also deploy dnstt-server (uses bundled binaries)
--uninstall, -u      Remove everything
```
