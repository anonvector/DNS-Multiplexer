# DNS Multiplexer

DNS proxy + tunnel manager for dnstt/noizdns. Scans resolvers for tunnel compatibility, picks the best ones, and keeps your tunnel running through them.

## Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main/deploy.sh)
```

Interactive menu lets you pick:

```
  1) Proxy only    — DNS proxy for your own dnstt/slipnet client
  2) Tunnel mode   — Full tunnel: users connect via SOCKS5 proxy
```

### Non-interactive

Tunnel mode:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main/deploy.sh) \
  --auto --tunnel --profile "slipnet://BASE64..."
```

Proxy only:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main/deploy.sh) --auto
```

### Manual deploy (when GitHub is blocked)

```bash
scp -r dns-multiplexer/ root@SERVER:/opt/dns-multiplexer/
ssh root@SERVER
cd /opt/dns-multiplexer
bash deploy.sh
```

## How it works

### Tunnel mode

```
[Users] --> SOCKS5 :1080 --> [slipnet] --> DNS --> [multiplexer 127.0.0.1:53] --> [best resolver] --> [dnstt-server]
```

1. Scans all resolvers for tunnel compatibility (score 0-6)
2. Picks the top 20 and routes tunnel DNS through them
3. Runs `slipnet` client as SOCKS5 proxy for users
4. Re-scans periodically and swaps in better resolvers — no restart needed

### Proxy mode

```
[dnstt-client] --> DNS --> [multiplexer :53] --> [resolvers] --> [dnstt-server]
```

Load-balances DNS queries across upstream resolvers with health tracking.

## Management

```bash
dns-mux --status      # Show status and logs
dns-mux --restart     # Restart
dns-mux --stop        # Stop
dns-mux --logs        # Live logs
dns-mux --uninstall   # Remove everything
```

## Run without installing

```bash
# Tunnel mode (auto-loads resolvers.txt from same directory)
./dns-multiplexer -tunnel -tunnel-profile "slipnet://..."

# Proxy mode
./dns-multiplexer -f resolvers.txt

# One-shot scan
./dns-multiplexer -scan -scan-domain t.example.com -f resolvers.txt
```

## Resolver scanning

Each resolver is tested for tunnel compatibility and scored 0-6:

| Test | What it checks |
|------|----------------|
| NS   | NS delegation + glue records |
| TXT  | TXT record support |
| RND  | Random subdomain resolution |
| DPI  | Encoded payload queries (tunnel realism) |
| EDNS | EDNS0 buffer size (512/900/1232) |
| NXD  | NXDOMAIN correctness |

## Flags

### Tunnel mode

| Flag | Default | Description |
|------|---------|-------------|
| `-tunnel` | | Enable tunnel mode |
| `-tunnel-profile` | | `slipnet://` URI or file path |
| `-tunnel-listen` | `0.0.0.0:1080` | SOCKS5 address for users |
| `-tunnel-type` | `dnstt` | `dnstt` or `noizdns` (auto-detected from profile) |
| `-tunnel-domain` | | Tunnel domain (auto-detected from profile) |
| `-tunnel-pubkey` | | Server public key (auto-detected from profile) |
| `-tunnel-binary` | `slipnet` | Path to slipnet binary |
| `-scan-interval` | `5m` | Re-scan interval |
| `-scan-min-score` | `3` | Min score (0-6) to use a resolver |
| `-scan-top` | `20` | Keep top N resolvers |
| `-scan-workers` | `200` | Concurrent scan workers |

### General

| Flag | Default | Description |
|------|---------|-------------|
| `-listen`, `-l` | `0.0.0.0:53` | DNS proxy listen address (auto `127.0.0.1` in tunnel mode) |
| `-resolver`, `-r` | | Upstream resolver (repeatable) |
| `-resolvers-file`, `-f` | | Resolver list file |
| `-doh` | | Use DoH upstream |
| `-mode`, `-m` | `round-robin` | `round-robin` or `random` |
| `-tcp` | | Also listen TCP |
| `-cache` | | Enable DNS cache |
| `-health-check` | | Periodic health checks |
| `-stats` | | Log statistics |
| `-cover` | | Cover traffic |
| `-scan` | | One-shot scan mode |
| `-scan-domain` | | Domain for scanning |

## Build

```bash
go build -o dns-multiplexer .

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o bin/dns-multiplexer-linux-amd64 .
```
