# minitunnel

A single binary that combines a **WebSocket proxy** (VLESS / Trojan /
Shadowsocks, from [websgo](https://github.com/bramstera/websgo)) with a
**stripped-down Cloudflare tunnel client** (built from `cloudflared`
v2024.10.0).

It runs a local WS proxy server. If `TUNNEL_TOKEN` is set, it also exposes
that server through a Cloudflare tunnel so the proxy is reachable over HTTPS
via the edge. If `TUNNEL_TOKEN` is **empty**, the tunnel is not started and
the WS proxy listens directly (e.g. behind your own reverse proxy).

In tunnel mode it is the equivalent of:

```
cloudflared tunnel --edge-ip-version auto --protocol http2 run --token <TOKEN>
```

with `--edge-ip-version=auto` and `--protocol=http2` hard-coded. The tunnel
proxies edge traffic to the local WS proxy server.

## Configuration

Three values live at the top of `main.go` and can be overridden by environment
variables:

```go
var (
    TunnelToken = os.Getenv("TUNNEL_TOKEN")                           // ""  = direct mode
    Port        = getenvInt("PORT", 8080)                             // 8080
    UUID        = getenvDefault("UUID", "b64c9a01-3f09-4dea-a0f1-dc85e5a3ac19")
)
```

| Variable        | Default                                | Meaning                                                              |
|-----------------|----------------------------------------|----------------------------------------------------------------------|
| `TUNNEL_TOKEN`  | _(empty)_                              | Cloudflare tunnel token, base64 JSON. Empty = direct mode.           |
| `PORT`          | `8080`                                 | Local WS server port.                                                |
| `UUID`          | `b64c9a01-3f09-4dea-a0f1-dc85e5a3ac19` | Proxy UUID (VLESS/Trojan credential).                               |
| `WSPATH`        | `api/v1/user?token=<UUID[:8]>&lang=en` | WebSocket path clients connect to.                                   |
| `TUNNEL_URL`    | `http://localhost:<PORT>`              | (tunnel mode) Origin URL the tunnel proxies to.                      |
| `TUNNEL_ORIGIN` | —                                      | Alias for `TUNNEL_URL` (takes precedence).                           |

### Behaviour

- `GET /` → `Bot is running.` (plain text)
- `GET <WSPATH>` → WebSocket upgrade → protocol auto-detect
  (VLESS version byte `0` + UUID, or Trojan SHA224 hash, or Shadowsocks ATYP)
- any other path → `404`
- WS query string (if `WSPATH` contains `?`) is validated exactly

## Build

The binary is part of the `github.com/cloudflare/cloudflared` module, so it is
built from the module root:

```
cd cloudflared-2024.10.0
go build -o minitunnel ./cmd/minitunnel
```

Stripped:

```
go build -trimpath -ldflags="-s -w" -o minitunnel ./cmd/minitunnel
```

## Run

### Tunnel mode (set `TUNNEL_TOKEN`)

```
export TUNNEL_TOKEN='eyJhIjoi...base64...'
./minitunnel
```
The WS proxy listens on `:8080` (localhost) and the tunnel exposes it at your
tunnel hostname over HTTPS.

> Note: the Cloudflare dashboard's remote ingress (Public Hostname) must point
> at the origin this binary serves on, e.g. `http://localhost:8080`. If your
dashboard is configured for a different port, either change `PORT` or update
the dashboard service URL.

### Direct mode (leave `TUNNEL_TOKEN` empty)

```
PORT=8443 ./minitunnel
```
The WS proxy listens on `:8443` on all interfaces; put your own TLS reverse
proxy in front.

Ctrl-C (SIGINT/SIGTERM) triggers a graceful shutdown.

## Client config (tunnel mode)

```
vless://<UUID>@<any-sni>:443?encryption=none&security=tls&sni=<tunnel-host>
  &type=ws&host=<tunnel-host>&path=<WSPATH-urlencoded>#<name>
```

## Layout

```
cmd/minitunnel/
  main.go          # entry point: WS proxy server + tunnel client
  README.md
  ws/
    ws.go          # WebSocket upgrade + protocol auto-detect
    vl.go          # VLESS handler
    tr.go          # Trojan handler
    ss.go          # Shadowsocks handler
    dns/
      dns.go       # DoH hostname resolver (dns.google + system fallback)
```

## How it differs from stock `cloudflared`

The tunnel client in `main.go` calls the existing cloudflared library packages
(`supervisor`, `connection`, `orchestration`, `ingress`, `tlsconfig`,
`features`, `edgediscovery`) directly. It drops, from the code path of this
binary:

- the `urfave/cli` command tree and all subcommands
- Sentry error reporting
- Prometheus metrics server
- auto-updater
- systemd / launchd / Windows service management
- quick tunnels
- QUIC transport (only HTTP/2 is wired up)
- ICMP / packet routing
- remote management logging rules
- DNS-over-HTTPS proxy

The connection logic itself (edge discovery, HTTP/2 registration, control
stream, reconnect/backoff, ingress proxy, WebSocket streaming) is **unchanged**
— it is the exact same code the full `cloudflared` runs.

The WS proxy (`ws/`) is adapted from websgo, with the Status Page / system
stats / embedded HTML removed; the root path returns a plain `Bot is running.`
string.
