# proxyjoss

Rotating HTTP and SOCKS5 proxy that keeps its upstream list fresh, proves which
entries actually work, and hands each client a selector to choose its egress.

Two halves:

- **`proxyjoss` (Go)** is the control plane *and* the client-facing listener. It
  parses and de-duplicates the feed, tracks health and cooldown, ranks and
  round-robins entries, authenticates clients by selector, and serves a status
  API.
- **[`worker/`](worker/)** is an optional [Cloudflare Worker](https://developers.cloudflare.com/workers/)
  that acts as the data plane. It asks proxyjoss for a ranked egress list and
  dials it with `cloudflare:sockets`, so requests can leave through a different
  network than the one proxyjoss runs on.

## What the proxy list actually is

The default feed is
[Emilia](https://github.com/papapapapdelesia/Emilia)'s `Data/alive.txt`, rows of
`ip,port,country,isp`.

Those addresses are **Cloudflare edge IPs, not forward proxies.** This was
measured against the live feed rather than assumed:

| Probe | Result |
| --- | --- |
| SOCKS5 greeting | answered with `4854` — ASCII `HT`, the start of an HTTP response |
| HTTP `CONNECT` | `400 Server: cloudflare` |
| TLS handshake, SNI `example.com` / `cloudflare.com` | succeeds |
| TLS handshake, SNI `kernel.org`, `mozilla.org`, `neverssl.com` | fails |

So the practical consequences:

- `forward` and `auto` mode are **useless against this feed**; a connection to
  an entry is an HTTP server, not a proxy. They still work against a feed of
  real forward proxies, which is why the modes exist.
- `relay` reaches the entry and lets the client speak to it directly. It works,
  and it only works for destinations Cloudflare serves, because the client's own
  TLS carries the SNI.
- `worker` reaches the same entry through a Cloudflare Worker. The bytes are
  identical; the difference is visibility, and it is worth having.

### Why `worker` exists

Dialling an entry directly already works, so `worker` is not about capability.
It is about what leaves the machine.

With `relay`, the TLS ClientHello that crosses the local network carries the
**destination's real SNI in the clear.** Anything on the path can read it, and
that is precisely what a filter looks for. With `worker`, the hop to the edge
presents the **Worker's own domain** as its SNI, and the real destination name
never appears outside the encrypted session:

```
relay    you ──── SNI: example.com ──────────────────▶ edge ──▶ origin
worker   you ── SNI: tunnel.example.workers.dev ─▶ Worker ─▶ edge ─▶ origin
                └──────── the real SNI is inside here ────────┘
```

The mechanism is that an Emilia address is a Cloudflare edge node announced
inside an ISP's own IP space, so the dial target and the SNI are chosen
independently. Dialing `10.0.0.1` with `ServerName` set to a routed zone makes
that edge serve the Worker.

```json
"upstream": {
  "mode": "worker",
  "max_attempts": 12,
  "sni": "example.com",
  "worker": {
    "host": "tunnel.example.workers.dev",
    "token": "the same secret as the Worker's TUNNEL_TOKEN",
    "timeout": "10s"
  }
}
```

`worker.host` is what makes the hop work, and it must be a bare hostname: a
scheme is forgiven, a port or path is rejected.

### What a destination actually sees

A feed address is the **ingress** hop. It is not automatically the address the
destination sees, and pretending otherwise is how a proxy ends up looking like it
works while leaking.

Measured against the live feed, one pinned entry at a time:

| | |
| --- | --- |
| destination reported the feed address | 5 of 12 |
| destination reported the edge's own egress | 7 of 12 |
| destination reported this host's address | 0 of 12 |

The two cases are the same mechanism. The edge node accepts the connection on the
address from the feed, then opens its own connection to the origin, and it leaves
from Cloudflare's space rather than from the address it was dialled on. Whether a
given node happens to egress on the address it ingresses is up to that node.

The row that matters is the third. If the host's own address ever appears, the
request bypassed the proxy. Run the check rather than reasoning about it:

```bash
./scripts/verify-worker-exit-ip.sh /path/to/config.json 12
```

It pins each entry with a `proxy-<id>` selector, asks an echo service what source
address it observed, and fails loudly if the host's own address shows up.

### What `worker` cannot do

- **Only destinations Cloudflare serves.** The edge has no certificate for
  anything else, so the client's TLS fails. This is inherent to the feed, not to
  this mode.
- **No plaintext.** The hop is port 443 and the edge only speaks TLS, so a
  plain `http://` request comes back as Cloudflare's own
  `400 The plain HTTP request was sent to HTTPS port`. Use `https://`.
- **The Worker itself cannot dial every address.** `connect()` is refused for
  port 80 and for addresses inside Cloudflare's own published ranges, which is
  why `example.com` and `1.1.1.1` fail from inside a Worker while the Emilia
  addresses succeed.

## Install

```bash
go build -o proxyjoss ./cmd/proxyjoss
```

## Run

```bash
cp config.example.json config.json
./proxyjoss -config config.json
```

```
proxy listening on 127.0.0.1:8080 (HTTP + SOCKS5)
status API on http://127.0.0.1:9090/
```

```bash
curl -x http://global@127.0.0.1:8080 https://example.com
curl --socks5-hostname country-ID:127.0.0.1:8080 https://example.com
```

## Container

The image is built from the same source and is configured entirely by
environment, so no config file is needed inside the container.

```bash
docker run --rm -p 8080:8080 -p 9090:9090   -e PROXYJOSS_UPSTREAM_MODE=worker   -e PROXYJOSS_UPSTREAM_WORKER_HOST=proxyjoss-tunnel.insidexofficial.workers.dev   -e PROXYJOSS_UPSTREAM_WORKER_TOKEN=<the Workers TUNNEL_TOKEN>   -e PROXYJOSS_UPSTREAM_WORKER_EGRESS=direct   -e PROXYJOSS_UPSTREAM_SNI=example.com   -e PROXYJOSS_UPSTREAM_DIAL_TIMEOUT=4s   -e PROXYJOSS_UPSTREAM_MAX_ATTEMPTS=12   -e PROXYJOSS_HEALTH_ENABLED=true   ghcr.io/kelvinzer0/proxyjoss:latest
```

A `docker-compose.yml` is also shipped; it enforces the required token
variable so you cannot forget it:

```bash
PROXYJOSS_UPSTREAM_WORKER_TOKEN=<token> docker compose up
```

The image is multi-arch (amd64, arm64), runs as non-root, and carries a
built-in health check that hits the status API. Version stamping means
`proxyjoss version` inside the container reports the tag the image was cut
from, not a hard-coded string.

Every field can be overridden at runtime by the same `PROXYJOSS_` variables,
so the image works for any Worker, any feed, any selector.

## Selectors

The proxy username chooses the egress. SOCKS5 uses the username field; HTTP
proxy auth uses the username in the URL.

| Username | Meaning |
| --- | --- |
| `global` | every entry, rotating (the default) |
| `country-ID` | entries in one country |
| `isp-biznet` | entries from one organisation, matched loosely |
| `proxy-h03c19005` | one specific entry, stable across feed refreshes |
| `proxy-42` | one entry by position, which shifts when the feed changes |

Set `auth.required` and `auth.password` to make the password mandatory. Without
one, any password is accepted and the username alone decides the selector, so
**an unauthenticated listener is a free proxy** — bind it to `127.0.0.1` unless
you have put authentication in front of it.

## Commands

```bash
proxyjoss                      # serve
proxyjoss check                # load the feed and summarise the pool
proxyjoss doctor -probes 20    # and probe a sample of entries
proxyjoss version
```

`doctor` is the fastest way to see what the feed really contains before trusting
it with traffic.

## Status API

Read-only, on `admin.addr`:

| Path | Purpose |
| --- | --- |
| `/healthz` | `503` when nothing is usable, `200` otherwise |
| `/stats` | pool totals, health aggregate, live traffic counters |
| `/proxies` | paged entry list, with health and cooldown |
| `/countries` | country buckets |
| `/isps` | organisation buckets |
| `/selectors` | what a username would resolve to |
| `/probe?addr=...` | probe one entry on demand |

## Control plane for the Worker

Two extra endpoints, served on the same listener, let a Worker hold no list of
its own. They are refused entirely until `admin.control_token` is set, and
require that token in an `X-Proxyjoss-Token` header.

| Path | Purpose |
| --- | --- |
| `GET /control/resolve?selector=...&n=...` | ranked egress list, `404` when nothing is offerable |
| `POST /control/report` | record egress success and failure |

Entries in cooldown are excluded, and a `404` is the signal to stop trying that
egress rather than an error to retry. Entries that have never been checked *are*
included, because the Worker is the thing that would otherwise prove them.

See [`worker/README.md`](worker/README.md) for the worker side, the deployment
commands, and the security rules it enforces.

## Development

```bash
make check      # gofmt, vet, build, test
make race       # the same tests under the race detector
make worker     # bun test in worker/
make all        # everything
```

The worker has no network dependencies in its tests: `cloudflare:sockets` is
imported lazily and the socket is injected, so `bun test` runs offline.
