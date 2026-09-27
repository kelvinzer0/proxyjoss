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
- `relay` reaches the entry and lets the client speak to it directly. That is
  the only mode that does anything useful here, and it only works for
  destinations Cloudflare serves, because the client's own TLS carries the SNI.
- Anything else needs the Worker, which reaches the destination from Cloudflare's
  network and optionally pins the egress address it leaves from.

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
