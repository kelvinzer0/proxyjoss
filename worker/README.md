# proxyjoss-tunnel

Cloudflare Worker yang berfungsi sebagai **data plane** untuk proxyjoss.

## Apa yang sebenarnya dilakukan Worker ini

Worker Cloudflare hanya menerima HTTP. Tidak ada cara membuka port TCP mentah ke
Worker, jadi ini **bukan** proxy SOCKS5 atau HTTP mandiri. Yang dibangun adalah hop
upstream dari proxyjoss, yang tetap memegang listener TCP untuk klien:

```
klien -> proxyjoss (SOCKS5 / HTTP di port asli)
      -> WebSocket  -> worker ini
      -> cloudflare:sockets connect() -> egress
```

proxyjoss adalah **control plane**: ia memiliki daftar proxy, health, selector,
dan API admin. Worker menanyakan daftar egress terurut ke sana, bukan mengunduh
feed sendiri, supaya hanya ada satu implementasi parsing, de-duplikasi, health,
dan cooldown.

## Dua bentuk egress

Feed Emilia bukan kumpulan forward proxy. Address di dalamnya adalah IP edge
Cloudflare, dan koneksi TCP polos ke address itu hanya bisa membawa lalu lintas
yang SNI TLS-nya milik zona yang dilayani Cloudflare. Ini sudah diverifikasi
langsung terhadap feed yang hidup:

| Uji | Hasil |
| --- | --- |
| SOCKS5 greeting | dijawab `4854` (`"HT"`), yaitu respons HTTP |
| HTTP `CONNECT` | `400 Server: cloudflare` |
| TLS, SNI `example.com` / `cloudflare.com` | berhasil |
| TLS, SNI non-Cloudflare (`kernel.org`, `mozilla.org`, `neverssl.com`) | gagal |

Karena itu ada dua strategi:

- `direct` — `connect({ hostname: target })`. Mencapai semua tujuan.
- `edge` — `connect({ hostname: entry, port: entryPort })` dari daftar Emilia.
  Hanya untuk target yang di-hosting Cloudflare, tetapi memberi IP sumber
  berbeda dan bisa dipilih per negara.

Parameter `egress` pada permintaan:

| Nilai | Perilaku |
| --- | --- |
| `auto` (default) | coba `edge` bila ada kandidat, lalu jatuh ke `direct` |
| `edge` | hanya `edge`; permintaan gagal bila semua entry mati |
| `direct` | selalu koneksi langsung |

Fallback dari `edge` ke `direct` disengaja: percobaan `edge` ke target
non-Cloudflare hanya berujung pada satu kegagalan TLS, sedangkan melewati `edge` yang diminta
menghapus egress yang dipilih pengguna. Mode `edge` tersedia untuk yang benar-benar
butuh egress tersebut dan bersedia gagal.

## Endpoint

### `GET /` dan `GET /healthz`

Melaporkan status konfigurasi. Tidak pernah membocorkan secret.

### `GET /tunnel`

Harus WebSocket upgrade. Parameter:

| Parameter | Wajib | Keterangan |
| --- | --- | --- |
| `target` | ya | `host:port`, default port 443 |
| `token` | ya* | shared secret, boleh lewat header `X-Proxyjoss-Token` |
| `selector` | tidak | diteruskan ke control plane, default `global` |
| `egress` | tidak | `auto`, `edge`, atau `direct` |

*Header lebih diutamakan daripada query parameter karena handshake WebSocket dari browser
tidak bisa mengatur header, sedangkan klien Go bisa.*

Contoh:

```
ws://tunnel.example.workers.dev/tunnel?target=example.com:443&token=SHARED&selector=country-ID&egress=edge
```

### `GET /cache/flush`

Mengosongkan cache daftar egress.

## Keamanan

Worker yang bisa dialing ke destination atas permintaan adalah open proxy kecuali ia
menolak pemanggil anonim, jadi dua hal ini tidak opsional:

- **Auth gagal-tertutup.** Tanpa `TUNNEL_TOKEN` yang dikonfigurasi, setiap
  permintaan ditolak `503`, bukan diizinkan. Perbandingan token dilakukan
  constant-time.
- **Guard SSRF** (`src/guard.js`) berjalan sebelum socket apa pun dibuka, sehingga
  target yang ditolak tidak pernah memakai egress maupun CPU Worker. Ditolak:
  loopback, RFC 1918, link-local termasuk `169.254.169.254` untuk metadata
  instance, CGNAT, multicast, TEST-NET, alamat IPv4-mapped dari blok di atas,
  nama host internal (`.local`, `.internal`, `localhost`), single-label hostname,
  dan port yang tidak pantas untuk proxy publik (22, 25, 3306, 6379, 9200, …).

Semua permintaan yang bisa ditolak tanpa socket ditolak lebih dulu, di
`parseTunnelRequest`, sebelum ada socket yang dibuka.

## Kontrak control plane

Dilayani proxyjoss di listener admin. Shared secret lewat header
`X-Proxyjoss-Token`.

### `GET /control/resolve?selector=<name>&n=<count>`

```json
{
  "selector": "global",
  "candidates": [{ "addr": "146.70.37.253:2087", "country": "ID", "score": 9.1 }]
}
```

- `401` bila secret salah atau hilang
- `404` bila selector tidak cocok apa pun, yang Worker perlakukan sebagai "tidak
  ada kandidat" dan bukan error
- `candidates` sudah terurut, sehat, dan cooldown sudah diperhitungkan oleh
  control plane

### `POST /control/report`

```json
{ "results": [{ "addr": "146.70.37.253:2087", "ok": true, "ms": 42 }] }
```

`202` bila diterima. Laporan ini尽力而为: kegagalan reporting tidak pernah
memengaruhi permintaan yang sedang dilayani, dan Worker tidak pernah gagal hanya
karena control plane sedang tidak dapat dihubungi.

## Ketahanan

- Daftar egress di-cache per isolate (`CONTROL_PLANE_TTL_MS`, default 30 detik),
  sehingga ledakan koneksi tidak menjadi ledakan permintaan ke control plane.
- Control plane yang error dilayani dengan daftar lama yang ditandai `stale`,
  bukan dengan kehilangan egress.
- Maksimal tiga entry dicoba sebelum menyerah pada jalur `edge`, dengan anggaran
  waktu total 4 detik.
- Socket yang gagal pada upstream dianggap ditutup normal, bukan error, sehingga
  satu sisi yang tutup tidak时报galat pada sisi lain.

## Pengembangan

```bash
bun test          # 81 test, tanpa network
npx wrangler dev  # dijalankan di workerd dengan cloudflare:sockets sungguhan
npx wrangler secret put TUNNEL_TOKEN
npx wrangler secret put CONTROL_PLANE_TOKEN
npx wrangler deploy
```

`cloudflare:sockets` di-import secara dinamis hanya di jalur tunnel, supaya
`bun test` bisa berjalan di luar workerd. Egress di-inject lewat `env.__connect`
dalam test.
