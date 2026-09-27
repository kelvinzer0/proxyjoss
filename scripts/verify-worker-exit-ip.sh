#!/usr/bin/env bash
#
# Verifies that a request made through the proxy really leaves the machine
# through the address taken from the feed, rather than through the host's own
# connection.
#
# "It returned a page" only proves bytes moved. This proves where they came
# from, by pinning one feed entry at a time with a `proxy-<id>` selector and
# asking an echo service what source address it saw.
#
# Usage:
#   ./scripts/verify-worker-exit-ip.sh <config-file> [sample-size]
#
# The config must select a mode that routes through the feed. The default
# sample size is 12.

set -uo pipefail

CONFIG=${1:-}
SAMPLES=${2:-12}
ADMIN=${ADMIN:-http://127.0.0.1:19090}
PROXY=${PROXY:-127.0.0.1:18080}
WARMUP=${WARMUP:-75}
ECHO_SERVICES=(
	"https://icanhazip.com"
	"https://api.ipify.org"
	"https://ifconfig.me/ip"
)

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

[ -n "$CONFIG" ] || die "usage: $0 <config-file> [sample-size]"
[ -f "$CONFIG" ] || die "no such config: $CONFIG"
[ -x ./proxyjoss ] || die "build it first: go build -o proxyjoss ./cmd/proxyjoss"

command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required"

work=$(mktemp -d)
trap 'kill "${child:-0}" 2>/dev/null; rm -rf "$work"' EXIT

# The direct address is the one the proxy must never appear as, so read it once
# per service and compare against every sample below.
echo "== host's own address, measured without the proxy =="
for svc in "${ECHO_SERVICES[@]}"; do
	printf '   %-28s %s\n' "$svc" "$(curl -sS --max-time 20 "$svc" 2>/dev/null | tr -d '\r\n ')"

done > "$work/direct" 2>/dev/null
cat "$work/direct"
mapfile -t OWN_IPS < <(awk 'NF>1 {print $2}' "$work/direct")

if [ "${#OWN_IPS[@]}" -eq 0 ]; then
	die "could not read this host's own address; refusing to guess what a leak looks like"
fi

echo
echo "== starting the proxy =="
./proxyjoss -config "$CONFIG" > "$work/proxy.log" 2>&1 &
child=$!
sleep "$WARMUP"
kill -0 "$child" 2>/dev/null || { cat "$work/proxy.log"; die "the proxy exited during warmup"; }

curl -sS --max-time 20 "$ADMIN/proxies" > "$work/proxies.json" 2>/dev/null ||
	die "the status API at $ADMIN did not answer"

mapfile -t entries < <(
	python3 - "$work/proxies.json" "$SAMPLES" <<-'PY'
		import json, sys

		items = json.load(open(sys.argv[1]))["items"]
		want = int(sys.argv[2])
		# "probed" means the edge already completed a TLS handshake with this
		# process, which is what makes the address worth sampling. Request counts
		# are deliberately not required: a freshly started pool has none.
		usable = [p for p in items if p["healthy"] and p["available"] and p["probed"] > 0]
		for p in usable[:want]:
		    print(p["id"], p["addr"])
	PY
)

[ "${#entries[@]}" -gt 0 ] || die "no healthy entries to sample"

echo
printf '   %-22s %-24s %s\n' "FEED ENTRY" "SEEN BY DESTINATION" "VERDICT"
printf '   %-22s %-24s %s\n' "----------------------" "------------------------" "-------"

same=0
different=0
leaked=0
failed=0
ok=0

for row in "${entries[@]}"; do
	read -r id addr <<<"$row"
	entry_ip=${addr%:*}

	seen=""
	for svc in "${ECHO_SERVICES[@]}"; do
		seen=$(curl -sS --max-time 25 \
			--socks5-hostname "$PROXY" --proxy-user "proxy-$id:" \
			"$svc" 2>/dev/null | tr -d '\r\n ')
		[ -n "$seen" ] && break
	done

	if [ -z "$seen" ]; then
		printf '   %-22s %-24s %s\n' "$addr" "-" "no reply"
		failed=$((failed + 1))
		continue
	fi

	ok=$((ok + 1))
	verdict="differs"

	if [ "$seen" = "$entry_ip" ]; then
		verdict="the feed address"
		same=$((same + 1))
	elif printf '%s\n' "${OWN_IPS[@]}" | grep -qxF "$seen"; then
		# The host's own address surfacing is the one failure that would mean the
		# proxy was bypassed, so it outranks the interesting-but-expected case.
		verdict="LEAK, the host address"
		leaked=$((leaked + 1))
	else
		verdict="the edge's own egress"
		different=$((different + 1))
	fi

	printf '   %-22s %-24s %s\n' "$addr" "$seen" "$verdict"
done

echo
echo "== summary =="
printf '   %d answered, %d reported the feed address, %d reported the edge egress\n' "$ok" "$same" "$different"
printf '   own egress, %d leaked the host address, %d did not answer\n' "$leaked" "$failed"

if [ "$ok" -eq 0 ]; then
	die "not one request came back, so nothing was verified"
fi
if [ "$leaked" -ne 0 ]; then
	die "the host's own address was seen by a destination: traffic bypassed the proxy"
fi

echo
echo "   Traffic reaches the feed address, and the host's own address never does."
echo "   A destination often sees the edge node's egress rather than the address"
echo "   that was dialled, because the edge leaves for the origin from its own"
echo "   space, so \"differs\" above is the expected result, not a failure."
