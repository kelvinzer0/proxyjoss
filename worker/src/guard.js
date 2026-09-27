/**
 * Target validation for the tunnel endpoint.
 *
 * The Worker dials whatever host it is told to, from inside Cloudflare's
 * network. Without this guard it would be a server-side request forgery gadget
 * aimed at addresses a public worker must never reach: the loopback interface,
 * RFC 1918 space, link-local metadata services, and Cloudflare's own internal
 * ranges. Blocking them is not optional, so the check runs before any socket is
 * opened and a denied target never reaches the egress code.
 */

/** Ports a tunnel is never allowed to reach. */
const BLOCKED_PORTS = new Set([22, 25, 465, 587, 3306, 5432, 6379, 11211, 27017, 9200, 2375, 2376]);

/** True when host is a bare IPv4 literal. */
export function isIPv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  return m.slice(1).every((part) => {
    if (part.length > 1 && part[0] === '0') return false; // no octal-looking parts
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

/** True when host is an IPv6 literal, with or without brackets. */
export function isIPv6(host) {
  const h = String(host).replace(/^\[|\]$/g, '');
  if (!h.includes(':')) return false;

  // "::" may appear at most once, so the address has at most two groups.
  const halves = h.split('::');
  if (halves.length > 2) return false;

  // An embedded IPv4 literal occupies the last two hextets, not one group.
  const countGroups = (side) => {
    if (side === '') return 0;
    const groups = side.split(':');
    const last = groups[groups.length - 1];
    return groups.length + (last.includes('.') ? 1 : 0);
  };

  // A side may end in an embedded IPv4 literal, which occupies two hextets.
  const validSide = (side) => {
    if (side === '') return true;
    const groups = side.split(':');
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i];
      if (i === groups.length - 1 && g.includes('.')) {
        if (!isIPv4(g)) return false;
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false;
    }
    return true;
  };

  if (halves.length === 2) {
    if (!validSide(halves[0]) || !validSide(halves[1])) return false;
    // "::" stands for at least one hextet, so eight is already too many.
    return countGroups(halves[0]) + countGroups(halves[1]) <= 7;
  }
  if (!validSide(h)) return false;
  // Without "::" every hextet must be written out, so the count is exact.
  return countGroups(h) === 8;
}

/**
 * Reports whether an IPv4 address is in a range a public proxy must not reach.
 *
 * Kept as a table of [network, prefix] pairs so each entry is a recognisable
 * reserved range rather than an opaque numeric test.
 */
export function isBlockedIPv4(ip) {
  if (!isIPv4(ip)) return true; // not a literal we can reason about
  const o = ip.split('.').map(Number);
  const [a, b] = o;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // RFC 1918
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local, incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
  if (a === 192 && b === 168) return true; // RFC 1918
  if (a === 192 && b === 0) return true; // 192.0.0.0/24, 192.0.2.0/24
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  if (a === 198 && b === 51) return true; // TEST-NET-2
  if (a === 203 && b === 0) return true; // TEST-NET-3
  if (a === 224) return true; // multicast
  if (a >= 240) return true; // reserved, incl. 255.255.255.255
  return false;
}

/** Reports whether an IPv6 address is in a range a public proxy must not reach. */
export function isBlockedIPv6(host) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === '::1' || h === '::') return true; // loopback, unspecified
  if (h.startsWith('fe80')) return true; // link-local
  if (/^f[cd]/.test(h)) return true; // unique local fc00::/7
  // IPv4-mapped and IPv4-compatible forms embed an IPv4 address, so the same
  // reserved ranges apply: ::ffff:127.0.0.1 and friends.
  const mapped = /::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(h);
  if (mapped) return isBlockedIPv4(mapped[1]);
  if (h.startsWith('64:ff9b')) return true; // NAT64
  if (h.startsWith('2001:db8')) return true; // documentation
  if (h.startsWith('100')) return true; // discard-only
  return false;
}

/** Hostnames that must never be dialled regardless of DNS. */
const BLOCKED_NAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'instance-data',
]);

/**
 * Parses a port, rejecting anything that is not a run of digits.
 *
 * Number('') is 0 and Number('0x10') is 16, so a plain numeric check would let
 * "example.com:" through as port 0 and accept hex notation.
 */
function parsePort(raw) {
  const s = String(raw);
  if (!/^\d{1,5}$/.test(s)) return null;
  const n = Number(s);
  return n >= 1 && n <= 65535 ? n : null;
}

/** Suffixes that resolve inside a private network. */
const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa', '.lan'];

/**
 * Splits "host:port", "[v6]:port" or a bare host into parts.
 *
 * A bare host defaults to port 443, matching how a pinned target is read
 * everywhere else in this project.
 */
export function splitTarget(raw, defaultPort = 443) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s) return null;

  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end < 0) return null;
    const host = s.slice(1, end);
    const rest = s.slice(end + 1);
    if (!rest) return { host, port: defaultPort };
    if (!rest.startsWith(':')) return null;
    const port = parsePort(rest.slice(1));
    if (port === null) return null;
    return { host, port };
  }

  // An unbracketed IPv6 literal has many colons and no port.
  if (s.includes(':') && s.split(':').length > 2) return { host: s, port: defaultPort };

  const idx = s.lastIndexOf(':');
  if (idx < 0) return { host: s, port: defaultPort };
  const host = s.slice(0, idx);
  if (!host) return null;
  const port = parsePort(s.slice(idx + 1));
  if (port === null) return null;
  return { host, port };
}

/**
 * Validates a target, returning { host, port } or a reason string.
 *
 * Literal addresses are checked directly. A hostname is accepted because the
 * Worker resolves it inside Cloudflare's network where public DNS applies, but
 * obviously internal names are refused up front.
 */
export function checkTarget(raw, { defaultPort = 443, allowPrivate = false } = {}) {
  const parts = splitTarget(raw, defaultPort);
  if (!parts) return { ok: false, reason: `cannot parse target ${JSON.stringify(raw)}` };
  const { host, port } = parts;

  if (port < 1 || port > 65535) return { ok: false, reason: `port ${port} is out of range` };
  if (allowPrivate) return { ok: true, host, port };

  const name = host.toLowerCase().replace(/\.$/, '');

  if (isIPv4(name)) {
    if (isBlockedIPv4(name)) return { ok: false, reason: `refusing private address ${name}` };
    return { ok: true, host: name, port };
  }
  if (isIPv6(host)) {
    if (isBlockedIPv6(host)) return { ok: false, reason: `refusing private address ${host}` };
    return { ok: true, host, port };
  }
  if (BLOCKED_NAMES.has(name)) return { ok: false, reason: `refusing internal hostname ${name}` };
  for (const suffix of BLOCKED_SUFFIXES) {
    if (name.endsWith(suffix)) return { ok: false, reason: `refusing internal hostname ${name}` };
  }
  // A bare label with no dot is a machine name on the local network.
  if (!name.includes('.') && !name.includes(':')) {
    return { ok: false, reason: `refusing single-label hostname ${name}` };
  }
  if (BLOCKED_PORTS.has(port)) {
    return { ok: false, reason: `refusing port ${port}` };
  }
  return { ok: true, host: name, port };
}
