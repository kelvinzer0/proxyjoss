import { describe, expect, test } from 'bun:test';
import { checkTarget, isBlockedIPv4, isBlockedIPv6, isIPv4, isIPv6, splitTarget } from '../src/guard.js';

describe('isIPv4', () => {
  test('accepts dotted quads in range', () => {
    for (const ip of ['1.2.3.4', '0.0.0.0', '255.255.255.255', '146.70.37.253']) {
      expect(isIPv4(ip)).toBe(true);
    }
  });

  test('rejects malformed literals', () => {
    for (const ip of ['1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.a', '01.2.3.4', '', '1.2.3.-4']) {
      expect(isIPv4(ip)).toBe(false);
    }
  });
});

describe('isBlockedIPv4', () => {
  test('blocks loopback, RFC 1918, link-local and metadata', () => {
    for (const ip of [
      '127.0.0.1',
      '127.9.9.9',
      '10.0.0.1',
      '172.16.0.1',
      '172.31.255.254',
      '192.168.1.1',
      '169.254.169.254', // cloud instance metadata
      '0.0.0.0',
      '100.64.0.1', // CGNAT
      '198.18.0.1', // benchmarking
      '203.0.113.5', // TEST-NET-3
      '224.0.0.1',
      '255.255.255.255',
    ]) {
      expect(isBlockedIPv4(ip)).toBe(true);
    }
  });

  test('allows public addresses', () => {
    for (const ip of ['1.1.1.1', '8.8.8.8', '146.70.37.253', '172.15.0.1', '172.32.0.1', '192.169.1.1', '100.128.0.1']) {
      expect(isBlockedIPv4(ip)).toBe(false);
    }
  });
});

describe('isBlockedIPv6', () => {
  test('blocks loopback, unique-local, link-local and mapped forms', () => {
    for (const ip of ['::1', '::', 'fe80::1', 'fd00::1', 'fc00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::1', '2001:db8::1']) {
      expect(isBlockedIPv6(ip)).toBe(true);
    }
  });

  test('allows public addresses', () => {
    for (const ip of ['2606:4700::1', '2001:4860:4860::8888']) {
      expect(isBlockedIPv6(ip)).toBe(false);
    }
  });

  test('is strict about IPv6 syntax', () => {
    // Valid: full form, compressed form, embedded IPv4.
    expect(isIPv6('2606:4700:4700::1111')).toBe(true);
    expect(isIPv6('::')).toBe(true);
    expect(isIPv6('2001:db8::1')).toBe(true);
    expect(isIPv6('0:0:0:0:0:0:1.2.3.4')).toBe(true);
    expect(isIPv6('fe80::1%eth0'.split('%')[0])).toBe(true);

    // Invalid: too few hextets without "::", repeated "::", oversized groups,
    // and non-hex characters.
    expect(isIPv6('a:b:c')).toBe(false);
    expect(isIPv6('2606:4700::1::2')).toBe(false);
    expect(isIPv6('12345::1')).toBe(false);
    expect(isIPv6('2606:4700::zzzz')).toBe(false);
    expect(isIPv6('1.2.3.4')).toBe(false);
  });

  test('rejects an address with nine hextets', () => {
    expect(isIPv6('1:2:3:4:5:6:7:8:9')).toBe(false);
  });
});

describe('splitTarget', () => {
  test('splits host and port', () => {
    expect(splitTarget('example.com:8443')).toEqual({ host: 'example.com', port: 8443 });
  });

  test('defaults a bare host to 443', () => {
    expect(splitTarget('example.com')).toEqual({ host: 'example.com', port: 443 });
  });

  test('handles bracketed IPv6', () => {
    expect(splitTarget('[2606:4700::1]:443')).toEqual({ host: '2606:4700::1', port: 443 });
    expect(splitTarget('[2606:4700::1]')).toEqual({ host: '2606:4700::1', port: 443 });
  });

  test('treats an unbracketed IPv6 literal as host only', () => {
    expect(splitTarget('2606:4700::1111')).toEqual({ host: '2606:4700::1111', port: 443 });
  });

  test('rejects nonsense', () => {
    for (const bad of ['', '   ', 'example.com:', ':443', '[2606:4700::1', 'example.com:http']) {
      expect(splitTarget(bad)).toBeNull();
    }
  });
});

describe('checkTarget', () => {
  test('accepts a public host and port', () => {
    expect(checkTarget('example.com:443')).toEqual({ ok: true, host: 'example.com', port: 443 });
  });

  test('refuses private literals', () => {
    for (const bad of ['127.0.0.1:80', '10.1.2.3:443', '192.168.0.1', '169.254.169.254:80', '[::1]:443']) {
      const res = checkTarget(bad);
      expect(res.ok).toBe(false);
      expect(res.reason).toMatch(/private|parse/i);
    }
  });

  test('refuses internal hostnames', () => {
    for (const bad of ['localhost', 'metadata.google.internal', 'db.internal', 'router.local', 'printer.lan', 'myserver']) {
      expect(checkTarget(bad).ok).toBe(false);
    }
  });

  test('refuses an out of range port', () => {
    expect(checkTarget('example.com:0').ok).toBe(false);
    expect(checkTarget('example.com:70000').ok).toBe(false);
  });

  test('refuses ports a public proxy should not reach', () => {
    expect(checkTarget('example.com:22').ok).toBe(false);
    expect(checkTarget('example.com:6379').ok).toBe(false);
  });

  test('allowPrivate permits the internal addresses, for tests and private use', () => {
    expect(checkTarget('127.0.0.1:8080', { allowPrivate: true })).toEqual({
      ok: true,
      host: '127.0.0.1',
      port: 8080,
    });
  });

  test('normalises a trailing dot and case', () => {
    expect(checkTarget('Example.COM.:443')).toEqual({ ok: true, host: 'example.com', port: 443 });
  });
});
