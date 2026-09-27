import { describe, expect, test } from 'bun:test';
import { authenticate, timingSafeEqual } from '../src/auth.js';

const url = (query = '') => new URL(`https://tunnel.example/tunnel${query}`);

describe('timingSafeEqual', () => {
  test('compares content', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
    expect(timingSafeEqual('', '')).toBe(true);
    expect(timingSafeEqual(undefined, 'a')).toBe(false);
  });
});

describe('authenticate', () => {
  test('fails closed when no token is configured', () => {
    const res = authenticate({}, url('?token=anything'), new Headers());
    expect(res.ok).toBe(false);
    expect(res.status).toBe(503);
  });

  test('rejects a missing token', () => {
    const res = authenticate({ TUNNEL_TOKEN: 'secret' }, url(), new Headers());
    expect(res.ok).toBe(false);
    expect(res.status).toBe(401);
  });

  test('rejects a wrong token', () => {
    const res = authenticate({ TUNNEL_TOKEN: 'secret' }, url('?token=wrong'), new Headers());
    expect(res.ok).toBe(false);
    expect(res.status).toBe(403);
  });

  test('accepts the token from a query parameter', () => {
    const res = authenticate({ TUNNEL_TOKEN: 'secret' }, url('?token=secret'), new Headers());
    expect(res.ok).toBe(true);
    expect(res.selector).toBe('global');
  });

  test('accepts the token from a header', () => {
    const res = authenticate({ TUNNEL_TOKEN: 'secret' }, url(), new Headers({ 'X-Proxyjoss-Token': 'secret' }));
    expect(res.ok).toBe(true);
  });

  test('prefers the header over the query parameter', () => {
    const env = { TUNNEL_TOKEN: 'secret' };
    const res = authenticate(env, url('?token=wrong'), new Headers({ 'X-Proxyjoss-Token': 'secret' }));
    expect(res.ok).toBe(true);
  });

  test('reads and caps the selector', () => {
    const env = { TUNNEL_TOKEN: 'secret' };
    expect(authenticate(env, url('?token=secret&selector=country-ID'), new Headers()).selector).toBe('country-ID');
    const long = 'x'.repeat(200);
    expect(authenticate(env, url(`?token=secret&selector=${long}`), new Headers()).selector).toHaveLength(64);
  });
});
