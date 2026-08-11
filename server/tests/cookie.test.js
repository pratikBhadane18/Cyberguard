'use strict';

/**
 * CyberGuard Cookie Scanner Tests
 *
 * All tests are deterministic — no external network calls.
 * We test with mock Set-Cookie header strings and objects.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  analyzeCookies,
  parseCookie,
  analyzeCookieSecurity,
  isLikelySessionCookie,
  extractSetCookieHeaders,
} = require('../src/services/cookieScanner');

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Returns the finding for a specific attribute from a cookie's findings array. */
const findingFor = (cookie, attr) =>
  cookie.findings.find((f) => f.attribute === attr) ?? null;

// ── 1. extractSetCookieHeaders ────────────────────────────────────────────────

describe('extractSetCookieHeaders()', () => {
  it('returns empty array when set-cookie is absent', () => {
    assert.deepEqual(extractSetCookieHeaders({}), []);
  });

  it('returns array when set-cookie is already an array', () => {
    const h = { 'set-cookie': ['a=1', 'b=2'] };
    assert.deepEqual(extractSetCookieHeaders(h), ['a=1', 'b=2']);
  });

  it('wraps a single string value in an array', () => {
    const h = { 'set-cookie': 'a=1; HttpOnly' };
    assert.deepEqual(extractSetCookieHeaders(h), ['a=1; HttpOnly']);
  });

  it('handles mixed-case header key (Set-Cookie)', () => {
    const h = { 'Set-Cookie': ['x=1'] };
    assert.deepEqual(extractSetCookieHeaders(h), ['x=1']);
  });
});

// ── 2. parseCookie ────────────────────────────────────────────────────────────

describe('parseCookie() — basic parsing', () => {
  it('parses cookie name correctly', () => {
    const c = parseCookie('session=abc123; HttpOnly');
    assert.equal(c.name, 'session');
  });

  it('ALWAYS redacts the cookie value', () => {
    const c = parseCookie('jwt=eyJhbGciOiJIUzI1NiJ9.payload.sig; Secure; HttpOnly');
    assert.equal(c.redactedValue, '[REDACTED]');
    // The raw JWT must not appear anywhere in the result object
    const json = JSON.stringify(c);
    assert.ok(!json.includes('eyJ'), 'JWT value must be redacted');
  });

  it('parses Secure attribute (flag, case-insensitive)', () => {
    assert.equal(parseCookie('a=1; Secure').secure, true);
    assert.equal(parseCookie('a=1; SECURE').secure, true);
    assert.equal(parseCookie('a=1').secure, false);
  });

  it('parses HttpOnly attribute (flag, case-insensitive)', () => {
    assert.equal(parseCookie('a=1; HttpOnly').httpOnly, true);
    assert.equal(parseCookie('a=1; HTTPONLY').httpOnly, true);
    assert.equal(parseCookie('a=1').httpOnly, false);
  });

  it('parses SameSite=Strict (case-insensitive recognition)', () => {
    const c = parseCookie('a=1; SameSite=Strict');
    assert.equal(c.sameSite, 'Strict');
  });

  it('parses SameSite=Lax', () => {
    const c = parseCookie('a=1; SameSite=Lax');
    assert.equal(c.sameSite, 'Lax');
  });

  it('parses SameSite=None', () => {
    const c = parseCookie('a=1; SameSite=None; Secure');
    assert.equal(c.sameSite, 'None');
    assert.equal(c.secure, true);
  });

  it('parses samesite= in lowercase (case-insensitive attribute key)', () => {
    const c = parseCookie('a=1; samesite=lax');
    // Value casing is preserved as-is from the header
    assert.ok(c.sameSite != null);
    assert.ok(c.sameSite.toLowerCase() === 'lax');
  });

  it('parses Path attribute', () => {
    const c = parseCookie('a=1; Path=/admin');
    assert.equal(c.path, '/admin');
  });

  it('parses Domain attribute', () => {
    const c = parseCookie('a=1; Domain=example.com');
    assert.equal(c.domain, 'example.com');
  });

  it('parses Max-Age attribute as a number', () => {
    const c = parseCookie('a=1; Max-Age=3600');
    assert.equal(c.maxAge, 3600);
  });

  it('parses Expires attribute (date string with comma preserved)', () => {
    const raw = 'a=1; Expires=Thu, 01 Jan 2026 00:00:00 GMT';
    const c = parseCookie(raw);
    assert.ok(c.expires?.includes('Jan 2026'), `Expected date in expires, got: ${c.expires}`);
  });

  it('parses a fully-featured cookie', () => {
    const raw = 'session=tok; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=example.com; Max-Age=7200';
    const c = parseCookie(raw);
    assert.equal(c.name, 'session');
    assert.equal(c.secure, true);
    assert.equal(c.httpOnly, true);
    assert.equal(c.sameSite, 'Lax');
    assert.equal(c.path, '/');
    assert.equal(c.domain, 'example.com');
    assert.equal(c.maxAge, 7200);
    assert.equal(c.redactedValue, '[REDACTED]');
  });
});

// ── 3. isLikelySessionCookie ──────────────────────────────────────────────────

describe('isLikelySessionCookie()', () => {
  const sessionNames = [
    'session', 'sessionid', 'session_id', 'connect.sid',
    'sid', 'auth', 'auth_token', 'access_token', 'refresh_token',
    'jwt', 'token', '__session',
  ];

  for (const name of sessionNames) {
    it(`flags "${name}" as likely session`, () => {
      assert.equal(isLikelySessionCookie(name), true);
    });

    it(`flags uppercase "${name.toUpperCase()}" as likely session (case-insensitive)`, () => {
      assert.equal(isLikelySessionCookie(name.toUpperCase()), true);
    });
  }

  it('does NOT flag "preferences" as a session cookie', () => {
    assert.equal(isLikelySessionCookie('preferences'), false);
  });

  it('does NOT flag "theme" as a session cookie', () => {
    assert.equal(isLikelySessionCookie('theme'), false);
  });
});

// ── 4. analyzeCookieSecurity ──────────────────────────────────────────────────

describe('analyzeCookieSecurity() — Secure attribute', () => {
  it('produces no Secure finding when Secure is present', () => {
    const c = parseCookie('session=x; Secure; HttpOnly; SameSite=Lax');
    const findings = analyzeCookieSecurity(c);
    assert.equal(findingFor({ findings }, 'Secure'), null);
  });

  it('produces MEDIUM finding for likely session cookie missing Secure', () => {
    const c = parseCookie('session=x; HttpOnly; SameSite=Lax');
    const findings = analyzeCookieSecurity(c);
    const f = findings.find((x) => x.attribute === 'Secure');
    assert.ok(f, 'Secure finding expected');
    assert.equal(f.status, 'missing');
    assert.equal(f.severity, 'MEDIUM');
  });

  it('produces LOW finding for non-session cookie missing Secure', () => {
    const c = parseCookie('theme=dark; SameSite=Lax');
    const findings = analyzeCookieSecurity(c);
    const f = findings.find((x) => x.attribute === 'Secure');
    assert.ok(f, 'Secure finding expected');
    assert.equal(f.severity, 'LOW');
  });
});

describe('analyzeCookieSecurity() — HttpOnly attribute', () => {
  it('produces no HttpOnly finding when HttpOnly is present', () => {
    const c = parseCookie('session=x; Secure; HttpOnly; SameSite=Lax');
    const findings = analyzeCookieSecurity(c);
    assert.equal(findings.find((x) => x.attribute === 'HttpOnly'), undefined);
  });

  it('produces MEDIUM finding for likely session cookie missing HttpOnly', () => {
    const c = parseCookie('session=x; Secure; SameSite=Lax');
    const findings = analyzeCookieSecurity(c);
    const f = findings.find((x) => x.attribute === 'HttpOnly');
    assert.ok(f);
    assert.equal(f.severity, 'MEDIUM');
    assert.ok(f.description.includes('JavaScript'), 'Description should mention JavaScript');
  });

  it('produces LOW finding for non-session cookie missing HttpOnly', () => {
    const c = parseCookie('prefs=dark; Secure; SameSite=Lax');
    const findings = analyzeCookieSecurity(c);
    const f = findings.find((x) => x.attribute === 'HttpOnly');
    assert.ok(f);
    assert.equal(f.severity, 'LOW');
  });
});

describe('analyzeCookieSecurity() — SameSite attribute', () => {
  it('produces no SameSite finding for SameSite=Strict', () => {
    const c = parseCookie('session=x; Secure; HttpOnly; SameSite=Strict');
    const findings = analyzeCookieSecurity(c);
    assert.equal(findings.find((x) => x.attribute === 'SameSite'), undefined);
  });

  it('produces no SameSite finding for SameSite=Lax', () => {
    const c = parseCookie('session=x; Secure; HttpOnly; SameSite=Lax');
    const findings = analyzeCookieSecurity(c);
    assert.equal(findings.find((x) => x.attribute === 'SameSite'), undefined);
  });

  it('produces no finding for SameSite=None WITH Secure', () => {
    const c = parseCookie('embed=x; SameSite=None; Secure');
    const findings = analyzeCookieSecurity(c);
    const sameSiteFinding = findings.find((x) => x.attribute === 'SameSite');
    assert.equal(sameSiteFinding, undefined,
      'SameSite=None with Secure is valid — no finding expected');
  });

  it('produces MEDIUM finding for SameSite=None without Secure', () => {
    const c = parseCookie('embed=x; SameSite=None');
    const findings = analyzeCookieSecurity(c);
    const f = findings.find((x) => x.attribute === 'SameSite');
    assert.ok(f, 'SameSite finding expected');
    assert.equal(f.status, 'misconfigured');
    assert.equal(f.severity, 'MEDIUM');
  });

  it('produces LOW finding when SameSite is missing', () => {
    const c = parseCookie('prefs=dark; Secure; HttpOnly');
    const findings = analyzeCookieSecurity(c);
    const f = findings.find((x) => x.attribute === 'SameSite');
    assert.ok(f, 'Missing SameSite finding expected');
    assert.equal(f.status, 'missing');
    assert.equal(f.severity, 'LOW');
  });
});

// ── 5. analyzeCookies — integration over mock headers ────────────────────────

describe('analyzeCookies() — no cookies', () => {
  it('returns analyzed:true with count 0 and empty array when no Set-Cookie', () => {
    const result = analyzeCookies({});
    assert.equal(result.analyzed, true);
    assert.equal(result.count, 0);
    assert.deepEqual(result.cookies, []);
  });
});

describe('analyzeCookies() — single secure session cookie', () => {
  const headers = {
    'set-cookie': ['session=tok; HttpOnly; Secure; SameSite=Lax; Path=/'],
  };

  it('returns count 1', () => {
    assert.equal(analyzeCookies(headers).count, 1);
  });

  it('cookie name is "session"', () => {
    const { cookies } = analyzeCookies(headers);
    assert.equal(cookies[0].name, 'session');
  });

  it('flags as likelySession', () => {
    assert.equal(analyzeCookies(headers).cookies[0].likelySession, true);
  });

  it('has no security findings for a fully-configured session cookie', () => {
    assert.equal(analyzeCookies(headers).cookies[0].findings.length, 0);
  });

  it('redactedValue is [REDACTED]', () => {
    assert.equal(analyzeCookies(headers).cookies[0].redactedValue, '[REDACTED]');
  });
});

describe('analyzeCookies() — multiple cookies', () => {
  const headers = {
    'set-cookie': [
      'session=abc; HttpOnly; Secure; SameSite=Strict',
      'prefs=dark; SameSite=Lax',
      'analytics=xyz; SameSite=Lax',
    ],
  };

  it('returns correct count', () => {
    assert.equal(analyzeCookies(headers).count, 3);
  });

  it('session cookie has likelySession:true', () => {
    const session = analyzeCookies(headers).cookies.find((c) => c.name === 'session');
    assert.equal(session.likelySession, true);
  });

  it('prefs cookie has likelySession:false', () => {
    const prefs = analyzeCookies(headers).cookies.find((c) => c.name === 'prefs');
    assert.equal(prefs.likelySession, false);
  });

  it('no cookie contains the actual value string', () => {
    const result = analyzeCookies(headers);
    const json = JSON.stringify(result);
    assert.ok(!json.includes('abc'), 'Session value "abc" must be redacted');
    assert.ok(!json.includes('dark'), '"dark" preference value must be redacted');
    assert.ok(!json.includes('xyz'), '"xyz" analytics value must be redacted');
  });
});

describe('analyzeCookies() — JWT value redaction', () => {
  it('JWT value never appears in findings or cookie metadata', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxw';
    const headers = { 'set-cookie': [`jwt=${jwt}; HttpOnly; Secure; SameSite=Strict`] };
    const result = analyzeCookies(headers);
    const json = JSON.stringify(result);
    assert.ok(!json.includes(jwt), 'JWT value must not appear in output');
    assert.ok(!json.includes('eyJhbGci'), 'JWT header segment must not appear in output');
  });
});

describe('analyzeCookies() — severity rules', () => {
  it('session cookie without Secure → MEDIUM', () => {
    const h = { 'set-cookie': ['session=x; HttpOnly; SameSite=Lax'] };
    const cookie = analyzeCookies(h).cookies[0];
    const f = cookie.findings.find((x) => x.attribute === 'Secure');
    assert.equal(f.severity, 'MEDIUM');
  });

  it('non-session cookie without Secure → LOW', () => {
    const h = { 'set-cookie': ['prefs=dark; SameSite=Lax'] };
    const cookie = analyzeCookies(h).cookies[0];
    const f = cookie.findings.find((x) => x.attribute === 'Secure');
    assert.equal(f.severity, 'LOW');
  });

  it('SameSite=None without Secure → MEDIUM', () => {
    const h = { 'set-cookie': ['embed=x; SameSite=None'] };
    const cookie = analyzeCookies(h).cookies[0];
    const f = cookie.findings.find((x) => x.attribute === 'SameSite');
    assert.equal(f.severity, 'MEDIUM');
  });

  it('missing SameSite → LOW', () => {
    const h = { 'set-cookie': ['prefs=x; Secure; HttpOnly'] };
    const cookie = analyzeCookies(h).cookies[0];
    const f = cookie.findings.find((x) => x.attribute === 'SameSite');
    assert.equal(f.severity, 'LOW');
  });

  it('no finding uses HIGH or CRITICAL', () => {
    const h = { 'set-cookie': ['session=x'] }; // worst case: all missing
    const { cookies } = analyzeCookies(h);
    for (const cookie of cookies) {
      for (const f of cookie.findings) {
        assert.notEqual(f.severity, 'HIGH');
        assert.notEqual(f.severity, 'CRITICAL');
      }
    }
  });
});

describe('analyzeCookies() — attribute parsing edge cases', () => {
  it('parses Path and Domain from a real-world-style header', () => {
    const h = { 'set-cookie': ['prefs=v; Path=/app; Domain=sub.example.com; SameSite=Lax'] };
    const cookie = analyzeCookies(h).cookies[0];
    assert.equal(cookie.path, '/app');
    assert.equal(cookie.domain, 'sub.example.com');
  });

  it('parses Max-Age correctly', () => {
    const h = { 'set-cookie': ['tok=x; Max-Age=86400; Secure; HttpOnly; SameSite=Lax'] };
    const cookie = analyzeCookies(h).cookies[0];
    assert.equal(cookie.maxAge, 86400);
  });

  it('parses Expires date string containing a comma', () => {
    const h = { 'set-cookie': ['a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; SameSite=Lax'] };
    const cookie = analyzeCookies(h).cookies[0];
    assert.ok(cookie.expires?.includes('2026'), 'Expires year should be preserved');
  });

  it('handles all attributes in any order', () => {
    const h = { 'set-cookie': ['SameSite=Lax; auth=x; Path=/; HttpOnly; Secure'] };
    const cookie = analyzeCookies(h).cookies[0];
    // name is the very first token before '='
    // (real cookie names don't start with SameSite, this tests robustness)
    assert.ok(typeof cookie.name === 'string');
    assert.equal(cookie.secure, true);
    assert.equal(cookie.httpOnly, true);
  });

  it('handles attribute keys in all-caps (SECURE, HTTPONLY)', () => {
    const h = { 'set-cookie': ['tok=x; SECURE; HTTPONLY; SAMESITE=LAX'] };
    const cookie = analyzeCookies(h).cookies[0];
    assert.equal(cookie.secure, true);
    assert.equal(cookie.httpOnly, true);
    assert.ok(cookie.sameSite != null);
  });
});
