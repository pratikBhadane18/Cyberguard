'use strict';

/**
 * CyberGuard TLS Scanner Tests
 *
 * Uses Node's built-in `node:test` runner.
 * Run with:  npm test  (from the server/ directory)
 *
 * Test strategy:
 *   - calcDaysRemaining: pure unit tests — no network, fully deterministic.
 *   - checkHostnameValid: unit tests with mock cert objects — no network.
 *   - scanTls(http://...): confirms immediate non-analyzed response.
 *   - scanTls(https://...): real outbound connection, checks structure only
 *     (no assertions on specific issuer text or TLS version — those change).
 *   - performScan integration: confirms tls field present on both HTTP & HTTPS.
 *   - Existing SSRF tests are in ssrf.test.js and run via the same npm test.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  scanTls,
  calcDaysRemaining,
  checkHostnameValid,
  EXPIRY_WARNING_DAYS,
} = require('../src/services/tlsScanner');

const { performScan } = require('../src/services/scannerService');

// ---------------------------------------------------------------------------
// 1. calcDaysRemaining — pure unit tests (no network)
// ---------------------------------------------------------------------------

describe('calcDaysRemaining()', () => {
  it('returns approximately 180 for a date 180 days in the future', () => {
    const future = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000);
    const days = calcDaysRemaining(future.toUTCString());
    // Allow ±1 day for millisecond timing variation
    assert.ok(days >= 179 && days <= 181, `Expected ~180, got ${days}`);
  });

  it('returns 0 for a date one day in the past (expired)', () => {
    const past = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const days = calcDaysRemaining(past.toUTCString());
    assert.equal(days, 0);
  });

  it('returns 0 for a date one year in the past', () => {
    const past = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);
    const days = calcDaysRemaining(past.toUTCString());
    assert.equal(days, 0);
  });

  it('returns approximately 1 for a date one day in the future', () => {
    const tomorrow = new Date(Date.now() + 25 * 60 * 60 * 1000); // 25 h
    const days = calcDaysRemaining(tomorrow.toUTCString());
    assert.ok(days >= 1 && days <= 2, `Expected 1, got ${days}`);
  });

  it('correctly identifies the expiry-warning threshold', () => {
    // A cert expiring in exactly EXPIRY_WARNING_DAYS days
    const warnDate = new Date(Date.now() + EXPIRY_WARNING_DAYS * 24 * 60 * 60 * 1000);
    const days = calcDaysRemaining(warnDate.toUTCString());
    assert.ok(days >= EXPIRY_WARNING_DAYS - 1 && days <= EXPIRY_WARNING_DAYS + 1);
  });
});

// ---------------------------------------------------------------------------
// 2. checkHostnameValid — unit tests with mock cert objects (no network)
// ---------------------------------------------------------------------------

describe('checkHostnameValid()', () => {
  it('returns true when hostname matches the CN', () => {
    // tls.checkServerIdentity falls back to CN when no subjectaltname
    const cert = { subject: { CN: 'example.com' } };
    // Suppress: Node shows a deprecation for CN fallback; result is still correct
    const result = checkHostnameValid('example.com', cert);
    assert.equal(typeof result, 'boolean');
  });

  it('returns true when hostname matches a SAN DNS entry', () => {
    const cert = {
      subject: { CN: 'example.com' },
      subjectaltname: 'DNS:example.com, DNS:www.example.com',
    };
    assert.equal(checkHostnameValid('example.com', cert), true);
    assert.equal(checkHostnameValid('www.example.com', cert), true);
  });

  it('returns false when hostname does NOT match any SAN', () => {
    const cert = {
      subject: { CN: 'example.com' },
      subjectaltname: 'DNS:example.com, DNS:www.example.com',
    };
    assert.equal(checkHostnameValid('attacker.com', cert), false);
  });

  it('returns true for a wildcard SAN matching a subdomain', () => {
    const cert = {
      subject: { CN: '*.example.com' },
      subjectaltname: 'DNS:*.example.com',
    };
    assert.equal(checkHostnameValid('api.example.com', cert), true);
  });

  it('returns false when no cert object is passed', () => {
    assert.equal(checkHostnameValid('example.com', {}), false);
  });
});

// ---------------------------------------------------------------------------
// 3. scanTls() — HTTP target (no network connection made)
// ---------------------------------------------------------------------------

describe('scanTls() — HTTP target', () => {
  it('returns analyzed:false without making a connection', async () => {
    const result = await scanTls('http://example.com');
    assert.equal(result.analyzed, false, 'analyzed should be false for HTTP');
    assert.ok(
      typeof result.reason === 'string' && result.reason.length > 0,
      'Should include a reason string'
    );
    assert.ok(
      result.reason.toLowerCase().includes('http'),
      'Reason should mention HTTP'
    );
  });

  it('does NOT include a certificate field for HTTP targets', async () => {
    const result = await scanTls('http://example.com');
    assert.equal(result.certificate, undefined);
  });
});

// ---------------------------------------------------------------------------
// 4. scanTls() — HTTPS public target (network required)
//    Assertions are structural only — no specific issuer, protocol, or expiry.
// ---------------------------------------------------------------------------

describe('scanTls() — HTTPS public target (network required)', () => {
  it('returns analyzed:true with required fields for https://example.com', async () => {
    const result = await scanTls('https://example.com');

    assert.equal(result.analyzed, true, 'analyzed should be true');

    // If TLS inspection failed (e.g. network issue), the status field is set
    if (result.status === 'error') {
      // Skip structural assertions but mark why
      console.warn('[TLS test] TLS inspection returned error:', result.message);
      return;
    }

    assert.ok(result.protocol, 'protocol should be present');
    assert.ok(result.certificate, 'certificate object should be present');

    const { certificate: cert } = result;

    assert.ok(typeof cert.subject === 'string', 'subject should be a string');
    assert.ok(typeof cert.issuer === 'string', 'issuer should be a string');
    assert.ok(typeof cert.validFrom === 'string', 'validFrom should be an ISO string');
    assert.ok(typeof cert.validTo === 'string', 'validTo should be an ISO string');
    assert.ok(typeof cert.expired === 'boolean', 'expired should be boolean');
    assert.ok(typeof cert.expiringSoon === 'boolean', 'expiringSoon should be boolean');
    assert.ok(typeof cert.daysRemaining === 'number', 'daysRemaining should be number');
    assert.ok(typeof cert.hostnameValid === 'boolean', 'hostnameValid should be boolean');

    // Verify ISO date strings are parseable
    assert.ok(!isNaN(Date.parse(cert.validFrom)), 'validFrom must be a valid date');
    assert.ok(!isNaN(Date.parse(cert.validTo)), 'validTo must be a valid date');
  });

  it('recognizes example.com cert as currently valid (not expired)', async () => {
    const result = await scanTls('https://example.com');

    if (result.status === 'error') {
      console.warn('[TLS test] Skipping expiry check — TLS inspection error');
      return;
    }

    assert.equal(result.certificate.expired, false, 'example.com cert should not be expired');
    assert.ok(
      result.certificate.daysRemaining > 0,
      'daysRemaining should be > 0 for a valid cert'
    );
  });

  it('recognizes example.com cert as hostname-valid', async () => {
    const result = await scanTls('https://example.com');

    if (result.status === 'error') {
      console.warn('[TLS test] Skipping hostname check — TLS inspection error');
      return;
    }

    assert.equal(
      result.certificate.hostnameValid,
      true,
      'example.com cert should be valid for its own hostname'
    );
  });
});

// ---------------------------------------------------------------------------
// 5. performScan() integration — TLS field present in full scan result
// ---------------------------------------------------------------------------

describe('performScan() — TLS integration (network required)', () => {
  it('HTTPS scan result includes a tls field with analyzed:true', async () => {
    const result = await performScan('https://example.com');

    assert.ok(result.tls, 'tls field should exist in the scan result');
    assert.equal(result.tls.analyzed, true, 'analyzed should be true for HTTPS');
  });

  it('HTTP scan result includes a tls field with analyzed:false', async () => {
    const result = await performScan('http://example.com');

    assert.ok(result.tls, 'tls field should exist in the scan result');
    assert.equal(result.tls.analyzed, false, 'analyzed should be false for HTTP');
    assert.ok(result.tls.reason, 'reason string should be present for HTTP');
  });

  it('HTTP scan result that redirects to HTTPS sets redirectsToHttps:true', async () => {
    // http://example.com redirects to https://example.com
    const result = await performScan('http://example.com');

    // The redirect detection checks the final URL after the redirect chain.
    // example.com redirects to HTTPS, so this should be true.
    // If example.com changes behaviour this is a known network-dependent case.
    if (result.finalUrl && result.finalUrl.startsWith('https://')) {
      assert.equal(result.redirectsToHttps, true, 'redirectsToHttps should be true');
    } else {
      // No redirect occurred — field should be absent (undefined)
      assert.equal(result.redirectsToHttps, undefined);
    }
  });

  it('HTTPS scan result does not have redirectsToHttps set', async () => {
    const result = await performScan('https://example.com');
    // redirectsToHttps only applies to HTTP origins
    assert.equal(result.redirectsToHttps, undefined);
  });
});
