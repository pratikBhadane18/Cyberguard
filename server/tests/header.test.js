'use strict';

/**
 * CyberGuard Header Scanner Tests
 *
 * All tests are deterministic — no external network is required.
 * We test individual analyzer functions with mock header objects.
 * The integration test (analyzeHeaders) also uses mock data.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  analyzeHeaders,
  analyzeHsts,
  analyzeCsp,
  analyzeXFrameOptions,
  analyzeXContentTypeOptions,
  analyzeReferrerPolicy,
  analyzePermissionsPolicy,
} = require('../src/services/headerScanner');

// ── Fixtures ─────────────────────────────────────────────────────────────────

const ALL_HEADERS_PRESENT = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy':   "default-src 'self'; script-src 'self'",
  'x-frame-options':           'DENY',
  'x-content-type-options':    'nosniff',
  'referrer-policy':           'strict-origin-when-cross-origin',
  'permissions-policy':        'camera=(), microphone=()',
};

const NO_HEADERS = {};

// ── 1. analyzeHeaders() — integration over mock objects ──────────────────────

describe('analyzeHeaders() — all six headers present', () => {
  it('returns analyzed:true', () => {
    const result = analyzeHeaders(ALL_HEADERS_PRESENT, true);
    assert.equal(result.analyzed, true);
  });

  it('returns exactly six findings', () => {
    const result = analyzeHeaders(ALL_HEADERS_PRESENT, true);
    assert.equal(result.findings.length, 6);
  });

  it('every finding has the required fields', () => {
    const result = analyzeHeaders(ALL_HEADERS_PRESENT, true);
    for (const f of result.findings) {
      assert.ok(typeof f.header === 'string',      `header must be string (got ${typeof f.header})`);
      assert.ok(typeof f.status === 'string',      `status must be string`);
      assert.ok(typeof f.severity === 'string',    `severity must be string`);
      assert.ok(typeof f.description === 'string', `description must be string`);
      // value may be null, string is optional for missing headers
    }
  });

  it('all present and well-configured → severity INFO only', () => {
    const result = analyzeHeaders(ALL_HEADERS_PRESENT, true);
    for (const f of result.findings) {
      assert.equal(f.severity, 'INFO', `Expected INFO for ${f.header}, got ${f.severity}`);
    }
  });
});

describe('analyzeHeaders() — no security headers present', () => {
  it('returns analyzed:true', () => {
    assert.equal(analyzeHeaders(NO_HEADERS, true).analyzed, true);
  });

  it('returns six findings', () => {
    assert.equal(analyzeHeaders(NO_HEADERS, true).findings.length, 6);
  });

  it('all findings have status missing or not_applicable', () => {
    const result = analyzeHeaders(NO_HEADERS, true);
    for (const f of result.findings) {
      assert.ok(
        ['missing', 'not_applicable'].includes(f.status),
        `Expected missing/not_applicable for ${f.header}, got ${f.status}`
      );
    }
  });

  it('no finding uses HIGH or CRITICAL severity', () => {
    const result = analyzeHeaders(NO_HEADERS, true);
    for (const f of result.findings) {
      assert.notEqual(f.severity, 'HIGH',     `${f.header} must not use HIGH`);
      assert.notEqual(f.severity, 'CRITICAL', `${f.header} must not use CRITICAL`);
    }
  });
});

// ── 2. Case-insensitive header names ─────────────────────────────────────────

describe('analyzeHeaders() — case-insensitive header lookup', () => {
  it('reads Strict-Transport-Security regardless of case', () => {
    const h = { 'STRICT-TRANSPORT-SECURITY': 'max-age=31536000' };
    const result = analyzeHeaders(h, true);
    const finding = result.findings.find((f) => f.header === 'Strict-Transport-Security');
    assert.equal(finding.status, 'present');
  });

  it('reads X-Content-Type-Options with mixed case', () => {
    const h = { 'X-Content-Type-Options': 'nosniff' };
    const result = analyzeHeaders(h, true);
    const finding = result.findings.find((f) => f.header === 'X-Content-Type-Options');
    assert.equal(finding.status, 'present');
  });

  it('reads x-frame-options with all lowercase', () => {
    const h = { 'x-frame-options': 'SAMEORIGIN' };
    const result = analyzeHeaders(h, true);
    const finding = result.findings.find((f) => f.header === 'X-Frame-Options');
    assert.equal(finding.status, 'present');
  });
});

// ── 3. HSTS ──────────────────────────────────────────────────────────────────

describe('analyzeHsts()', () => {
  it('returns present + INFO for max-age ≥ 1 year on HTTPS', () => {
    const r = analyzeHsts('max-age=31536000; includeSubDomains', true);
    assert.equal(r.status, 'present');
    assert.equal(r.severity, 'INFO');
  });

  it('returns present + INFO for max-age exactly = 31536000', () => {
    const r = analyzeHsts('max-age=31536000', true);
    assert.equal(r.status, 'present');
  });

  it('returns weak + LOW for max-age < 1 year on HTTPS', () => {
    const r = analyzeHsts('max-age=2592000', true); // 30 days
    assert.equal(r.status, 'weak');
    assert.equal(r.severity, 'LOW');
  });

  it('returns weak for max-age = 0 on HTTPS', () => {
    const r = analyzeHsts('max-age=0', true);
    assert.equal(r.status, 'weak');
  });

  it('returns invalid + LOW when max-age directive is absent', () => {
    const r = analyzeHsts('includeSubDomains', true);
    assert.equal(r.status, 'invalid');
    assert.equal(r.severity, 'LOW');
  });

  it('returns missing + MEDIUM when HSTS header absent on HTTPS target', () => {
    const r = analyzeHsts(null, true);
    assert.equal(r.status, 'missing');
    assert.equal(r.severity, 'MEDIUM');
  });

  it('returns not_applicable + INFO for HTTP target regardless of value', () => {
    const r = analyzeHsts(null, false);
    assert.equal(r.status, 'not_applicable');
    assert.equal(r.severity, 'INFO');
  });

  it('returns not_applicable even when HSTS header is present on HTTP response', () => {
    const r = analyzeHsts('max-age=31536000', false);
    assert.equal(r.status, 'not_applicable');
  });

  it('correctly parses max-age from value string', () => {
    const r = analyzeHsts('max-age=63072000', true); // 2 years
    assert.equal(r.status, 'present');
    assert.ok(r.description.includes('63072000'));
  });

  it('parses max-age case-insensitively (MAX-AGE)', () => {
    const r = analyzeHsts('MAX-AGE=31536000', true);
    assert.equal(r.status, 'present');
  });
});

// ── 4. CSP ───────────────────────────────────────────────────────────────────

describe('analyzeCsp()', () => {
  it('returns missing + MEDIUM when CSP is absent', () => {
    const r = analyzeCsp(null);
    assert.equal(r.status, 'missing');
    assert.equal(r.severity, 'MEDIUM');
  });

  it("returns weak + LOW when policy contains 'unsafe-inline'", () => {
    const r = analyzeCsp("default-src 'self'; script-src 'unsafe-inline'");
    assert.equal(r.status, 'weak');
    assert.equal(r.severity, 'LOW');
    assert.ok(r.description.includes("'unsafe-inline'"));
  });

  it("returns weak + LOW when policy contains 'unsafe-eval'", () => {
    const r = analyzeCsp("default-src 'self'; script-src 'unsafe-eval'");
    assert.equal(r.status, 'weak');
    assert.ok(r.description.includes("'unsafe-eval'"));
  });

  it('returns weak + LOW for standalone wildcard source (*)', () => {
    const r = analyzeCsp("default-src *");
    assert.equal(r.status, 'weak');
    assert.ok(r.description.includes('wildcard'));
  });

  it('returns weak for wildcard alongside other sources', () => {
    const r = analyzeCsp("script-src 'self' *");
    assert.equal(r.status, 'weak');
  });

  it('does NOT flag *.example.com as a wildcard source', () => {
    const r = analyzeCsp("img-src *.example.com");
    assert.equal(r.status, 'present');
  });

  it('returns present + INFO for a reasonable policy', () => {
    const r = analyzeCsp("default-src 'self'; img-src 'self' data:; style-src 'self'");
    assert.equal(r.status, 'present');
    assert.equal(r.severity, 'INFO');
  });

  it('returns present + INFO for a minimal self-only policy', () => {
    const r = analyzeCsp("default-src 'self'");
    assert.equal(r.status, 'present');
  });
});

// ── 5. X-Frame-Options ───────────────────────────────────────────────────────

describe('analyzeXFrameOptions()', () => {
  it('returns present + INFO for DENY', () => {
    const r = analyzeXFrameOptions('DENY', null);
    assert.equal(r.status, 'present');
    assert.equal(r.severity, 'INFO');
  });

  it('returns present + INFO for SAMEORIGIN', () => {
    const r = analyzeXFrameOptions('SAMEORIGIN', null);
    assert.equal(r.status, 'present');
  });

  it('accepts lowercase deny (case-insensitive)', () => {
    const r = analyzeXFrameOptions('deny', null);
    assert.equal(r.status, 'present');
  });

  it('accepts mixed-case SameOrigin', () => {
    const r = analyzeXFrameOptions('SameOrigin', null);
    assert.equal(r.status, 'present');
  });

  it('returns invalid + LOW for an unrecognised value', () => {
    const r = analyzeXFrameOptions('ALLOWALL', null);
    assert.equal(r.status, 'invalid');
    assert.equal(r.severity, 'LOW');
  });

  it('returns missing + LOW when header absent and no CSP frame-ancestors', () => {
    const r = analyzeXFrameOptions(null, null);
    assert.equal(r.status, 'missing');
    assert.equal(r.severity, 'LOW');
  });

  it('returns missing + LOW when absent and CSP has no frame-ancestors', () => {
    const r = analyzeXFrameOptions(null, "default-src 'self'");
    assert.equal(r.status, 'missing');
  });

  it('returns not_applicable + INFO when CSP has frame-ancestors', () => {
    const r = analyzeXFrameOptions(null, "default-src 'self'; frame-ancestors 'none'");
    assert.equal(r.status, 'not_applicable');
    assert.equal(r.severity, 'INFO');
  });

  it('prefers not_applicable when both XFO absent and frame-ancestors present', () => {
    const r = analyzeXFrameOptions(null, "frame-ancestors 'self'");
    assert.equal(r.status, 'not_applicable');
  });
});

// ── 6. X-Content-Type-Options ────────────────────────────────────────────────

describe('analyzeXContentTypeOptions()', () => {
  it('returns present + INFO for nosniff', () => {
    const r = analyzeXContentTypeOptions('nosniff');
    assert.equal(r.status, 'present');
    assert.equal(r.severity, 'INFO');
  });

  it('accepts NOSNIFF uppercase (case-insensitive)', () => {
    const r = analyzeXContentTypeOptions('NOSNIFF');
    assert.equal(r.status, 'present');
  });

  it('accepts nosniff with surrounding whitespace', () => {
    const r = analyzeXContentTypeOptions('  nosniff  ');
    assert.equal(r.status, 'present');
  });

  it('returns invalid + LOW for an unrecognised value', () => {
    const r = analyzeXContentTypeOptions('sniff');
    assert.equal(r.status, 'invalid');
    assert.equal(r.severity, 'LOW');
  });

  it('returns invalid for empty string', () => {
    const r = analyzeXContentTypeOptions('');
    // Empty string is not "nosniff", so invalid
    assert.ok(['invalid', 'missing'].includes(r.status));
  });

  it('returns missing + LOW when header is absent', () => {
    const r = analyzeXContentTypeOptions(null);
    assert.equal(r.status, 'missing');
    assert.equal(r.severity, 'LOW');
  });
});

// ── 7. Referrer-Policy ───────────────────────────────────────────────────────

describe('analyzeReferrerPolicy()', () => {
  const validValues = [
    'no-referrer',
    'no-referrer-when-downgrade',
    'origin',
    'origin-when-cross-origin',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'unsafe-url',
  ];

  for (const v of validValues) {
    it(`returns present + INFO for "${v}"`, () => {
      const r = analyzeReferrerPolicy(v);
      assert.equal(r.status, 'present');
      assert.equal(r.severity, 'INFO');
    });
  }

  it('returns missing + LOW when header is absent', () => {
    const r = analyzeReferrerPolicy(null);
    assert.equal(r.status, 'missing');
    assert.equal(r.severity, 'LOW');
  });

  it('returns invalid + LOW for an unrecognised value', () => {
    const r = analyzeReferrerPolicy('send-everything');
    assert.equal(r.status, 'invalid');
    assert.equal(r.severity, 'LOW');
  });

  it('accepts comma-separated multi-value policy (fallback chain)', () => {
    const r = analyzeReferrerPolicy('no-referrer, strict-origin-when-cross-origin');
    assert.equal(r.status, 'present');
  });

  it('returns invalid when one token in multi-value is unrecognised', () => {
    const r = analyzeReferrerPolicy('no-referrer, unknown-policy');
    assert.equal(r.status, 'invalid');
  });
});

// ── 8. Permissions-Policy ────────────────────────────────────────────────────

describe('analyzePermissionsPolicy()', () => {
  it('returns present + INFO when header is set', () => {
    const r = analyzePermissionsPolicy('camera=(), microphone=()');
    assert.equal(r.status, 'present');
    assert.equal(r.severity, 'INFO');
  });

  it('returns missing + INFO (not LOW) when header is absent', () => {
    const r = analyzePermissionsPolicy(null);
    assert.equal(r.status, 'missing');
    assert.equal(r.severity, 'INFO');
  });

  it('preserves the raw value in the finding', () => {
    const val = 'geolocation=(), payment=()';
    const r = analyzePermissionsPolicy(val);
    assert.equal(r.value, val);
  });
});
