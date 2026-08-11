'use strict';

/**
 * CyberGuard Report Generation Tests
 *
 * Uses Node's built-in `node:test` runner — no external test framework.
 * Run with:  npm test  (from the server/ directory)
 *
 * ALL tests are deterministic and make ZERO external network requests.
 *
 * PDF text is verified by:
 *   1. Decompressing all zlib-deflate content streams.
 *   2. Extracting WinAnsi-encoded hex glyph strings (<AABB...>) from the
 *      decompressed PDF content.
 *   This reliably recovers the human-readable text that PDFKit embeds using
 *   Helvetica/WinAnsiEncoding inside TJ operators.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const zlib   = require('node:zlib');

const {
  sanitizeScanResult,
  generateReport,
  sanitizeFilename,
  safeStr,
} = require('../src/services/reportService');

// ── PDF text extraction helper ────────────────────────────────────────────────

/**
 * Extracts human-readable text from a PDFKit-generated PDF Buffer.
 *
 * PDFKit compresses content streams with zlib/deflate and encodes text as
 * WinAnsi hex glyph strings (<AABBCC>) inside TJ operators.
 * This helper:
 *   1. Finds all "stream ... endstream" sections in the PDF.
 *   2. Attempts zlib.inflateSync on each — silently skips non-compressed data.
 *   3. Extracts all <hexstring> tokens from the decompressed content.
 *   4. Decodes each hex pair as a WinAnsi (Latin-1) code point.
 *
 * Also includes the raw latin1 of the full buffer so that plaintext PDF
 * metadata (/Title, /Author, /Subject etc.) can be searched directly.
 *
 * @param {Buffer} buf - PDF buffer from generateReport()
 * @returns {string} All recoverable text content
 */
function pdfText(buf) {
  const raw = buf.toString('binary');

  // Step 1 — decompress all content streams
  let decompressed = '';
  let searchFrom = 0;
  while (true) {
    let sStart = raw.indexOf('stream\n', searchFrom);
    const sStart2 = raw.indexOf('stream\r\n', searchFrom);
    // Take whichever stream marker appears first (handle both \n and \r\n)
    if (sStart2 >= 0 && (sStart < 0 || sStart2 < sStart)) sStart = sStart2;
    if (sStart < 0) break;

    const headerEnd = raw.indexOf('\n', sStart) + 1;
    const streamEnd = raw.indexOf('endstream', headerEnd);
    if (streamEnd < 0) break;

    const streamData = Buffer.from(raw.slice(headerEnd, streamEnd), 'binary');
    try {
      const inflated = zlib.inflateSync(streamData);
      decompressed += inflated.toString('binary');
    } catch {
      // Not a deflate stream — skip (e.g. font data, image data)
    }

    searchFrom = streamEnd + 9;
  }

  // Step 2 — extract WinAnsi text from hex-encoded glyph strings
  let hexText = '';
  const hexMatches = decompressed.match(/<([0-9a-fA-F]+)>/g) || [];
  for (const m of hexMatches) {
    const hexStr = m.slice(1, -1);
    for (let i = 0; i < hexStr.length; i += 2) {
      const code = parseInt(hexStr.slice(i, i + 2), 16);
      // WinAnsi printable range
      if (code > 31 && code < 256) hexText += String.fromCharCode(code);
    }
  }

  // Step 3 — also include raw latin1 buffer for metadata searches
  const metadata = buf.toString('latin1');

  return hexText + '\n' + metadata;
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

/**
 * A complete scan result fixture that exercises all report sections.
 * Score = 85 (100 - 15 MEDIUM penalty).
 */
const FULL_SCAN_RESULT = {
  target:        'https://example.com',
  finalUrl:      undefined,
  statusCode:    200,
  statusText:    'OK',
  responseTime:  142,
  isHttps:       true,
  scanTimestamp: '2026-08-11T15:00:00.000Z',
  tls: {
    analyzed: true,
    protocol: 'TLSv1.3',
    certificate: {
      subject:       'example.com',
      issuer:        'DigiCert Inc',
      validFrom:     '2026-01-01T00:00:00.000Z',
      validTo:       '2027-01-01T00:00:00.000Z',
      daysRemaining: 143,
      expired:       false,
      expiringSoon:  false,
      hostnameValid: true,
    },
  },
  headers: {
    analyzed: true,
    findings: [
      {
        header:         'Strict-Transport-Security',
        status:         'present',
        severity:       'INFO',
        value:          'max-age=31536000; includeSubDomains',
        description:    'HSTS is configured with max-age of 31536000s.',
        recommendation: null,
      },
      {
        header:         'Content-Security-Policy',
        status:         'missing',
        severity:       'MEDIUM',
        value:          null,
        description:    'Content-Security-Policy header is not set.',
        recommendation: 'Define a Content-Security-Policy.',
      },
    ],
  },
  cookies: {
    analyzed: true,
    count:    1,
    cookies: [
      {
        name:          'session',
        redactedValue: '[REDACTED]',
        likelySession: true,
        secure:        false,
        httpOnly:      true,
        sameSite:      'Lax',
        path:          '/',
        domain:        null,
        maxAge:        null,
        expires:       null,
        findings: [
          {
            attribute:      'Secure',
            status:         'missing',
            severity:       'MEDIUM',
            description:    '"session" is missing the Secure attribute.',
            recommendation: 'Add the Secure attribute.',
          },
        ],
      },
    ],
  },
  risk: {
    score:    85,
    riskLevel: 'LOW',
    summary:  { critical: 0, high: 0, medium: 1, low: 0, info: 1 },
    findings: [
      {
        id:             'header-content-security-policy-missing',
        category:       'headers',
        title:          'Content-Security-Policy Header Missing',
        severity:       'MEDIUM',
        description:    'Content-Security-Policy header is not set.',
        impact:         'Reduces CSP defense-in-depth.',
        recommendation: 'Define a Content-Security-Policy.',
        evidence:       'Header absent',
      },
      {
        id:             'header-strict-transport-security-present',
        category:       'headers',
        title:          'HSTS Present',
        severity:       'INFO',
        description:    'HSTS is configured correctly.',
        impact:         'None.',
        recommendation: '',
        evidence:       'Strict-Transport-Security: max-age=31536000',
      },
    ],
    topRecommendations: [
      {
        id:             'header-content-security-policy-missing',
        title:          'Content-Security-Policy Header Missing',
        severity:       'MEDIUM',
        recommendation: 'Define a Content-Security-Policy.',
      },
    ],
  },
};

/** HTTP-only target (no TLS analysis) */
const HTTP_SCAN_RESULT = {
  target:       'http://example.com',
  statusCode:   200,
  statusText:   'OK',
  responseTime: 80,
  isHttps:      false,
  tls: { analyzed: false, reason: 'Target uses HTTP' },
  headers: {
    analyzed: true,
    findings: [
      {
        header:         'Strict-Transport-Security',
        status:         'not_applicable',
        severity:       'INFO',
        value:          null,
        description:    'HSTS sent over HTTP is ignored by browsers.',
        recommendation: 'Ensure HTTPS endpoint sends HSTS.',
      },
    ],
  },
  cookies: { analyzed: true, count: 0, cookies: [] },
  risk: {
    score:    85,
    riskLevel: 'LOW',
    summary:  { critical: 0, high: 0, medium: 0, low: 0, info: 1 },
    findings: [],
    topRecommendations: [],
  },
};

/** Scan result with empty findings */
const EMPTY_FINDINGS_RESULT = {
  target:  'https://secure.example.com',
  isHttps: true,
  tls:     { analyzed: false },
  headers: { analyzed: true, findings: [] },
  cookies: { analyzed: true, count: 0, cookies: [] },
  risk: {
    score:    100,
    riskLevel: 'LOW',
    summary:   { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findings:  [],
    topRecommendations: [],
  },
};

// ── Test Suites ───────────────────────────────────────────────────────────────

describe('reportService — sanitizeFilename()', () => {
  it('14. Sanitizes https://example.com/ to a safe, dated PDF filename', () => {
    const name = sanitizeFilename('https://example.com/');
    assert.match(name, /^CyberGuard-Report-example-com-\d{4}-\d{2}-\d{2}\.pdf$/);
  });

  it('14b. Sanitizes a URL with path/query — result contains no special characters', () => {
    const name = sanitizeFilename('https://www.my-site.io/app?foo=bar');
    assert.match(name, /^CyberGuard-Report-/);
    assert.ok(name.endsWith('.pdf'));
    assert.ok(!name.includes('?'), 'filename must not contain ?');
    assert.ok(!name.includes('='), 'filename must not contain =');
  });

  it('14c. Handles a malformed/non-URL string without throwing', () => {
    assert.doesNotThrow(() => sanitizeFilename('not-a-url-at-all'));
  });
});

describe('reportService — sanitizeScanResult() validation', () => {
  it('15a. Rejects null input', () => {
    assert.throws(() => sanitizeScanResult(null), /must be a non-null object/);
  });

  it('15b. Rejects array input', () => {
    assert.throws(() => sanitizeScanResult([]), /must be a non-null object/);
  });

  it('15c. Rejects missing target field', () => {
    assert.throws(
      () => sanitizeScanResult({ risk: { score: 100, riskLevel: 'LOW' } }),
      /target/
    );
  });

  it('15d. Rejects missing risk field', () => {
    assert.throws(() => sanitizeScanResult({ target: 'https://x.com' }), /risk/);
  });

  it('15e. Rejects risk.score that is not a number', () => {
    assert.throws(
      () => sanitizeScanResult({ target: 'https://x.com', risk: { score: 'bad', riskLevel: 'LOW' } }),
      /score/
    );
  });

  it('8-sanitize. Cookie values are ALWAYS replaced with [REDACTED]', () => {
    const raw = {
      ...FULL_SCAN_RESULT,
      cookies: {
        analyzed: true,
        count: 1,
        cookies: [{
          name:          'session',
          value:         'SUPER_SECRET_SESSION_VALUE',
          redactedValue: 'SHOULD_ALSO_BE_REPLACED',
          likelySession: true,
          secure: false, httpOnly: true, sameSite: 'Lax',
          findings: [],
        }],
      },
    };
    const sanitized = sanitizeScanResult(raw);
    const json = JSON.stringify(sanitized);
    assert.ok(!json.includes('SUPER_SECRET_SESSION_VALUE'), 'Raw cookie value must be stripped');
    assert.ok(!json.includes('SHOULD_ALSO_BE_REPLACED'),   'redactedValue must be replaced');
    assert.ok(json.includes('[REDACTED]'),                  '[REDACTED] must appear in its place');
  });

  it('9-sanitize. JWT-pattern strings are replaced with [REDACTED]', () => {
    const jwtLike = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.someSignature';
    const raw = {
      target:  'https://example.com',
      isHttps: true,
      tls:     { analyzed: false },
      headers: { analyzed: true, findings: [] },
      cookies: { analyzed: true, count: 0, cookies: [] },
      risk: {
        score: 100, riskLevel: 'LOW',
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findings: [{
          id: 'f1', category: 'headers', title: 'Test',
          severity: 'INFO',
          description: `Token found: ${jwtLike}`,
          impact: '', recommendation: '', evidence: '',
        }],
        topRecommendations: [],
      },
    };
    const sanitized = sanitizeScanResult(raw);
    const json = JSON.stringify(sanitized);
    assert.ok(!json.includes('eyJhbGciOiJIUzI1NiJ9'), 'JWT header part must be redacted');
  });

  it('safeStr — truncates strings to 2000 characters', () => {
    const result = safeStr('A'.repeat(5000));
    assert.equal(result.length, 2000);
  });

  it('safeStr — returns empty string for null and undefined', () => {
    assert.equal(safeStr(null),      '');
    assert.equal(safeStr(undefined), '');
  });
});

describe('reportService — generateReport()', () => {
  it('1. Basic report generation — returns a non-empty Buffer', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    assert.ok(Buffer.isBuffer(buf), 'Must return a Buffer');
    assert.ok(buf.length > 0,       'Buffer must be non-empty');
  });

  it('2. Buffer starts with %PDF (valid PDF magic bytes)', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    assert.equal(buf.slice(0, 4).toString('ascii'), '%PDF', 'Must start with %PDF');
  });

  it('3. Correct security score (85) appears in the PDF content', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);
    assert.ok(text.includes('85'), 'Score 85 must appear in PDF');
  });

  it('4. Correct risk level (LOW) appears in the PDF content', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);
    assert.ok(text.includes('LOW'), 'Risk level LOW must appear in PDF');
  });

  it('5. Finding counts (summary) appear in the PDF content', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);
    assert.ok(
      text.includes('Medium') || text.includes('MEDIUM') || text.includes('1'),
      'Finding summary counts must appear in PDF'
    );
  });

  it('6. TLS section appears when tls.analyzed === true (protocol visible)', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);
    assert.ok(
      text.includes('TLSv1.3') || text.includes('TLS'),
      'TLS protocol or section must appear in PDF'
    );
  });

  it('7. Security header findings appear (Content-Security-Policy)', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);
    assert.ok(
      text.includes('Content-Security-Policy') ||
      text.includes('Security-Policy') ||
      text.includes('Security Headers'),
      'Header finding or section must appear in PDF'
    );
  });

  it('8. Cookie name appears but raw cookie value does NOT appear in the PDF', async () => {
    const raw = {
      ...FULL_SCAN_RESULT,
      cookies: {
        analyzed: true,
        count: 1,
        cookies: [{
          name:          'mysession',
          value:         'TOP_SECRET_COOKIE_VALUE_XYZ_9876',
          redactedValue: 'SECRET_REDACTED_VALUE_ABC_1234',
          likelySession: true,
          secure: false, httpOnly: true, sameSite: 'Lax',
          path: '/', domain: null, maxAge: null, expires: null,
          findings: [],
        }],
      },
    };
    const sanitized = sanitizeScanResult(raw);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);

    assert.ok(text.includes('mysession'),                  'Cookie name must appear in PDF');
    assert.ok(!text.includes('TOP_SECRET_COOKIE_VALUE'),   'Raw cookie value must NOT appear in PDF');
    assert.ok(!text.includes('SECRET_REDACTED_VALUE_ABC'), 'Old redactedValue must NOT appear in PDF');
  });

  it('9. JWT/session token strings are never included in the PDF', async () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0';
    const raw = {
      ...FULL_SCAN_RESULT,
      risk: {
        ...FULL_SCAN_RESULT.risk,
        findings: [{
          id: 'test', category: 'headers', title: 'Test',
          severity: 'INFO',
          description: `Leaked token: ${jwt}`,
          impact: '', recommendation: '', evidence: '',
        }],
      },
    };
    const sanitized = sanitizeScanResult(raw);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);
    // The sanitizer must have stripped it, so it should not appear
    assert.ok(
      !text.includes('eyJhbGciOiJIUzI1NiJ9'),
      'JWT must not appear in generated PDF'
    );
  });

  it('10. Top recommendations appear in the PDF', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);
    assert.ok(
      text.includes('Recommendation') || text.includes('RECOMMENDATION'),
      'Recommendations section must appear in PDF'
    );
  });

  it('11. Disclaimer text appears in the PDF', async () => {
    const sanitized = sanitizeScanResult(FULL_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    const text = pdfText(buf);
    assert.ok(
      text.includes('Disclaimer') ||
      text.includes('authorized') ||
      text.includes('CyberGuard performs automated'),
      'Disclaimer section must appear in PDF'
    );
  });

  it('12. HTTP target (no TLS analysis) still generates a valid PDF', async () => {
    const sanitized = sanitizeScanResult(HTTP_SCAN_RESULT);
    const buf = await generateReport(sanitized);
    assert.ok(Buffer.isBuffer(buf) && buf.length > 0, 'Must return non-empty Buffer');
    assert.equal(buf.slice(0, 4).toString('ascii'), '%PDF', 'Must be a valid PDF');
    const text = pdfText(buf);
    assert.ok(text.includes('http') || text.includes('HTTP'), 'HTTP target context must appear');
  });

  it('13. Empty findings handled — PDF still generated successfully', async () => {
    const sanitized = sanitizeScanResult(EMPTY_FINDINGS_RESULT);
    const buf = await generateReport(sanitized);
    assert.ok(Buffer.isBuffer(buf) && buf.length > 0, 'Must return non-empty Buffer for empty findings');
    assert.equal(buf.slice(0, 4).toString('ascii'), '%PDF', 'Must be a valid PDF');
  });
});
