'use strict';

/**
 * CyberGuard Information Disclosure / Technology Exposure Tests
 *
 * Uses Node's built-in `node:test` runner — no external test framework needed.
 * Run with:  npm test  (from the server/ directory)
 *
 * ALL tests are deterministic and make ZERO external network requests.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { analyzeDisclosure } = require('../src/services/disclosureScanner');
const { normalizeFindings, analyzeRisk } = require('../src/services/riskAnalyzer');
const { sanitizeScanResult, generateReport } = require('../src/services/reportService');

describe('analyzeDisclosure() — Header Technology Disclosure Analysis', () => {
  it('1. Returns zero findings when no disclosure headers are present', () => {
    const res = analyzeDisclosure({ 'content-type': 'text/html', 'cache-control': 'no-cache' });
    assert.equal(res.analyzed, true);
    assert.equal(res.count, 0);
    assert.deepEqual(res.findings, []);
  });

  it('2. Detects Server header without version', () => {
    const res = analyzeDisclosure({ server: 'nginx' });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'server-technology-disclosure');
    assert.equal(res.findings[0].severity, 'LOW');
    assert.ok(res.findings[0].description.includes('nginx'));
  });

  it('3. Detects Server header with explicit version details', () => {
    const res = analyzeDisclosure({ server: 'nginx/1.24.0 (Ubuntu)' });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'server-technology-disclosure');
    assert.equal(res.findings[0].severity, 'LOW');
    assert.ok(res.findings[0].description.includes('version information'));
    assert.ok(res.findings[0].evidence.includes('nginx/1.24.0'));
  });

  it('4. Detects X-Powered-By header', () => {
    const res = analyzeDisclosure({ 'x-powered-by': 'Express' });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'powered-by-technology-disclosure');
    assert.equal(res.findings[0].title, 'Application Technology Information Disclosed');
    assert.equal(res.findings[0].severity, 'LOW');
  });

  it('5. Detects X-AspNet-Version header', () => {
    const res = analyzeDisclosure({ 'x-aspnet-version': '4.0.30319' });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'aspnet-version-disclosure');
    assert.equal(res.findings[0].severity, 'LOW');
    assert.ok(res.findings[0].evidence.includes('4.0.30319'));
  });

  it('6. Detects X-AspNetMvc-Version header', () => {
    const res = analyzeDisclosure({ 'x-aspnetmvc-version': '5.2' });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'aspnetmvc-version-disclosure');
    assert.equal(res.findings[0].severity, 'LOW');
    assert.ok(res.findings[0].evidence.includes('5.2'));
  });

  it('7. Detects X-Generator header', () => {
    const res = analyzeDisclosure({ 'x-generator': 'WordPress 6.4.2' });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'generator-disclosure');
    assert.equal(res.findings[0].severity, 'LOW');
    assert.ok(res.findings[0].evidence.includes('WordPress 6.4.2'));
  });

  it('8. Detects Via header', () => {
    const res = analyzeDisclosure({ via: '1.1 varnish (Varnish/6.0)' });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'via-disclosure');
    assert.equal(res.findings[0].severity, 'LOW');
    assert.ok(res.findings[0].evidence.includes('varnish'));
  });

  it('9. Detects X-Drupal-Cache header', () => {
    const res = analyzeDisclosure({ 'x-drupal-cache': 'HIT' });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'drupal-cache-disclosure');
    assert.equal(res.findings[0].severity, 'LOW');
    assert.ok(res.findings[0].evidence.includes('HIT'));
  });

  it('10. Handles mixed-case header names case-insensitively', () => {
    const res = analyzeDisclosure({
      'Server': 'Apache/2.4.52',
      'X-Powered-BY': 'PHP/8.1.2',
      'X-GENERATOR': 'Joomla 4.0',
    });
    assert.equal(res.count, 3);
    const ids = res.findings.map((f) => f.id);
    assert.ok(ids.includes('server-technology-disclosure'));
    assert.ok(ids.includes('powered-by-technology-disclosure'));
    assert.ok(ids.includes('generator-disclosure'));
  });

  it('11. Keeps each finding visible when multiple technology headers are present', () => {
    const res = analyzeDisclosure({
      server: 'Kestrel',
      'x-powered-by': 'ASP.NET',
      'x-aspnet-version': '4.0.30319',
      'x-aspnetmvc-version': '5.0',
    });
    assert.equal(res.count, 4);
    assert.equal(new Set(res.findings.map((f) => f.id)).size, 4);
  });

  it('12. Safely truncates unusually long header values in evidence', () => {
    const longValue = 'A'.repeat(500);
    const res = analyzeDisclosure({ server: longValue });
    assert.equal(res.count, 1);
    assert.ok(res.findings[0].value.length <= 153); // 150 + '...'
    assert.ok(res.findings[0].value.endsWith('...'));
  });

  it('13. Finding IDs are deterministic and stable across calls', () => {
    const res1 = analyzeDisclosure({ server: 'nginx' });
    const res2 = analyzeDisclosure({ server: 'nginx' });
    assert.equal(res1.findings[0].id, 'server-technology-disclosure');
    assert.equal(res2.findings[0].id, 'server-technology-disclosure');
    assert.equal(res1.findings[0].id, res2.findings[0].id);
  });

  it('14. All disclosure findings are strictly assigned LOW severity', () => {
    const res = analyzeDisclosure({
      server: 'Apache/2.4.50 (Unix) OpenSSL/1.1.1d mod_wsgi/4.6.8 Python/3.8',
      'x-powered-by': 'Express',
      'x-aspnet-version': '2.0.50727',
      'x-generator': 'Drupal 7',
      via: '1.1 squid',
      'x-drupal-cache': 'MISS',
    });
    for (const f of res.findings) {
      assert.equal(f.severity, 'LOW', `Finding ${f.id} must be LOW severity`);
    }
  });

  it('15. Executes purely in-memory with zero network requests', () => {
    // Calling analyzeDisclosure synchronously must complete instantly without network
    const startTime = Date.now();
    const res = analyzeDisclosure({ server: 'nginx', 'x-powered-by': 'PHP' });
    const duration = Date.now() - startTime;
    assert.equal(res.count, 2);
    assert.ok(duration < 50, 'Must execute instantly without async or network activity');
  });

  it('16. Ignores sensitive-looking unrelated headers like Authorization or Set-Cookie', () => {
    const res = analyzeDisclosure({
      authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.secret',
      'set-cookie': 'session=secret123; Secure; HttpOnly',
      'x-custom-auth': 'token-xyz',
      server: 'Apache',
    });
    assert.equal(res.count, 1);
    assert.equal(res.findings[0].id, 'server-technology-disclosure');
    const json = JSON.stringify(res.findings);
    assert.ok(!json.includes('Bearer'));
    assert.ok(!json.includes('secret123'));
  });

  it('17. Integrates cleanly with scannerService partialResult structure', () => {
    const disclosure = analyzeDisclosure({ server: 'IIS/10.0', 'x-powered-by': 'ASP.NET' });
    const partialResult = {
      target: 'https://example.com',
      isHttps: true,
      headers: { analyzed: true, findings: [] },
      cookies: { analyzed: true, count: 0, cookies: [] },
      disclosure,
    };
    assert.equal(partialResult.disclosure.analyzed, true);
    assert.equal(partialResult.disclosure.count, 2);
  });

  it('18. Integrates with riskAnalyzer without excessive penalties', () => {
    const disclosure = analyzeDisclosure({ server: 'nginx', 'x-powered-by': 'Express' });
    const partialResult = {
      target: 'https://example.com',
      isHttps: true,
      headers: { analyzed: true, findings: [] },
      cookies: { analyzed: true, count: 0, cookies: [] },
      disclosure,
    };
    const findings = normalizeFindings(partialResult);
    const risk = analyzeRisk(findings);
    // Two LOW findings -> penalty = 5 + 5 = 10 -> score = 90 (LOW risk)
    assert.equal(risk.score, 90);
    assert.equal(risk.riskLevel, 'LOW');
    assert.equal(risk.summary.low, 2);
  });

  it('19. Integrates with PDF report generation service', async () => {
    const disclosure = analyzeDisclosure({ server: 'nginx/1.24.0', 'x-powered-by': 'Express' });
    const scanResult = {
      target: 'https://example.com',
      isHttps: true,
      tls: { analyzed: false },
      headers: { analyzed: true, findings: [] },
      cookies: { analyzed: true, count: 0, cookies: [] },
      disclosure,
      risk: {
        score: 90,
        riskLevel: 'LOW',
        summary: { critical: 0, high: 0, medium: 0, low: 2, info: 0 },
        findings: normalizeFindings({ target: 'https://example.com', isHttps: true, disclosure }),
        topRecommendations: [],
      },
    };
    const sanitized = sanitizeScanResult(scanResult);
    assert.equal(sanitized.disclosure.analyzed, true);
    assert.equal(sanitized.disclosure.findings.length, 2);

    const pdfBuffer = await generateReport(sanitized);
    assert.ok(Buffer.isBuffer(pdfBuffer));
    assert.equal(pdfBuffer.slice(0, 4).toString('ascii'), '%PDF');
  });

  it('20. Ensures no sensitive values appear in normalized disclosure findings', () => {
    const res = analyzeDisclosure({
      server: 'nginx/1.20.1',
      'x-powered-by': 'Express',
    });
    const normalized = normalizeFindings({
      target: 'https://example.com',
      isHttps: true,
      disclosure: res,
    });
    const serialized = JSON.stringify(normalized);
    assert.ok(!serialized.includes('authorization'));
    assert.ok(!serialized.includes('cookie'));
    assert.ok(!serialized.includes('password'));
    assert.ok(serialized.includes('information-disclosure'));
  });
});
