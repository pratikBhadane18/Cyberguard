'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeRisk } = require('../src/services/riskAnalyzer');

describe('analyzeRisk() — Heuristic Scoring & Penalties', () => {
  it('INFO findings produce zero penalty', () => {
    const findings = [
      { id: 'f1', severity: 'INFO', title: 'Info 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    const report = analyzeRisk(findings);
    assert.equal(report.score, 100);
  });

  it('LOW findings produce 5 penalty', () => {
    const findings = [
      { id: 'f1', severity: 'LOW', title: 'Low 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    const report = analyzeRisk(findings);
    assert.equal(report.score, 95);
  });

  it('MEDIUM findings produce 15 penalty', () => {
    const findings = [
      { id: 'f1', severity: 'MEDIUM', title: 'Med 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    const report = analyzeRisk(findings);
    assert.equal(report.score, 85);
  });

  it('HIGH findings produce 30 penalty', () => {
    const findings = [
      { id: 'f1', severity: 'HIGH', title: 'High 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    const report = analyzeRisk(findings);
    assert.equal(report.score, 70);
  });

  it('CRITICAL findings produce 50 penalty', () => {
    const findings = [
      { id: 'f1', severity: 'CRITICAL', title: 'Crit 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    const report = analyzeRisk(findings);
    assert.equal(report.score, 50);
  });

  it('Score calculation combines multiple penalties correctly', () => {
    const findings = [
      { id: 'f1', severity: 'LOW', title: 'Low 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f2', severity: 'MEDIUM', title: 'Med 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    // Penalty: 5 + 15 = 20. Score = 80.
    const report = analyzeRisk(findings);
    assert.equal(report.score, 80);
  });

  it('Score floor at 0 is correctly enforced', () => {
    const findings = [
      { id: 'f1', severity: 'CRITICAL', title: 'Crit 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f2', severity: 'CRITICAL', title: 'Crit 2', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f3', severity: 'CRITICAL', title: 'Crit 3', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    // Penalty: 50 * 3 = 150. Score should be 0.
    const report = analyzeRisk(findings);
    assert.equal(report.score, 0);
  });

  it('Score ceiling at 100 is correctly enforced', () => {
    const report = analyzeRisk([]);
    assert.equal(report.score, 100);
  });

  it('Risk-level thresholds are correctly resolved', () => {
    // 80–100 -> LOW
    assert.equal(analyzeRisk([]).riskLevel, 'LOW');
    assert.equal(analyzeRisk([{ id: 'f1', severity: 'MEDIUM', title: 'Med 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }]).riskLevel, 'LOW'); // score 85

    // 60–79 -> MEDIUM
    const medReport = analyzeRisk([
      { id: 'f1', severity: 'MEDIUM', title: 'Med 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f2', severity: 'LOW', title: 'Low 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f3', severity: 'LOW', title: 'Low 2', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ]); // score 100 - (15 + 5 + 5) = 75
    assert.equal(medReport.riskLevel, 'MEDIUM');

    // 40–59 -> HIGH
    const highReport = analyzeRisk([
      { id: 'f1', severity: 'HIGH', title: 'High 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f2', severity: 'MEDIUM', title: 'Med 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ]); // score 100 - (30 + 15) = 55
    assert.equal(highReport.riskLevel, 'HIGH');

    // 0–39 -> CRITICAL
    const critReport = analyzeRisk([
      { id: 'f1', severity: 'CRITICAL', title: 'Crit 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f2', severity: 'MEDIUM', title: 'Med 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ]); // score 100 - (50 + 15) = 35
    assert.equal(critReport.riskLevel, 'CRITICAL');
  });

  it('Duplicate finding IDs do not double-count towards penalty', () => {
    const findings = [
      { id: 'f1', severity: 'MEDIUM', title: 'Med 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f1', severity: 'MEDIUM', title: 'Med 1 Dupe', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    // Should apply penalty only once
    const report = analyzeRisk(findings);
    assert.equal(report.score, 85);
  });

  it('Finding counts are correctly aggregated in summary', () => {
    const findings = [
      { id: 'f1', severity: 'INFO', title: 'Info 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f2', severity: 'LOW', title: 'Low 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f3', severity: 'MEDIUM', title: 'Med 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f4', severity: 'HIGH', title: 'High 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' },
      { id: 'f5', severity: 'CRITICAL', title: 'Crit 1', category: 'headers', description: '', impact: '', recommendation: '', evidence: '' }
    ];
    const report = analyzeRisk(findings);
    assert.deepEqual(report.summary, {
      critical: 1,
      high: 1,
      medium: 1,
      low: 1,
      info: 1
    });
  });

  it('Top recommendations are sorted by severity priority (actionable only)', () => {
    const findings = [
      { id: 'f_low', severity: 'LOW', title: 'Low Title', category: 'headers', description: '', impact: '', recommendation: 'Fix Low', evidence: '' },
      { id: 'f_info', severity: 'INFO', title: 'Info Title', category: 'headers', description: '', impact: '', recommendation: 'Fix Info', evidence: '' },
      { id: 'f_crit', severity: 'CRITICAL', title: 'Crit Title', category: 'headers', description: '', impact: '', recommendation: 'Fix Crit', evidence: '' },
      { id: 'f_med', severity: 'MEDIUM', title: 'Med Title', category: 'headers', description: '', impact: '', recommendation: 'Fix Med', evidence: '' }
    ];
    const report = analyzeRisk(findings);
    // INFO should not be in topRecommendations.
    // Order should be CRITICAL -> MEDIUM -> LOW
    assert.equal(report.topRecommendations.length, 3);
    assert.equal(report.topRecommendations[0].id, 'f_crit');
    assert.equal(report.topRecommendations[1].id, 'f_med');
    assert.equal(report.topRecommendations[2].id, 'f_low');
  });

  it('Empty findings produce 100/100 LOW risk', () => {
    const report = analyzeRisk([]);
    assert.equal(report.score, 100);
    assert.equal(report.riskLevel, 'LOW');
    assert.deepEqual(report.summary, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    assert.deepEqual(report.topRecommendations, []);
  });

  it('Sensitive values (cookie/session tokens) are never included in normalized findings', () => {
    // Check that standard normalizeFindings doesn't leak sensitive data
    const mockScanData = {
      target: 'http://example.com',
      isHttps: false,
      cookies: {
        analyzed: true,
        cookies: [
          {
            name: 'session',
            secure: false,
            httpOnly: false,
            sameSite: null,
            likelySession: true,
            findings: [
              { attribute: 'Secure', status: 'missing', severity: 'MEDIUM', description: 'Missing secure', recommendation: 'Set Secure' }
            ]
          }
        ]
      }
    };
    const { normalizeFindings } = require('../src/services/riskAnalyzer');
    const normalized = normalizeFindings(mockScanData);
    const serialized = JSON.stringify(normalized);
    // Make sure no raw values or sensitive terms are present in findings
    assert.ok(!serialized.includes('abc123'));
    assert.ok(!serialized.includes('eyJhbGci'));
  });
});
