'use strict';

// Severity penalties for heuristic scoring
const SEVERITY_PENALTIES = {
  INFO: 0,
  LOW: 5,
  MEDIUM: 15,
  HIGH: 30,
  CRITICAL: 50,
};

// Impact descriptions for headers
const HEADER_IMPACTS = {
  'strict-transport-security': 'HSTS prevents protocol downgrade attacks and cookie hijacking by forcing browsers to use HTTPS.',
  'content-security-policy':   'CSP mitigates Cross-Site Scripting (XSS) and content injection attacks by restricting resources that can be loaded.',
  'x-frame-options':           'X-Frame-Options protects users against Clickjacking attacks by preventing the site from being framed.',
  'x-content-type-options':    'X-Content-Type-Options prevents the browser from MIME-sniffing responses away from the declared Content-Type.',
  'referrer-policy':           'Referrer-Policy controls how much information is shared in the Referer header during cross-origin requests.',
  'permissions-policy':        'Permissions-Policy restricts access to browser APIs (like camera, geolocation) to reduce attack surface.',
};

// Impact descriptions for cookie attributes
const COOKIE_IMPACTS = {
  'secure':   'Unencrypted transmission allows cookies to be captured in transit by network attackers.',
  'httponly': 'Permitting client-side scripts to read the cookie exposes session identifiers to theft via XSS.',
  'samesite': 'Absence or misconfiguration reduces defenses against Cross-Site Request Forgery (CSRF).',
};

/**
 * Normalizes all findings from TLS, Header, and Cookie scans into a standard structure.
 *
 * @param {object} scanData - Raw scan data from the scanners
 * @returns {Array<object>} Normalized findings
 */
function normalizeFindings(scanData) {
  const findings = [];

  const target = scanData.target || '';
  const isHttps = !!scanData.isHttps;
  const tls = scanData.tls || {};
  const headers = scanData.headers || {};
  const cookies = scanData.cookies || {};
  const disclosure = scanData.disclosure || {};

  // 1. Plain HTTPS check
  if (!isHttps) {
    findings.push({
      id: 'https-missing',
      category: 'https',
      title: 'Plain HTTP Connection',
      severity: 'MEDIUM',
      description: 'The target website uses unencrypted HTTP. All data transmitted between the client and the server is sent in cleartext.',
      impact: 'Allows eavesdropping and tampering with traffic by network adversaries (Man-in-the-Middle).',
      recommendation: 'Migrate to HTTPS and redirect all HTTP traffic to HTTPS.',
      evidence: `Target URL scheme: http://`,
    });
  }

  // 2. TLS findings
  if (tls.analyzed) {
    if (tls.status === 'error') {
      findings.push({
        id: 'tls-inspection-failed',
        category: 'tls',
        title: 'TLS Certificate Inspection Failed',
        severity: 'LOW',
        description: `The TLS certificate could not be inspected. ${tls.message || ''}`,
        impact: 'The scanner was unable to verify the certificate\'s validity, trust chain, or expiration.',
        recommendation: 'Check the target web server\'s TLS configuration and ensure the certificate is correctly installed.',
        evidence: tls.message || 'Inspection error',
      });
    } else if (tls.certificate) {
      const cert = tls.certificate;

      if (cert.expired) {
        findings.push({
          id: 'tls-cert-expired',
          category: 'tls',
          title: 'TLS Certificate Expired',
          severity: 'MEDIUM',
          description: `The TLS certificate presented by the target server has expired (valid to: ${cert.validTo}).`,
          impact: 'Users\' browsers will display security warnings, and secure connection attempts may be blocked.',
          recommendation: 'Renew the TLS certificate immediately.',
          evidence: `Expired on: ${cert.validTo}`,
        });
      } else if (cert.expiringSoon) {
        findings.push({
          id: 'tls-cert-expiring-soon',
          category: 'tls',
          title: 'TLS Certificate Expiring Soon',
          severity: 'LOW',
          description: `The TLS certificate will expire in ${cert.daysRemaining} days (on ${cert.validTo}).`,
          impact: 'The connection will trigger browser errors once the certificate expires.',
          recommendation: 'Schedule a replacement for the expiring certificate.',
          evidence: `${cert.daysRemaining} days remaining`,
        });
      }

      if (!cert.hostnameValid) {
        findings.push({
          id: 'tls-cert-hostname-mismatch',
          category: 'tls',
          title: 'TLS Certificate Hostname Mismatch',
          severity: 'MEDIUM',
          description: 'The domain name in the TLS certificate does not match the requested target hostname.',
          impact: 'Browsers will reject the connection because the identity of the server cannot be verified.',
          recommendation: 'Ensure the certificate matches the requested domain name (check Common Name or SANs).',
          evidence: `Subject CN: ${cert.subject || 'unknown'}`,
        });
      }
    }
  }

  // 3. Header findings
  if (headers.analyzed && Array.isArray(headers.findings)) {
    for (const h of headers.findings) {
      const headerNameLower = h.header.toLowerCase();
      const findingId = `header-${headerNameLower}-${h.status}`;

      findings.push({
        id: findingId,
        category: 'headers',
        title: `${h.header} Header ${h.status.charAt(0).toUpperCase() + h.status.slice(1)}`,
        severity: h.severity,
        description: h.description,
        impact: HEADER_IMPACTS[headerNameLower] || 'A missing or misconfigured security header reduces defense-in-depth protections.',
        recommendation: h.recommendation || 'No action required.',
        evidence: h.value ? `${h.header}: ${h.value}` : 'Header absent',
      });
    }
  }

  // 4. Cookie findings
  if (cookies.analyzed && Array.isArray(cookies.cookies)) {
    for (const c of cookies.cookies) {
      if (Array.isArray(c.findings)) {
        for (const cf of c.findings) {
          const attrLower = cf.attribute.toLowerCase();
          const findingId = `cookie-${c.name.toLowerCase()}-${attrLower}-${cf.status}`;

          findings.push({
            id: findingId,
            category: 'cookies',
            title: `Cookie "${c.name}" ${cf.attribute} Attribute ${cf.status.charAt(0).toUpperCase() + cf.status.slice(1)}`,
            severity: cf.severity,
            description: cf.description,
            impact: COOKIE_IMPACTS[attrLower] || 'Cookie security settings are suboptimal.',
            recommendation: cf.recommendation || 'Configure cookie attributes securely.',
            evidence: `Cookie name: ${c.name} (likely session: ${c.likelySession ? 'yes' : 'no'})`,
          });
        }
      }
    }
  }

  // 5. Disclosure findings
  if (disclosure.analyzed && Array.isArray(disclosure.findings)) {
    for (const d of disclosure.findings) {
      findings.push({
        id: d.id,
        category: 'information-disclosure',
        title: d.title,
        severity: d.severity || 'LOW',
        description: d.description,
        impact: d.impact || 'Technology disclosure may assist reconnaissance.',
        recommendation: d.recommendation || 'Consider removing or suppressing technology identification headers.',
        evidence: d.evidence || `${d.header}: ${d.value}`,
      });
    }
  }

  return findings;
}

/**
 * Calculates security score, risk level, and retrieves top recommendations.
 *
 * @param {Array<object>} findings - Normalized findings list
 * @returns {object} Risk report summary
 */
function analyzeRisk(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  const uniqueFindingIds = new Set();
  let totalPenalty = 0;

  for (const f of findings) {
    const sev = f.severity.toUpperCase();

    // Increment counts for all findings
    if (sev === 'CRITICAL') counts.critical++;
    else if (sev === 'HIGH') counts.high++;
    else if (sev === 'MEDIUM') counts.medium++;
    else if (sev === 'LOW') counts.low++;
    else counts.info++;

    // Scoring calculation uses unique finding IDs to prevent double-counting
    if (!uniqueFindingIds.has(f.id)) {
      uniqueFindingIds.add(f.id);
      const penalty = SEVERITY_PENALTIES[sev] ?? 0;
      totalPenalty += penalty;
    }
  }

  // Clamp score between 0 and 100
  const score = Math.max(0, Math.min(100, 100 - totalPenalty));

  // Determine overall risk level
  let riskLevel = 'LOW';
  if (score < 40) riskLevel = 'CRITICAL';
  else if (score < 60) riskLevel = 'HIGH';
  else if (score < 80) riskLevel = 'MEDIUM';

  // Sort recommendations: Actionable only (severity !== INFO), sorted by severity priority
  const severityPriority = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const actionableFindings = findings.filter(f => f.severity !== 'INFO');

  actionableFindings.sort((a, b) => {
    return (severityPriority[b.severity] || 0) - (severityPriority[a.severity] || 0);
  });

  const topRecommendations = actionableFindings.slice(0, 5).map(f => ({
    id: f.id,
    header: f.category === 'headers' ? f.title : f.header,
    title: f.title,
    severity: f.severity,
    recommendation: f.recommendation,
  }));

  return {
    score,
    riskLevel,
    summary: counts,
    findings,
    topRecommendations,
  };
}

module.exports = {
  normalizeFindings,
  analyzeRisk,
  SEVERITY_PENALTIES,
};
