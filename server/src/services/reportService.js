'use strict';

/**
 * CyberGuard Report Service
 *
 * Generates a professional, multi-page PDF security assessment report from an
 * already-completed scan result.
 *
 * Security guarantees:
 *   - Cookie values are ALWAYS replaced with [REDACTED] before any content is
 *     written to the PDF — even if the caller sends a malicious payload.
 *   - JWT-pattern strings (eyJ...) are detected and replaced with [REDACTED].
 *   - Authorization header values are stripped.
 *   - All string fields are truncated to a safe maximum length.
 *   - No network requests are made here. No SSRF surface is added.
 *
 * @module reportService
 */

const PDFDocument = require('pdfkit');

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_STRING_LENGTH  = 2000;
const MAX_FILENAME_LENGTH = 60;

// Regex to detect JWT-like strings: base64url header + payload
const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/;

// Palette — consistent with CyberGuard branding
const COLORS = {
  brand:       '#0ea5e9',   // sky-500
  brandDark:   '#0c4a6e',   // sky-900
  coverBg:     '#0f172a',   // slate-950
  coverText:   '#f8fafc',   // slate-50
  sectionHead: '#1e293b',   // slate-800
  bodyText:    '#334155',   // slate-700
  mutedText:   '#64748b',   // slate-500
  lineColor:   '#e2e8f0',   // slate-200
  pageBg:      '#ffffff',
  // Severity
  critical:    '#dc2626',   // red-600
  high:        '#ea580c',   // orange-600
  medium:      '#d97706',   // amber-600
  low:         '#2563eb',   // blue-600
  info:        '#64748b',   // slate-500
  pass:        '#16a34a',   // green-600
  warn:        '#d97706',   // amber-600
};

const SEVERITY_COLORS = {
  CRITICAL: COLORS.critical,
  HIGH:     COLORS.high,
  MEDIUM:   COLORS.medium,
  LOW:      COLORS.low,
  INFO:     COLORS.info,
};

// ── Input Sanitization ───────────────────────────────────────────────────────

/**
 * Truncates a string to MAX_STRING_LENGTH and removes ASCII control characters
 * (other than normal whitespace). Never throws.
 *
 * @param {*} val
 * @returns {string}
 */
function safeStr(val) {
  if (val === null || val === undefined) return '';
  const s = String(val)
    // Remove ASCII control chars except \t \n \r
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
    .slice(0, MAX_STRING_LENGTH);
  // Redact JWT-like tokens
  return s.replace(new RegExp(JWT_PATTERN.source, 'g'), '[REDACTED]');
}

/**
 * Recursively redacts sensitive fields in a cookie object.
 * Removes `value` and replaces `redactedValue` with '[REDACTED]'.
 *
 * @param {object} cookie
 * @returns {object}
 */
function sanitizeCookie(cookie) {
  if (!cookie || typeof cookie !== 'object') return {};
  const { value: _v, redactedValue: _rv, ...rest } = cookie;
  // Walk findings to sanitize any embedded sensitive data
  const findings = Array.isArray(rest.findings)
    ? rest.findings.map((f) => {
        if (!f || typeof f !== 'object') return f;
        const { value: _fv, ...fRest } = f;
        return {
          attribute:      safeStr(fRest.attribute),
          status:         safeStr(fRest.status),
          severity:       safeStr(fRest.severity),
          description:    safeStr(fRest.description),
          recommendation: safeStr(fRest.recommendation),
        };
      })
    : [];

  return {
    name:          safeStr(rest.name),
    redactedValue: '[REDACTED]',
    likelySession: !!rest.likelySession,
    secure:        !!rest.secure,
    httpOnly:      !!rest.httpOnly,
    sameSite:      rest.sameSite ? safeStr(rest.sameSite) : null,
    path:          rest.path    ? safeStr(rest.path)    : null,
    domain:        rest.domain  ? safeStr(rest.domain)  : null,
    maxAge:        typeof rest.maxAge === 'number' ? rest.maxAge : null,
    expires:       rest.expires ? safeStr(rest.expires) : null,
    findings,
  };
}

/**
 * Sanitizes and validates the raw scan result supplied by the caller.
 *
 * Throws an Error with a user-safe message if the payload is structurally
 * invalid (missing required fields). Sensitive values are redacted in-place
 * on a deep clone — the original object is never mutated.
 *
 * Required top-level fields: target (string), risk (object with score & riskLevel)
 *
 * @param {*} raw - Untrusted caller-supplied scan result
 * @returns {object} Sanitized scan result
 * @throws {Error} If the payload is structurally invalid
 */
function sanitizeScanResult(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('scanResult must be a non-null object.');
  }

  if (typeof raw.target !== 'string' || !raw.target.trim()) {
    throw new Error('scanResult.target must be a non-empty string.');
  }

  if (!raw.risk || typeof raw.risk !== 'object') {
    throw new Error('scanResult.risk must be an object.');
  }

  if (typeof raw.risk.score !== 'number') {
    throw new Error('scanResult.risk.score must be a number.');
  }

  if (typeof raw.risk.riskLevel !== 'string') {
    throw new Error('scanResult.risk.riskLevel must be a string.');
  }

  // Deep-sanitize cookies — values are ALWAYS redacted
  let cookies = { analyzed: false, count: 0, cookies: [] };
  if (raw.cookies && typeof raw.cookies === 'object') {
    cookies = {
      analyzed: !!raw.cookies.analyzed,
      count:    typeof raw.cookies.count === 'number' ? raw.cookies.count : 0,
      cookies:  Array.isArray(raw.cookies.cookies)
        ? raw.cookies.cookies.map(sanitizeCookie)
        : [],
    };
  }

  // Sanitize TLS section
  let tls = { analyzed: false };
  if (raw.tls && typeof raw.tls === 'object') {
    tls = { analyzed: !!raw.tls.analyzed };
    if (raw.tls.protocol)    tls.protocol = safeStr(raw.tls.protocol);
    if (raw.tls.status)      tls.status   = safeStr(raw.tls.status);
    if (raw.tls.message)     tls.message  = safeStr(raw.tls.message);
    if (raw.tls.reason)      tls.reason   = safeStr(raw.tls.reason);
    if (raw.tls.certificate && typeof raw.tls.certificate === 'object') {
      const c = raw.tls.certificate;
      tls.certificate = {
        subject:       c.subject       ? safeStr(c.subject)   : null,
        issuer:        c.issuer        ? safeStr(c.issuer)    : null,
        validFrom:     c.validFrom     ? safeStr(c.validFrom) : null,
        validTo:       c.validTo       ? safeStr(c.validTo)   : null,
        daysRemaining: typeof c.daysRemaining === 'number' ? c.daysRemaining : null,
        expired:       !!c.expired,
        expiringSoon:  !!c.expiringSoon,
        hostnameValid: !!c.hostnameValid,
      };
    }
  }

  // Sanitize headers section — never include Authorization or cookie values
  let headers = { analyzed: false, findings: [] };
  if (raw.headers && typeof raw.headers === 'object') {
    const findings = Array.isArray(raw.headers.findings)
      ? raw.headers.findings.map((f) => {
          if (!f || typeof f !== 'object') return null;
          return {
            header:         safeStr(f.header),
            status:         safeStr(f.status),
            severity:       safeStr(f.severity),
            // Only surface safe header values — never Authorization or Set-Cookie content
            value:          f.value ? safeStr(f.value) : null,
            description:    safeStr(f.description),
            recommendation: f.recommendation ? safeStr(f.recommendation) : null,
          };
        }).filter(Boolean)
      : [];
    headers = { analyzed: !!raw.headers.analyzed, findings };
  }

  // Sanitize disclosure section
  let disclosure = { analyzed: false, count: 0, findings: [] };
  if (raw.disclosure && typeof raw.disclosure === 'object') {
    const findings = Array.isArray(raw.disclosure.findings)
      ? raw.disclosure.findings.map((f) => {
          if (!f || typeof f !== 'object') return null;
          return {
            id:             safeStr(f.id),
            header:         safeStr(f.header),
            value:          safeStr(f.value),
            title:          safeStr(f.title),
            severity:       safeStr(f.severity),
            description:    safeStr(f.description),
            impact:         safeStr(f.impact),
            recommendation: safeStr(f.recommendation),
            evidence:       safeStr(f.evidence),
          };
        }).filter(Boolean)
      : [];
    disclosure = {
      analyzed: !!raw.disclosure.analyzed,
      count: typeof raw.disclosure.count === 'number' ? raw.disclosure.count : findings.length,
      findings,
    };
  }

  // Sanitize risk section
  const summary = raw.risk.summary && typeof raw.risk.summary === 'object'
    ? {
        critical: Number(raw.risk.summary.critical) || 0,
        high:     Number(raw.risk.summary.high)     || 0,
        medium:   Number(raw.risk.summary.medium)   || 0,
        low:      Number(raw.risk.summary.low)       || 0,
        info:     Number(raw.risk.summary.info)      || 0,
      }
    : { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  const findings = Array.isArray(raw.risk.findings)
    ? raw.risk.findings.map((f) => {
        if (!f || typeof f !== 'object') return null;
        return {
          id:             safeStr(f.id),
          category:       safeStr(f.category),
          title:          safeStr(f.title),
          severity:       safeStr(f.severity),
          description:    safeStr(f.description),
          impact:         safeStr(f.impact),
          recommendation: safeStr(f.recommendation),
          evidence:       safeStr(f.evidence),
        };
      }).filter(Boolean)
    : [];

  const topRecommendations = Array.isArray(raw.risk.topRecommendations)
    ? raw.risk.topRecommendations.map((r) => {
        if (!r || typeof r !== 'object') return null;
        return {
          id:             safeStr(r.id),
          title:          safeStr(r.title),
          severity:       safeStr(r.severity),
          recommendation: safeStr(r.recommendation),
        };
      }).filter(Boolean)
    : [];

  return {
    target:          safeStr(raw.target),
    finalUrl:        raw.finalUrl        ? safeStr(raw.finalUrl)   : undefined,
    statusCode:      typeof raw.statusCode === 'number' ? raw.statusCode : null,
    statusText:      raw.statusText      ? safeStr(raw.statusText) : null,
    responseTime:    typeof raw.responseTime === 'number' ? raw.responseTime : null,
    isHttps:         !!raw.isHttps,
    redirectsToHttps: raw.redirectsToHttps ? true : undefined,
    scanTimestamp:   raw.scanTimestamp   ? safeStr(raw.scanTimestamp) : new Date().toISOString(),
    tls,
    headers,
    cookies,
    disclosure,
    risk: { score: raw.risk.score, riskLevel: safeStr(raw.risk.riskLevel), summary, findings, topRecommendations },
  };
}

// ── Filename Sanitization ────────────────────────────────────────────────────

/**
 * Produces a safe, filesystem-friendly PDF filename from a target URL string.
 *
 * Example: "https://example.com/" → "CyberGuard-Report-example-com-2026-08-11.pdf"
 *
 * @param {string} target - The target URL
 * @returns {string} Safe filename
 */
function sanitizeFilename(target) {
  const dateStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  let host = '';
  try {
    host = new URL(target).hostname;
  } catch {
    host = target;
  }
  const safePart = host
    .replace(/[^a-zA-Z0-9.-]/g, '-')   // replace non-alphanumeric (except . and -)
    .replace(/\.+/g, '-')               // dots → dashes
    .replace(/-+/g, '-')                // collapse repeated dashes
    .replace(/^-+|-+$/g, '')            // strip leading/trailing dashes
    .slice(0, MAX_FILENAME_LENGTH);
  return `CyberGuard-Report-${safePart}-${dateStr}.pdf`;
}

// ── PDF Layout Helpers ───────────────────────────────────────────────────────

const PAGE_WIDTH  = 595.28;  // A4 points
const PAGE_HEIGHT = 841.89;
const MARGIN      = 50;
const CONTENT_W   = PAGE_WIDTH - MARGIN * 2;

/**
 * Draws a horizontal rule across the content width.
 */
function hRule(doc, y, color = COLORS.lineColor) {
  doc.save()
    .strokeColor(color)
    .lineWidth(0.5)
    .moveTo(MARGIN, y)
    .lineTo(PAGE_WIDTH - MARGIN, y)
    .stroke()
    .restore();
}

/**
 * Draws a colored filled rectangle (used for section headers and severity pills).
 */
function fillRect(doc, x, y, w, h, color) {
  doc.save().rect(x, y, w, h).fill(color).restore();
}

/**
 * Writes a section header bar with a white title.
 * Returns the Y position after the bar.
 */
function sectionHeader(doc, title, y) {
  // Check if we need a new page (leave 80pt minimum)
  if (y > PAGE_HEIGHT - 120) {
    doc.addPage();
    y = MARGIN;
  }
  fillRect(doc, MARGIN, y, CONTENT_W, 22, COLORS.sectionHead);
  doc.save()
    .fillColor('#ffffff')
    .fontSize(10)
    .font('Helvetica-Bold')
    .text(title.toUpperCase(), MARGIN + 8, y + 6, { width: CONTENT_W - 16, lineBreak: false })
    .restore();
  return y + 28;
}

/**
 * Draws a two-column key/value row.
 * Returns the Y position after the row.
 */
function kvRow(doc, key, value, y, opts = {}) {
  const { keyWidth = 160, valueColor = COLORS.bodyText } = opts;
  const safeValue = value === null || value === undefined ? '—' : String(value);

  // Ensure we don't go off the page
  if (y > PAGE_HEIGHT - 60) {
    doc.addPage();
    y = MARGIN;
  }

  doc.save()
    .fontSize(9)
    .font('Helvetica-Bold')
    .fillColor(COLORS.mutedText)
    .text(key, MARGIN, y, { width: keyWidth, lineBreak: false });

  doc.font('Helvetica')
    .fillColor(valueColor)
    .text(safeValue, MARGIN + keyWidth, y, { width: CONTENT_W - keyWidth });

  const textHeight = doc.heightOfString(safeValue, { width: CONTENT_W - keyWidth, font: 'Helvetica', size: 9 });
  doc.restore();

  return y + Math.max(14, textHeight + 2);
}

/**
 * Draws a severity badge (filled rect with text) at the given position.
 * Returns the badge's right edge X.
 */
function severityBadge(doc, severity, x, y) {
  const sev = (severity || 'INFO').toUpperCase();
  const color = SEVERITY_COLORS[sev] || COLORS.info;
  const label = sev;
  const badgeW = doc.widthOfString(label, { size: 8, font: 'Helvetica-Bold' }) + 10;
  const badgeH = 13;

  doc.save()
    .rect(x, y, badgeW, badgeH)
    .fill(color);

  doc.fillColor('#ffffff')
    .fontSize(8)
    .font('Helvetica-Bold')
    .text(label, x + 5, y + 3, { width: badgeW - 10, lineBreak: false })
    .restore();

  return x + badgeW + 6;
}

/**
 * Ensures there is enough vertical space remaining on the current page.
 * Adds a new page if not. Returns the updated Y.
 */
function ensureSpace(doc, y, needed = 80) {
  if (y + needed > PAGE_HEIGHT - MARGIN) {
    doc.addPage();
    return MARGIN;
  }
  return y;
}

// ── PDF Section Writers ──────────────────────────────────────────────────────

/**
 * Cover page — full dark background with CyberGuard branding.
 */
function writeCover(doc, data) {
  // Full-page dark background
  fillRect(doc, 0, 0, PAGE_WIDTH, PAGE_HEIGHT, COLORS.coverBg);

  // Top accent bar
  fillRect(doc, 0, 0, PAGE_WIDTH, 6, COLORS.brand);

  // Shield icon area (text art)
  doc.save()
    .fillColor(COLORS.brand)
    .fontSize(64)
    .font('Helvetica-Bold')
    .text('⬡', PAGE_WIDTH / 2 - 40, 100, { width: 80, align: 'center', lineBreak: false })
    .restore();

  // Title: CyberGuard
  doc.save()
    .fillColor(COLORS.coverText)
    .fontSize(38)
    .font('Helvetica-Bold')
    .text('CyberGuard', MARGIN, 190, { width: CONTENT_W, align: 'center' })
    .restore();

  // Subtitle
  doc.save()
    .fillColor(COLORS.brand)
    .fontSize(14)
    .font('Helvetica')
    .text('Web Security Assessment Report', MARGIN, 238, { width: CONTENT_W, align: 'center' })
    .restore();

  // Divider
  doc.save()
    .strokeColor(COLORS.brand)
    .lineWidth(1)
    .moveTo(MARGIN + 60, 265)
    .lineTo(PAGE_WIDTH - MARGIN - 60, 265)
    .stroke()
    .restore();

  // Metadata block
  const metaStartY = 290;
  const metaLabelX = PAGE_WIDTH / 2 - 130;
  const metaValueX = PAGE_WIDTH / 2 - 10;

  const rows = [
    ['Target',           data.target],
    ['Scan Date',        data.scanTimestamp
      ? new Date(data.scanTimestamp).toLocaleString('en-GB', { hour12: false })
      : new Date().toLocaleString('en-GB', { hour12: false })],
    ['Assessment Type',  'Automated Web Security Configuration Assessment'],
    ['HTTPS',            data.isHttps ? 'Yes' : 'No'],
    ['Security Score',   `${data.risk.score} / 100`],
    ['Overall Risk',     data.risk.riskLevel],
  ];

  let metaY = metaStartY;
  for (const [label, value] of rows) {
    doc.save()
      .fillColor(COLORS.mutedText)
      .fontSize(9)
      .font('Helvetica-Bold')
      .text(label.toUpperCase(), metaLabelX, metaY, { width: 120, align: 'right', lineBreak: false })
      .restore();

    doc.save()
      .fillColor(COLORS.coverText)
      .fontSize(9)
      .font('Helvetica')
      .text(value || '—', metaValueX + 10, metaY, { width: PAGE_WIDTH - metaValueX - MARGIN - 10 })
      .restore();

    metaY += 20;
  }

  // Classification bar
  fillRect(doc, MARGIN, PAGE_HEIGHT - 80, CONTENT_W, 28, '#1e3a5f');
  doc.save()
    .fillColor('#93c5fd')
    .fontSize(8)
    .font('Helvetica-Bold')
    .text(
      'CONFIDENTIAL — FOR AUTHORIZED SECURITY ASSESSMENT USE ONLY',
      MARGIN + 10, PAGE_HEIGHT - 68,
      { width: CONTENT_W - 20, align: 'center' }
    )
    .restore();

  // Version footer
  doc.save()
    .fillColor(COLORS.mutedText)
    .fontSize(7)
    .font('Helvetica')
    .text('CyberGuard v1.0 · Automated Assessment Only · Not a Penetration Test', MARGIN, PAGE_HEIGHT - 40, {
      width: CONTENT_W,
      align: 'center',
    })
    .restore();
}

/**
 * Executive Summary section.
 */
function writeExecutiveSummary(doc, data, startY) {
  let y = sectionHeader(doc, '1. Executive Summary', startY);
  y += 8;

  const { score, riskLevel, summary } = data.risk;

  // Score + risk in a prominent block
  const scoreColor = riskLevel === 'LOW' ? COLORS.pass
    : riskLevel === 'MEDIUM' ? COLORS.medium
    : COLORS.critical;

  doc.save()
    .fontSize(36)
    .font('Helvetica-Bold')
    .fillColor(scoreColor)
    .text(`${score}`, MARGIN, y, { lineBreak: false });

  doc.fontSize(18)
    .fillColor(COLORS.mutedText)
    .text(' / 100', MARGIN + 54, y + 10, { lineBreak: false });

  doc.fontSize(11)
    .font('Helvetica-Bold')
    .fillColor(scoreColor)
    .text(`${riskLevel} RISK`, MARGIN + 130, y + 10, { lineBreak: false });
  doc.restore();

  y += 52;

  // Finding counts bar
  const counts = [
    { label: 'Critical', count: summary.critical, color: COLORS.critical },
    { label: 'High',     count: summary.high,     color: COLORS.high },
    { label: 'Medium',   count: summary.medium,   color: COLORS.medium },
    { label: 'Low',      count: summary.low,       color: COLORS.low },
    { label: 'Info',     count: summary.info,      color: COLORS.info },
  ];

  const pillW = (CONTENT_W - 32) / counts.length;
  let pillX = MARGIN;
  for (const { label, count, color } of counts) {
    fillRect(doc, pillX, y, pillW - 4, 40, color);
    doc.save()
      .fillColor('#ffffff')
      .fontSize(18)
      .font('Helvetica-Bold')
      .text(String(count), pillX, y + 4, { width: pillW - 4, align: 'center', lineBreak: false });
    doc.fontSize(8)
      .font('Helvetica')
      .text(label, pillX, y + 26, { width: pillW - 4, align: 'center', lineBreak: false });
    doc.restore();
    pillX += pillW;
  }

  y += 52;

  // Assessment note
  doc.save()
    .fontSize(8.5)
    .font('Helvetica')
    .fillColor(COLORS.mutedText)
    .text(
      'This assessment is a heuristic evaluation based on the security controls implemented by CyberGuard. ' +
      'It does not guarantee that the target is free of vulnerabilities.',
      MARGIN, y, { width: CONTENT_W }
    )
    .restore();

  return y + 28;
}

/**
 * Target information section.
 */
function writeTargetInfo(doc, data, startY) {
  let y = sectionHeader(doc, '2. Target Information', startY);
  y += 8;

  y = kvRow(doc, 'Target URL',           data.target,       y);
  if (data.finalUrl) {
    y = kvRow(doc, 'Final URL',           data.finalUrl,     y);
  }
  y = kvRow(doc, 'HTTP Status',          data.statusCode ? `${data.statusCode} ${data.statusText || ''}`.trim() : '—', y);
  y = kvRow(doc, 'Response Time',        data.responseTime != null ? `${data.responseTime} ms` : '—', y);
  y = kvRow(doc, 'HTTPS Enabled',        data.isHttps ? 'Yes' : 'No', y,
    { valueColor: data.isHttps ? COLORS.pass : COLORS.warn });
  if (data.redirectsToHttps) {
    y = kvRow(doc, 'HTTP → HTTPS Redirect', 'Yes (HTTP target redirects to HTTPS)', y,
      { valueColor: COLORS.medium });
  }
  y = kvRow(doc, 'Scan Timestamp',       data.scanTimestamp
    ? new Date(data.scanTimestamp).toLocaleString('en-GB', { hour12: false })
    : '—', y);

  return y + 10;
}

/**
 * TLS / Certificate analysis section.
 */
function writeTlsSection(doc, data, startY) {
  let y = sectionHeader(doc, '3. TLS / Certificate Analysis', startY);
  y += 8;

  const { tls } = data;

  if (!tls || !tls.analyzed) {
    doc.save()
      .fontSize(9)
      .font('Helvetica')
      .fillColor(COLORS.mutedText)
      .text('TLS analysis was not performed because the target uses HTTP.', MARGIN, y, { width: CONTENT_W })
      .restore();
    return y + 24;
  }

  if (tls.status === 'error') {
    y = kvRow(doc, 'Status', `Error: ${tls.message || 'Unknown TLS error'}`, y, { valueColor: COLORS.warn });
    return y + 10;
  }

  if (tls.protocol) {
    y = kvRow(doc, 'Protocol',     tls.protocol, y);
  }

  if (tls.certificate) {
    const c = tls.certificate;
    y = kvRow(doc, 'Subject',            c.subject || '—', y);
    y = kvRow(doc, 'Issuer',             c.issuer  || '—', y);
    y = kvRow(doc, 'Valid From',         c.validFrom ? new Date(c.validFrom).toUTCString() : '—', y);
    y = kvRow(doc, 'Valid Until',        c.validTo   ? new Date(c.validTo).toUTCString()   : '—', y);
    y = kvRow(doc, 'Days Remaining',     c.daysRemaining != null ? String(c.daysRemaining) : '—', y,
      { valueColor: c.expired ? COLORS.critical : c.expiringSoon ? COLORS.warn : COLORS.pass });
    y = kvRow(doc, 'Hostname Valid',     c.hostnameValid ? 'Yes' : 'No', y,
      { valueColor: c.hostnameValid ? COLORS.pass : COLORS.critical });
    y = kvRow(doc, 'Expired',            c.expired ? 'Yes' : 'No', y,
      { valueColor: c.expired ? COLORS.critical : COLORS.pass });
  }

  return y + 10;
}

/**
 * Security headers analysis section.
 */
function writeHeadersSection(doc, data, startY) {
  let y = sectionHeader(doc, '4. Security Headers', startY);
  y += 8;

  const { headers } = data;
  if (!headers || !headers.analyzed || !Array.isArray(headers.findings) || headers.findings.length === 0) {
    doc.save().fontSize(9).font('Helvetica').fillColor(COLORS.mutedText)
      .text('No header analysis data available.', MARGIN, y, { width: CONTENT_W }).restore();
    return y + 24;
  }

  for (const finding of headers.findings) {
    y = ensureSpace(doc, y, 90);

    // Header name + severity badge
    const badgeRightX = severityBadge(doc, finding.severity, MARGIN, y);

    doc.save()
      .fontSize(10)
      .font('Helvetica-Bold')
      .fillColor(COLORS.sectionHead)
      .text(finding.header || '—', badgeRightX, y, { width: CONTENT_W - (badgeRightX - MARGIN), lineBreak: false })
      .restore();

    // Status chip
    const statusLabel = (finding.status || '').toUpperCase();
    doc.save()
      .fontSize(8)
      .font('Helvetica')
      .fillColor(COLORS.mutedText)
      .text(`Status: ${statusLabel}`, MARGIN, y + 16, { lineBreak: false })
      .restore();

    y += 28;

    if (finding.description) {
      doc.save().fontSize(8.5).font('Helvetica').fillColor(COLORS.bodyText)
        .text(finding.description, MARGIN, y, { width: CONTENT_W })
        .restore();
      y += doc.heightOfString(finding.description, { width: CONTENT_W, size: 8.5 }) + 4;
    }

    if (finding.recommendation) {
      doc.save().fontSize(8.5).font('Helvetica-Bold').fillColor(COLORS.brand)
        .text(`Recommendation: `, MARGIN, y, { continued: true, lineBreak: false })
        .font('Helvetica').fillColor(COLORS.bodyText)
        .text(finding.recommendation, { width: CONTENT_W })
        .restore();
      y += doc.heightOfString(finding.recommendation, { width: CONTENT_W, size: 8.5 }) + 4;
    }

    if (finding.value) {
      doc.save().fontSize(8).font('Helvetica').fillColor(COLORS.mutedText)
        .text(`Observed: ${finding.value}`, MARGIN, y, { width: CONTENT_W })
        .restore();
      y += 12;
    }

    y += 6;
    hRule(doc, y);
    y += 10;
  }

  return y;
}

/**
 * Information Disclosure section.
 */
function writeDisclosureSection(doc, data, startY) {
  let y = sectionHeader(doc, '5. Information Disclosure', startY);
  y += 8;

  const { disclosure } = data;

  if (!disclosure || !disclosure.analyzed || !Array.isArray(disclosure.findings) || disclosure.findings.length === 0) {
    doc.save()
      .fontSize(9)
      .font('Helvetica')
      .fillColor(COLORS.pass)
      .text('✓ No common technology-disclosure headers detected.', MARGIN, y, { width: CONTENT_W })
      .restore();
    return y + 24;
  }

  for (const finding of disclosure.findings) {
    y = ensureSpace(doc, y, 70);

    const badgeRightX = severityBadge(doc, finding.severity || 'LOW', MARGIN, y);

    doc.save()
      .fontSize(10)
      .font('Helvetica-Bold')
      .fillColor(COLORS.sectionHead)
      .text(finding.title || finding.header || '—', badgeRightX, y, { width: CONTENT_W - (badgeRightX - MARGIN), lineBreak: false })
      .restore();

    y += 18;

    if (finding.header && finding.value) {
      y = kvRow(doc, 'Observed Header', `${finding.header}: ${finding.value}`, y, { keyWidth: 120 });
    }

    if (finding.description) {
      doc.save().fontSize(8.5).font('Helvetica').fillColor(COLORS.bodyText)
        .text(finding.description, MARGIN, y, { width: CONTENT_W })
        .restore();
      y += doc.heightOfString(finding.description, { width: CONTENT_W, size: 8.5 }) + 4;
    }

    if (finding.recommendation) {
      doc.save().fontSize(8.5).font('Helvetica-Bold').fillColor(COLORS.brand)
        .text('Recommendation: ', MARGIN, y, { continued: true, lineBreak: false })
        .font('Helvetica').fillColor(COLORS.bodyText)
        .text(finding.recommendation, { width: CONTENT_W })
        .restore();
      y += doc.heightOfString(finding.recommendation, { width: CONTENT_W, size: 8.5 }) + 4;
    }

    y += 4;
    hRule(doc, y);
    y += 10;
  }

  return y;
}

/**
 * Cookie security analysis section.
 */
function writeCookieSection(doc, data, startY) {
  let y = sectionHeader(doc, '6. Cookie Security', startY);
  y += 8;

  const { cookies } = data;

  if (!cookies || !cookies.analyzed || cookies.count === 0) {
    doc.save().fontSize(9).font('Helvetica').fillColor(COLORS.mutedText)
      .text('No Set-Cookie headers were returned by the target.', MARGIN, y, { width: CONTENT_W }).restore();
    return y + 24;
  }

  for (const cookie of cookies.cookies) {
    y = ensureSpace(doc, y, 100);

    // Cookie name heading
    doc.save()
      .fontSize(10)
      .font('Helvetica-Bold')
      .fillColor(COLORS.sectionHead)
      .text(`Cookie: ${cookie.name}`, MARGIN, y)
      .restore();

    if (cookie.likelySession) {
      doc.save().fontSize(8).font('Helvetica').fillColor(COLORS.warn)
        .text('(likely session / auth cookie)', MARGIN + doc.widthOfString(`Cookie: ${cookie.name}`, { size: 10, font: 'Helvetica-Bold' }) + 6, y + 1, { lineBreak: false })
        .restore();
    }

    y += 16;

    // Attribute grid
    const attrs = [
      ['Value',         '[REDACTED]'],   // Always redacted
      ['Secure',        cookie.secure    ? 'Yes' : 'No'],
      ['HttpOnly',      cookie.httpOnly  ? 'Yes' : 'No'],
      ['SameSite',      cookie.sameSite  || '—'],
      ['Path',          cookie.path      || '—'],
      ['Domain',        cookie.domain    || '—'],
      ['Max-Age',       cookie.maxAge != null ? String(cookie.maxAge) : '—'],
      ['Expires',       cookie.expires   || '—'],
    ];

    for (const [key, val] of attrs) {
      y = kvRow(doc, key, val, y, { keyWidth: 100 });
    }

    // Cookie-level findings
    if (Array.isArray(cookie.findings) && cookie.findings.length > 0) {
      y += 4;
      doc.save().fontSize(8.5).font('Helvetica-Bold').fillColor(COLORS.bodyText)
        .text('Findings:', MARGIN, y).restore();
      y += 14;

      for (const cf of cookie.findings) {
        y = ensureSpace(doc, y, 40);
        severityBadge(doc, cf.severity, MARGIN, y);
        doc.save().fontSize(8.5).font('Helvetica').fillColor(COLORS.bodyText)
          .text(`${cf.attribute}: ${cf.description || ''}`, MARGIN + 60, y, { width: CONTENT_W - 60 })
          .restore();
        const cfH = doc.heightOfString(`${cf.attribute}: ${cf.description || ''}`, { width: CONTENT_W - 60, size: 8.5 });
        y += Math.max(14, cfH + 2);
      }
    }

    y += 4;
    hRule(doc, y);
    y += 10;
  }

  return y;
}

/**
 * Detailed findings section — grouped by severity.
 */
function writeFindingsSection(doc, data, startY) {
  let y = sectionHeader(doc, '7. Detailed Findings', startY);
  y += 8;

  const allFindings = data.risk.findings;

  if (!allFindings || allFindings.length === 0) {
    doc.save().fontSize(9).font('Helvetica').fillColor(COLORS.pass)
      .text('✓ No security findings were identified by this assessment.', MARGIN, y, { width: CONTENT_W }).restore();
    return y + 24;
  }

  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  let findingNumber = 1;

  for (const sev of order) {
    const group = allFindings.filter((f) => (f.severity || '').toUpperCase() === sev);
    if (group.length === 0) continue;

    y = ensureSpace(doc, y, 40);
    // Group sub-header
    const groupColor = SEVERITY_COLORS[sev] || COLORS.info;
    fillRect(doc, MARGIN, y, CONTENT_W, 18, groupColor + '22'); // alpha tint
    doc.save()
      .fontSize(9)
      .font('Helvetica-Bold')
      .fillColor(groupColor)
      .text(`${sev} (${group.length} finding${group.length !== 1 ? 's' : ''})`, MARGIN + 8, y + 4, { lineBreak: false })
      .restore();
    y += 24;

    for (const finding of group) {
      y = ensureSpace(doc, y, 120);

      // Finding number + severity badge + title
      const badgeEnd = severityBadge(doc, finding.severity, MARGIN, y);
      doc.save()
        .fontSize(9)
        .font('Helvetica-Bold')
        .fillColor(COLORS.sectionHead)
        .text(`[${String(findingNumber).padStart(2, '0')}] ${finding.title}`, badgeEnd, y, {
          width: CONTENT_W - (badgeEnd - MARGIN),
          lineBreak: false,
        })
        .restore();

      y += 16;

      // ID + category
      doc.save().fontSize(7.5).font('Helvetica').fillColor(COLORS.mutedText)
        .text(`ID: ${finding.id}  ·  Category: ${finding.category}`, MARGIN, y, { lineBreak: false })
        .restore();
      y += 12;

      const fields = [
        ['Description',     finding.description],
        ['Impact',          finding.impact],
        ['Recommendation',  finding.recommendation],
        ['Evidence',        finding.evidence],
      ];

      for (const [label, text] of fields) {
        if (!text) continue;
        y = ensureSpace(doc, y, 30);
        doc.save().fontSize(8).font('Helvetica-Bold').fillColor(COLORS.mutedText)
          .text(`${label}: `, MARGIN, y, { continued: true, lineBreak: false })
          .font('Helvetica').fillColor(COLORS.bodyText)
          .text(text, { width: CONTENT_W })
          .restore();
        y += doc.heightOfString(text, { width: CONTENT_W - 80, size: 8 }) + 4;
      }

      y += 4;
      hRule(doc, y, '#f1f5f9');
      y += 8;
      findingNumber++;
    }

    y += 6;
  }

  return y;
}

/**
 * Top recommendations section.
 */
function writeRecommendations(doc, data, startY) {
  let y = sectionHeader(doc, '8. Top Recommendations', startY);
  y += 8;

  const recs = data.risk.topRecommendations;
  if (!recs || recs.length === 0) {
    doc.save().fontSize(9).font('Helvetica').fillColor(COLORS.pass)
      .text('✓ No priority recommendations at this time. All assessed controls meet baseline policies.', MARGIN, y, { width: CONTENT_W }).restore();
    return y + 24;
  }

  let idx = 1;
  for (const rec of recs) {
    y = ensureSpace(doc, y, 60);
    const badgeEnd = severityBadge(doc, rec.severity, MARGIN, y);
    doc.save()
      .fontSize(9)
      .font('Helvetica-Bold')
      .fillColor(COLORS.sectionHead)
      .text(`${idx}. ${rec.title}`, badgeEnd, y, { width: CONTENT_W - (badgeEnd - MARGIN), lineBreak: false })
      .restore();
    y += 16;

    doc.save().fontSize(8.5).font('Helvetica').fillColor(COLORS.bodyText)
      .text(rec.recommendation, MARGIN, y, { width: CONTENT_W })
      .restore();
    y += doc.heightOfString(rec.recommendation, { width: CONTENT_W, size: 8.5 }) + 8;

    hRule(doc, y, '#f1f5f9');
    y += 8;
    idx++;
  }

  return y;
}

/**
 * Disclaimer section.
 */
function writeDisclaimer(doc, startY) {
  let y = ensureSpace(doc, startY, 100);
  y = sectionHeader(doc, '9. Disclaimer & Legal Notice', y);
  y += 8;

  const disclaimerText =
    'CyberGuard performs automated security configuration checks against the supplied target. ' +
    'The assessment is heuristic and limited to the controls implemented by this version of CyberGuard. ' +
    'It does not constitute a full penetration test, vulnerability assessment, or guarantee of security.\n\n' +
    'This report should only be used as one component of a broader security programme. ' +
    'Additional manual testing, code review, and expert assessment may be required to identify all security issues.\n\n' +
    'IMPORTANT: Security scanning must only be performed against systems and applications that you own or have ' +
    'explicit written authorization to test. Unauthorized scanning may violate applicable laws and regulations. ' +
    'The operators of CyberGuard accept no liability for unauthorized use of this tool.';

  doc.save()
    .fontSize(8.5)
    .font('Helvetica')
    .fillColor(COLORS.bodyText)
    .text(disclaimerText, MARGIN, y, { width: CONTENT_W })
    .restore();

  return y + doc.heightOfString(disclaimerText, { width: CONTENT_W, size: 8.5 }) + 20;
}

// ── Page Number Footer ───────────────────────────────────────────────────────

/**
 * Adds a "Page N" footer to every page after the cover.
 * Called once after the document is complete via range.
 */
function addPageNumbers(doc) {
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    // Skip cover (page 0)
    if (i === 0) continue;
    doc.switchToPage(range.start + i);
    hRule(doc, PAGE_HEIGHT - 38);
    doc.save()
      .fontSize(7.5)
      .font('Helvetica')
      .fillColor(COLORS.mutedText)
      .text('CyberGuard Security Assessment Report', MARGIN, PAGE_HEIGHT - 28, {
        width: CONTENT_W / 2,
        align: 'left',
        lineBreak: false,
      })
      .text(`Page ${i + 1} of ${range.count}`, PAGE_WIDTH / 2, PAGE_HEIGHT - 28, {
        width: CONTENT_W / 2,
        align: 'right',
        lineBreak: false,
      })
      .restore();
  }
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Generates the CyberGuard security assessment PDF report.
 *
 * Takes a sanitized scan result and returns a Buffer containing the complete
 * PDF document. No network calls are made.
 *
 * @param {object} scanResult - Already-sanitized scan result (from sanitizeScanResult)
 * @returns {Promise<Buffer>}
 */
function generateReport(scanResult) {
  return new Promise((resolve, reject) => {
    try {
      const chunks = [];

      const doc = new PDFDocument({
        size:          'A4',
        autoFirstPage: true,
        bufferPages:   true,   // Required for page numbers via switchToPage
        margins: {
          top:    MARGIN,
          bottom: MARGIN,
          left:   MARGIN,
          right:  MARGIN,
        },
        info: {
          Title:    'CyberGuard Security Assessment Report',
          Author:   'CyberGuard Automated Scanner',
          Subject:  `Security Assessment: ${scanResult.target}`,
          Keywords: 'security, assessment, web, https, tls, headers, cookies',
          Creator:  'CyberGuard v1.0',
        },
      });

      doc.on('data',  (chunk) => chunks.push(chunk));
      doc.on('end',   () => resolve(Buffer.concat(chunks)));
      doc.on('error', (err) => reject(err));

      // ── Cover page ──────────────────────────────────────────────────────
      writeCover(doc, scanResult);

      // ── Content pages ───────────────────────────────────────────────────
      doc.addPage();
      let y = MARGIN;

      y = writeExecutiveSummary(doc, scanResult, y);
      y += 14;
      y = writeTargetInfo(doc, scanResult, y);
      y += 14;
      y = writeTlsSection(doc, scanResult, y);
      y += 14;
      y = writeHeadersSection(doc, scanResult, y);
      y += 14;
      y = writeDisclosureSection(doc, scanResult, y);
      y += 14;
      y = writeCookieSection(doc, scanResult, y);
      y += 14;
      y = writeFindingsSection(doc, scanResult, y);
      y += 14;
      y = writeRecommendations(doc, scanResult, y);
      y += 14;
      writeDisclaimer(doc, y);

      // ── Page numbers (skip cover) ────────────────────────────────────────
      addPageNumbers(doc);

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = {
  sanitizeScanResult,
  generateReport,
  sanitizeFilename,
  // Exported for unit testing
  safeStr,
};
