'use strict';

/**
 * Cookie Security Scanner
 *
 * Parses and analyzes Set-Cookie response headers for security attribute
 * configuration. All cookie VALUES are redacted — only names and attributes
 * are surfaced. No network requests are made here; headers come from the
 * existing HTTP response in scannerService.
 */

// ── Session-cookie heuristic ─────────────────────────────────────────────────

/**
 * Exact-match set of cookie names (lower-cased) that are commonly used for
 * session or authentication state.
 *
 * This heuristic is intentionally conservative. A match here does NOT confirm
 * that the cookie is an authentication cookie — it is a signal only. The
 * findings always use qualified language ("likely session", "appears to be").
 */
const SESSION_COOKIE_NAMES = new Set([
  'session',
  'sessionid',
  'session_id',
  'connect.sid',
  'sid',
  'auth',
  'auth_token',
  'access_token',
  'refresh_token',
  'jwt',
  'token',
  '__session',
  'csrftoken',
  'csrf_token',
  'bearer',
  'id_token',
  'user_token',
]);

/**
 * Returns true if the cookie name matches a known session/auth pattern.
 * Comparison is case-insensitive.
 *
 * @param {string} name
 * @returns {boolean}
 */
function isLikelySessionCookie(name) {
  return SESSION_COOKIE_NAMES.has(name.toLowerCase());
}

// ── Cookie parser ────────────────────────────────────────────────────────────

/**
 * Parses a single raw Set-Cookie header string into a structured object.
 *
 * The cookie VALUE is always replaced with '[REDACTED]' — it is never stored
 * or returned to callers. Only the name and attributes are preserved.
 *
 * Attribute names are compared case-insensitively per RFC 6265.
 *
 * @param {string} raw - e.g. "session=abc123; HttpOnly; Secure; SameSite=Lax"
 * @returns {object}
 */
function parseCookie(raw) {
  // Split on ';'. Note: Expires values contain commas but NOT semicolons,
  // so splitting on ';' is safe and preserves the Expires date string.
  const parts = raw.split(';').map((p) => p.trim()).filter(Boolean);

  // First segment is name=value (or just a name if there is no '=')
  const nameValuePart = parts[0] ?? '';
  const eqIdx = nameValuePart.indexOf('=');
  const name = (eqIdx === -1 ? nameValuePart : nameValuePart.slice(0, eqIdx)).trim();
  // Value is deliberately not stored.

  // Attribute defaults
  const attrs = {
    secure:   false,
    httpOnly: false,
    sameSite: null,  // string | null
    path:     null,
    domain:   null,
    maxAge:   null,  // number | null
    expires:  null,  // string | null
  };

  // Parse attributes (parts[1..])
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const lowerPart = part.toLowerCase();

    if (lowerPart === 'secure') {
      attrs.secure = true;
    } else if (lowerPart === 'httponly') {
      attrs.httpOnly = true;
    } else if (lowerPart.startsWith('samesite=')) {
      // Preserve original casing of the value for display; compare lower
      attrs.sameSite = part.slice('samesite='.length).trim();
    } else if (lowerPart.startsWith('path=')) {
      attrs.path = part.slice('path='.length).trim();
    } else if (lowerPart.startsWith('domain=')) {
      attrs.domain = part.slice('domain='.length).trim();
    } else if (lowerPart.startsWith('max-age=')) {
      const n = parseInt(part.slice('max-age='.length).trim(), 10);
      attrs.maxAge = isNaN(n) ? null : n;
    } else if (lowerPart.startsWith('expires=')) {
      attrs.expires = part.slice('expires='.length).trim();
    }
    // Unknown attributes are silently ignored
  }

  return {
    name: name || '(unnamed)',
    redactedValue: '[REDACTED]',
    likelySession: isLikelySessionCookie(name),
    ...attrs,
  };
}

// ── Security analyzers ───────────────────────────────────────────────────────

/**
 * Analyzes a parsed cookie object and returns an array of security findings.
 *
 * Severity scale (consistent with other CyberGuard scanners):
 *   INFO   — informational; no expected negative impact
 *   LOW    — hardening recommendation for non-session cookies
 *   MEDIUM — hardening recommendation for likely session/auth cookies,
 *             or a clear misconfiguration (e.g. SameSite=None without Secure)
 *
 * HIGH and CRITICAL are NOT used; attribute issues alone are hardening
 * findings, not confirmed vulnerabilities.
 *
 * @param {object} cookie - Parsed cookie from parseCookie()
 * @returns {Array<object>} findings
 */
function analyzeCookieSecurity(cookie) {
  const findings = [];
  const session  = cookie.likelySession;

  // ── Secure attribute ────────────────────────────────────────────────────
  if (!cookie.secure) {
    findings.push({
      attribute: 'Secure',
      status: 'missing',
      severity: session ? 'MEDIUM' : 'LOW',
      description: session
        ? `"${cookie.name}" appears to be a session or authentication cookie, ` +
          'but the Secure attribute is missing. HTTPS-only cookie transmission ' +
          'is not explicitly enforced.'
        : `"${cookie.name}" does not have the Secure attribute. ` +
          'The cookie may be transmitted over unencrypted connections.',
      recommendation: 'Add the Secure attribute so the cookie is only sent over HTTPS.',
    });
  }

  // ── HttpOnly attribute ──────────────────────────────────────────────────
  if (!cookie.httpOnly) {
    findings.push({
      attribute: 'HttpOnly',
      status: 'missing',
      severity: session ? 'MEDIUM' : 'LOW',
      description: session
        ? `"${cookie.name}" appears to be a session or authentication cookie ` +
          'without HttpOnly. Client-side JavaScript may be able to access this cookie.'
        : `"${cookie.name}" does not have the HttpOnly attribute. ` +
          'Client-side scripts can read its value.',
      recommendation:
        'Add the HttpOnly attribute to prevent client-side script access.',
    });
  }

  // ── SameSite attribute ──────────────────────────────────────────────────
  if (!cookie.sameSite) {
    findings.push({
      attribute: 'SameSite',
      status: 'missing',
      severity: 'LOW',
      description:
        `"${cookie.name}" has no SameSite attribute. SameSite provides an ` +
        'additional defense against certain cross-site request scenarios. ' +
        'Without it, browsers may apply a default (typically Lax for navigation).',
      recommendation:
        'Add SameSite=Lax or SameSite=Strict where appropriate.',
    });
  } else if (cookie.sameSite.toLowerCase() === 'none') {
    if (!cookie.secure) {
      // SameSite=None without Secure is rejected by modern browsers
      findings.push({
        attribute: 'SameSite',
        status: 'misconfigured',
        severity: 'MEDIUM',
        description:
          `"${cookie.name}" has SameSite=None without the Secure attribute. ` +
          'Modern browsers reject SameSite=None cookies that are not also marked Secure, ' +
          'which may cause the cookie to be dropped entirely.',
        recommendation:
          'Add the Secure attribute when using SameSite=None.',
      });
    }
    // SameSite=None with Secure is valid (e.g. cross-site embeds) — no finding
  }
  // SameSite=Strict or SameSite=Lax with valid Secure/HttpOnly → no finding

  return findings;
}

// ── Set-Cookie header extraction ─────────────────────────────────────────────

/**
 * Extracts all Set-Cookie header strings from an Axios response headers object.
 *
 * Node's http.IncomingMessage stores the 'set-cookie' header as an array
 * (since multiple values are allowed). Axios preserves this. We also handle
 * the edge case where a proxy or test fixture provides a single string.
 *
 * @param {object} headers - Raw response headers object.
 * @returns {string[]}
 */
function extractSetCookieHeaders(headers) {
  // Normalize to lowercase key lookup
  const normalized = {};
  for (const [k, v] of Object.entries(headers || {})) {
    normalized[k.toLowerCase()] = v;
  }

  const raw = normalized['set-cookie'];
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.map(String);
  return [String(raw)];
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Analyzes all Set-Cookie headers from an HTTP response and returns
 * structured security findings for each cookie.
 *
 * Cookie values are ALWAYS redacted — '[REDACTED]' is returned in place of
 * any actual value. Only names, attributes, and findings are surfaced.
 *
 * No additional HTTP requests are made. The caller supplies the headers
 * from the existing response.
 *
 * @param {object} rawHeaders - HTTP response headers (from Axios response.headers).
 * @returns {object}
 */
function analyzeCookies(rawHeaders) {
  const rawCookies = extractSetCookieHeaders(rawHeaders);

  if (rawCookies.length === 0) {
    return {
      analyzed: true,
      count: 0,
      cookies: [],
    };
  }

  const cookies = rawCookies.map((raw) => {
    const parsed   = parseCookie(raw);
    const findings = analyzeCookieSecurity(parsed);
    return { ...parsed, findings };
  });

  return {
    analyzed: true,
    count: cookies.length,
    cookies,
  };
}

module.exports = {
  analyzeCookies,
  // Exported for unit testing
  parseCookie,
  analyzeCookieSecurity,
  isLikelySessionCookie,
  extractSetCookieHeaders,
};
