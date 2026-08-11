'use strict';

// Minimum HSTS max-age we consider acceptable (1 year in seconds)
const HSTS_MIN_MAX_AGE = 31_536_000;

// All valid Referrer-Policy token values per the W3C spec
const VALID_REFERRER_POLICIES = new Set([
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
  '',          // empty string is spec-valid (browser default)
]);

// Only these two values are defined by the X-Frame-Options spec
const VALID_XFO_VALUES = new Set(['DENY', 'SAMEORIGIN']);

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Converts a raw headers object into a Map keyed by lower-cased name.
 * Handles both plain objects (from Axios) and objects with mixed-case keys.
 *
 * @param {object} headers
 * @returns {Map<string, string>}
 */
function normalizeHeaders(headers) {
  const map = new Map();
  for (const [k, v] of Object.entries(headers || {})) {
    map.set(k.toLowerCase(), String(v));
  }
  return map;
}

/** @param {Map} map @param {string} name @returns {string|null} */
const get = (map, name) => map.get(name.toLowerCase()) ?? null;

// ── Individual header analyzers ──────────────────────────────────────────────

/**
 * Analyzes Strict-Transport-Security.
 *
 * Limitation: HSTS is only meaningful over HTTPS. For HTTP targets the header
 * is delivered but browsers ignore it — we mark it not_applicable. Even for
 * HTTPS targets, HSTS only protects users AFTER their browser has cached the
 * policy; first-visit protection requires HSTS preloading, which is out of
 * scope here.
 *
 * @param {string|null} value
 * @param {boolean} isHttps - Whether the final response URL was HTTPS.
 */
function analyzeHsts(value, isHttps) {
  if (!isHttps) {
    return {
      header: 'Strict-Transport-Security',
      status: 'not_applicable',
      severity: 'INFO',
      value: value ?? null,
      description:
        'HSTS headers sent over plain HTTP are ignored by browsers. ' +
        'HSTS must be delivered from an HTTPS response to take effect.',
      recommendation:
        'Ensure your HTTPS endpoint sends a valid HSTS header. Do not rely on an HTTP response to set HSTS.',
    };
  }

  if (!value) {
    return {
      header: 'Strict-Transport-Security',
      status: 'missing',
      severity: 'MEDIUM',
      value: null,
      description:
        'Strict-Transport-Security is not set on this HTTPS response. ' +
        'Without HSTS, browsers may make initial plain-HTTP requests before being redirected to HTTPS.',
      recommendation:
        'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
    };
  }

  // Parse max-age (required directive)
  const match = /max-age\s*=\s*(\d+)/i.exec(value);
  if (!match) {
    return {
      header: 'Strict-Transport-Security',
      status: 'invalid',
      severity: 'LOW',
      value,
      description:
        'HSTS header is present but does not contain a valid max-age directive, ' +
        'which is required by the spec.',
      recommendation:
        'Add a max-age directive: Strict-Transport-Security: max-age=31536000; includeSubDomains',
    };
  }

  const maxAge = parseInt(match[1], 10);
  if (maxAge < HSTS_MIN_MAX_AGE) {
    const days = Math.floor(maxAge / 86_400);
    return {
      header: 'Strict-Transport-Security',
      status: 'weak',
      severity: 'LOW',
      value,
      description:
        `HSTS max-age is ${maxAge}s (${days} day${days === 1 ? '' : 's'}), ` +
        `below the recommended minimum of 1 year (${HSTS_MIN_MAX_AGE}s).`,
      recommendation:
        'Increase max-age to at least 31536000 (1 year). Consider adding includeSubDomains.',
    };
  }

  const days = Math.floor(maxAge / 86_400);
  return {
    header: 'Strict-Transport-Security',
    status: 'present',
    severity: 'INFO',
    value,
    description: `HSTS is configured with max-age of ${maxAge}s (${days} days).`,
    recommendation: null,
  };
}

/**
 * Analyzes Content-Security-Policy.
 *
 * Performs lightweight heuristic checks only — not a full CSP parser.
 * Weak-directive detection is intentionally conservative: the presence of
 * 'unsafe-inline', 'unsafe-eval', or a standalone wildcard source is flagged
 * as a potential weakness, not as a confirmed vulnerability.
 *
 * @param {string|null} value
 */
function analyzeCsp(value) {
  if (!value) {
    return {
      header: 'Content-Security-Policy',
      status: 'missing',
      severity: 'MEDIUM',
      value: null,
      description:
        'Content-Security-Policy header is not set. A missing CSP does not ' +
        'automatically mean the site is exploitable, but CSP is an important ' +
        'defense-in-depth layer against content-injection attacks.',
      recommendation:
        'Define a Content-Security-Policy that is appropriate for your application.',
    };
  }

  const weaknesses = [];

  if (/'unsafe-inline'/.test(value))    weaknesses.push("'unsafe-inline'");
  if (/'unsafe-eval'/.test(value))      weaknesses.push("'unsafe-eval'");

  // Standalone wildcard source: e.g. "script-src *" or "default-src *"
  // Intentionally does NOT flag *.example.com (wildcard subdomain).
  if (/(?:^|[\s;,])\*(?:$|[\s;,])/.test(value)) weaknesses.push('wildcard source (*)');

  if (weaknesses.length > 0) {
    return {
      header: 'Content-Security-Policy',
      status: 'weak',
      severity: 'LOW',
      value,
      description:
        `CSP is present but contains potentially permissive directives: ` +
        `${weaknesses.join(', ')}. These may reduce the policy's effectiveness in some scenarios.`,
      recommendation:
        'Review and tighten CSP directives. Avoid unsafe-inline and unsafe-eval where possible.',
    };
  }

  return {
    header: 'Content-Security-Policy',
    status: 'present',
    severity: 'INFO',
    value,
    description:
      'Content-Security-Policy is configured without obviously weak directives detected.',
    recommendation: null,
  };
}

/**
 * Analyzes X-Frame-Options.
 *
 * Also inspects the CSP value for a frame-ancestors directive, which provides
 * equivalent or stronger framing control in modern browsers. Sites using
 * frame-ancestors in their CSP are not penalised for omitting X-Frame-Options.
 *
 * @param {string|null} value
 * @param {string|null} cspValue - The raw CSP header, used to check for frame-ancestors.
 */
function analyzeXFrameOptions(value, cspValue) {
  const hasFrameAncestors = cspValue != null && /frame-ancestors/i.test(cspValue);

  if (!value) {
    if (hasFrameAncestors) {
      return {
        header: 'X-Frame-Options',
        status: 'not_applicable',
        severity: 'INFO',
        value: null,
        description:
          'X-Frame-Options is absent, but the Content-Security-Policy contains a ' +
          'frame-ancestors directive, which provides equivalent or stronger framing ' +
          'control in modern browsers.',
        recommendation: null,
      };
    }

    return {
      header: 'X-Frame-Options',
      status: 'missing',
      severity: 'LOW',
      value: null,
      description:
        'X-Frame-Options is not set and no frame-ancestors CSP directive was detected. ' +
        'This is a hardening recommendation — a missing header does not confirm a ' +
        'clickjacking vulnerability.',
      recommendation:
        'Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.',
    };
  }

  // The spec defines values case-insensitively; normalise before checking.
  if (!VALID_XFO_VALUES.has(value.trim().toUpperCase())) {
    return {
      header: 'X-Frame-Options',
      status: 'invalid',
      severity: 'LOW',
      value,
      description: `X-Frame-Options value "${value}" is not a recognised standard value.`,
      recommendation: 'Use DENY or SAMEORIGIN.',
    };
  }

  return {
    header: 'X-Frame-Options',
    status: 'present',
    severity: 'INFO',
    value,
    description: `X-Frame-Options is set to ${value.trim().toUpperCase()}.`,
    recommendation: null,
  };
}

/**
 * Analyzes X-Content-Type-Options.
 * The only standardised value is "nosniff".
 *
 * @param {string|null} value
 */
function analyzeXContentTypeOptions(value) {
  if (!value) {
    return {
      header: 'X-Content-Type-Options',
      status: 'missing',
      severity: 'LOW',
      value: null,
      description:
        'X-Content-Type-Options is not set. This header prevents browsers from ' +
        'MIME-type sniffing a response away from the declared Content-Type, which ' +
        'can reduce exposure to certain content-injection risks.',
      recommendation: 'Add X-Content-Type-Options: nosniff.',
    };
  }

  if (value.trim().toLowerCase() !== 'nosniff') {
    return {
      header: 'X-Content-Type-Options',
      status: 'invalid',
      severity: 'LOW',
      value,
      description:
        `X-Content-Type-Options is set to "${value}", which is not the ` +
        `standard "nosniff" value and will be ignored by browsers.`,
      recommendation: 'Set X-Content-Type-Options: nosniff.',
    };
  }

  return {
    header: 'X-Content-Type-Options',
    status: 'present',
    severity: 'INFO',
    value,
    description: 'X-Content-Type-Options: nosniff is correctly configured.',
    recommendation: null,
  };
}

/**
 * Analyzes Referrer-Policy.
 * Multi-value policies (comma-separated fallback list) are handled.
 *
 * @param {string|null} value
 */
function analyzeReferrerPolicy(value) {
  if (!value) {
    return {
      header: 'Referrer-Policy',
      status: 'missing',
      severity: 'LOW',
      value: null,
      description:
        'Referrer-Policy is not set. Without an explicit policy the browser default ' +
        'applies (typically no-referrer-when-downgrade). This is a hardening ' +
        'recommendation, not a confirmed vulnerability.',
      recommendation:
        'Add a Referrer-Policy such as: strict-origin-when-cross-origin.',
    };
  }

  // Per spec, comma-separated list of policies (fallback chain)
  const tokens = value.split(',').map((t) => t.trim().toLowerCase());
  const invalid = tokens.filter((t) => !VALID_REFERRER_POLICIES.has(t));

  if (invalid.length > 0) {
    return {
      header: 'Referrer-Policy',
      status: 'invalid',
      severity: 'LOW',
      value,
      description: `Referrer-Policy contains unrecognised token(s): ${invalid.join(', ')}.`,
      recommendation:
        'Use a recognised policy value such as strict-origin-when-cross-origin.',
    };
  }

  return {
    header: 'Referrer-Policy',
    status: 'present',
    severity: 'INFO',
    value,
    description: `Referrer-Policy is configured: ${value}.`,
    recommendation: null,
  };
}

/**
 * Analyzes Permissions-Policy.
 *
 * For this version we detect presence/absence and surface the configured value.
 * Judging the completeness of every possible feature directive is out of scope.
 *
 * @param {string|null} value
 */
function analyzePermissionsPolicy(value) {
  if (!value) {
    return {
      header: 'Permissions-Policy',
      status: 'missing',
      severity: 'INFO',
      value: null,
      description:
        'Permissions-Policy is not set. This header restricts browser feature and API ' +
        'access. Its absence is a hardening opportunity rather than a confirmed weakness.',
      recommendation:
        'Consider adding a Permissions-Policy header to restrict unnecessary browser feature access.',
    };
  }

  return {
    header: 'Permissions-Policy',
    status: 'present',
    severity: 'INFO',
    value,
    description: 'Permissions-Policy header is configured.',
    recommendation: null,
  };
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Analyzes a raw HTTP response headers object for security-relevant configuration.
 *
 * All header names are handled case-insensitively. Headers are read from the
 * existing HTTP response — no additional network request is made.
 *
 * Severity scale:
 *   INFO   — header is well-configured, or absence is purely advisory.
 *   LOW    — header is missing or misconfigured; security hardening recommendation.
 *   MEDIUM — header is absent and provides meaningful defense-in-depth (e.g. CSP, HSTS).
 *
 * We intentionally do not use HIGH or CRITICAL for missing headers: their
 * absence indicates a hardening gap, not necessarily a confirmed exploitable flaw.
 *
 * @param {object} rawHeaders - HTTP response headers (e.g. from Axios response.headers).
 * @param {boolean} isHttps   - Whether the final response was delivered over HTTPS.
 * @returns {object} Header analysis result.
 */
function analyzeHeaders(rawHeaders, isHttps) {
  const headers = normalizeHeaders(rawHeaders);

  const hsts = get(headers, 'strict-transport-security');
  const csp  = get(headers, 'content-security-policy');
  const xfo  = get(headers, 'x-frame-options');
  const xcto = get(headers, 'x-content-type-options');
  const rp   = get(headers, 'referrer-policy');
  const pp   = get(headers, 'permissions-policy');

  return {
    analyzed: true,
    findings: [
      analyzeHsts(hsts, isHttps),
      analyzeCsp(csp),
      analyzeXFrameOptions(xfo, csp),
      analyzeXContentTypeOptions(xcto),
      analyzeReferrerPolicy(rp),
      analyzePermissionsPolicy(pp),
    ],
  };
}

module.exports = {
  analyzeHeaders,
  // Individual analyzers exported for deterministic unit testing
  analyzeHsts,
  analyzeCsp,
  analyzeXFrameOptions,
  analyzeXContentTypeOptions,
  analyzeReferrerPolicy,
  analyzePermissionsPolicy,
};
