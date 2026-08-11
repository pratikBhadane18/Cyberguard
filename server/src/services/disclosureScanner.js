'use strict';

/**
 * Information Disclosure / Technology Exposure Scanner
 *
 * Examines response headers for server, framework, CMS, or proxy technology
 * identification headers. All findings are categorized as LOW severity
 * hardening recommendations.
 *
 * No external network calls, CVE database lookups, or active fingerprinting are
 * performed.
 */

// Maximum character length for header value evidence
const MAX_EVIDENCE_LENGTH = 150;

/**
 * Known technology-disclosure header definitions and normalized metadata.
 */
const DISCLOSURE_HEADER_DEFINITIONS = [
  {
    headerName: 'server',
    id: 'server-technology-disclosure',
    title: 'Server Technology Information Disclosed',
    description: (val) =>
      /\d/.test(val)
        ? `The Server response header exposes server technology and version information: "${val}".`
        : `The Server response header exposes server technology information: "${val}".`,
    impact: 'Technology disclosure may assist reconnaissance and attack-surface identification.',
    recommendation: 'Consider minimizing unnecessary server and version information in response headers.',
  },
  {
    headerName: 'x-powered-by',
    id: 'powered-by-technology-disclosure',
    title: 'Application Technology Information Disclosed',
    description: (val) =>
      `The X-Powered-By header discloses underlying application framework or technology: "${val}".`,
    impact: 'Application framework information may assist reconnaissance.',
    recommendation: 'Consider removing unnecessary framework-identification headers.',
  },
  {
    headerName: 'x-aspnet-version',
    id: 'aspnet-version-disclosure',
    title: 'ASP.NET Version Information Disclosed',
    description: (val) =>
      `The X-AspNet-Version header discloses specific ASP.NET framework version details: "${val}".`,
    impact: 'Specific framework version disclosure assists targeted attack-surface mapping.',
    recommendation: 'Disable X-AspNet-Version in Web.config or HTTP response settings.',
  },
  {
    headerName: 'x-aspnetmvc-version',
    id: 'aspnetmvc-version-disclosure',
    title: 'ASP.NET MVC Version Information Disclosed',
    description: (val) =>
      `The X-AspNetMvc-Version header discloses ASP.NET MVC framework version details: "${val}".`,
    impact: 'MVC version disclosure assists targeted reconnaissance.',
    recommendation: 'Disable MvcHeader in MvcHandler settings or server configuration.',
  },
  {
    headerName: 'x-generator',
    id: 'generator-disclosure',
    title: 'Technology Generator Information Disclosed',
    description: (val) =>
      `The X-Generator header discloses CMS or content generation software details: "${val}".`,
    impact: 'CMS or site generator details assist technology fingerprinting.',
    recommendation: 'Remove or suppress X-Generator response headers.',
  },
  {
    headerName: 'via',
    id: 'via-disclosure',
    title: 'Proxy / Via Header Information Disclosed',
    description: (val) =>
      `The Via response header reveals internal proxy, gateway, or CDN network hops: "${val}".`,
    impact: 'Exposes proxy topology and intermediate gateway software details.',
    recommendation: 'Configure proxies or CDNs to suppress or obfuscate Via headers if appropriate.',
  },
  {
    headerName: 'x-drupal-cache',
    id: 'drupal-cache-disclosure',
    title: 'Drupal Cache Information Disclosed',
    description: (val) =>
      `The X-Drupal-Cache header reveals underlying Drupal CMS usage and caching state: "${val}".`,
    impact: 'CMS-specific headers assist automated technology fingerprinting.',
    recommendation: 'Remove or mask Drupal-specific response headers in production.',
  },
];

/**
 * Converts a raw headers object into a Map with lower-cased keys.
 *
 * @param {object} headers
 * @returns {Map<string, string>}
 */
function normalizeHeaders(headers) {
  const map = new Map();
  for (const [k, v] of Object.entries(headers || {})) {
    if (typeof k === 'string' && v != null) {
      map.set(k.toLowerCase(), String(v).trim());
    }
  }
  return map;
}

/**
 * Truncates and cleans string values for evidence display.
 *
 * @param {string} val
 * @returns {string}
 */
function safeTruncate(val) {
  if (!val) return '';
  const cleaned = String(val).replace(/[\x00-\x1f\x7f]/g, '').trim();
  if (cleaned.length <= MAX_EVIDENCE_LENGTH) return cleaned;
  return cleaned.slice(0, MAX_EVIDENCE_LENGTH) + '...';
}

/**
 * Analyzes raw HTTP response headers for technology disclosure headers.
 *
 * Header matching is case-insensitive.
 * All findings are assigned LOW severity.
 *
 * @param {object} rawHeaders - HTTP response headers object
 * @returns {object} Analysis result
 */
function analyzeDisclosure(rawHeaders) {
  const headerMap = normalizeHeaders(rawHeaders);
  const findings = [];

  for (const def of DISCLOSURE_HEADER_DEFINITIONS) {
    if (headerMap.has(def.headerName)) {
      const rawVal = headerMap.get(def.headerName);
      const safeVal = safeTruncate(rawVal);

      // Preserve canonical header display casing for title/evidence
      const displayHeader = def.headerName
        .split('-')
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join('-');

      findings.push({
        id: def.id,
        category: 'information-disclosure',
        title: def.title,
        severity: 'LOW',
        header: displayHeader,
        value: safeVal,
        description: def.description(safeVal),
        impact: def.impact,
        recommendation: def.recommendation,
        evidence: `${displayHeader}: ${safeVal}`,
      });
    }
  }

  return {
    analyzed: true,
    count: findings.length,
    findings,
  };
}

module.exports = {
  analyzeDisclosure,
  // Exported for deterministic unit testing
  DISCLOSURE_HEADER_DEFINITIONS,
};
