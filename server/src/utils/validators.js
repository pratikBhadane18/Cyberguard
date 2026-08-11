/**
 * Validates that a string is a properly formatted HTTP or HTTPS URL.
 *
 * This is the first line of protocol defence: it rejects file://, ftp://,
 * javascript:, data:, and any other scheme before DNS resolution or network
 * activity occurs.
 *
 * @param {string} url
 * @returns {boolean}
 */
function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Checks whether a hostname is an obviously internal/local name that should
 * be blocked without even attempting DNS resolution.
 *
 * This is a supplementary control. The primary SSRF defence is DNS pre-
 * resolution in ipValidator.js. This function catches cases where the OS
 * resolver might resolve a name to a private IP but the caller would rather
 * reject it early (e.g. "localhost", "myserver.local").
 *
 * Blocked patterns:
 *   - "localhost" (exact, case-insensitive)
 *   - *.local    (mDNS / Bonjour names)
 *   - *.internal (common corporate convention)
 *   - *.corp     (common corporate convention)
 *   - *.lan      (home/office LAN names)
 *   - *.home     (home router convention)
 *   - *.localdomain
 *   - *.intranet
 *
 * @param {string} hostname
 * @returns {boolean}
 */
function isBlockedHostname(hostname) {
  const lower = hostname.toLowerCase();

  if (lower === 'localhost') return true;

  const blockedSuffixes = [
    '.local',
    '.internal',
    '.corp',
    '.lan',
    '.home',
    '.localdomain',
    '.intranet',
  ];

  return blockedSuffixes.some((suffix) => lower.endsWith(suffix));
}

module.exports = { isValidUrl, isBlockedHostname };
