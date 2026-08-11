'use strict';

const tls = require('tls');

// Time limit for the TLS handshake + certificate retrieval
const TLS_TIMEOUT_MS = 8_000;

// Days remaining at which we consider a certificate "expiring soon"
const EXPIRY_WARNING_DAYS = 30;

/**
 * Calculates how many full days remain until a certificate expires.
 * Returns 0 if the date is in the past (already expired).
 *
 * Exported so it can be unit-tested with mock date strings.
 *
 * @param {string} validTo - The cert's valid_to string (as returned by Node's TLS API).
 * @returns {number}
 */
function calcDaysRemaining(validTo) {
  const expiryMs = new Date(validTo).getTime();
  const nowMs = Date.now();
  const diffMs = expiryMs - nowMs;
  return diffMs <= 0 ? 0 : Math.floor(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Checks whether the certificate is valid for the given hostname using
 * Node's built-in tls.checkServerIdentity(), which implements RFC 2818 /
 * RFC 6125 hostname matching (including wildcard SANs and the CN fallback).
 *
 * Exported for unit testing.
 *
 * @param {string} hostname
 * @param {object} cert - Peer certificate object from getPeerCertificate()
 * @returns {boolean}
 */
function checkHostnameValid(hostname, cert) {
  try {
    // Returns undefined when the hostname matches, an Error when it does not.
    const mismatch = tls.checkServerIdentity(hostname, cert);
    return mismatch === undefined;
  } catch {
    return false;
  }
}

/**
 * Formats a certificate name object (subject or issuer) into a human-readable
 * string. Prefers the Common Name (CN); falls back to the Organisation (O).
 *
 * @param {object|undefined} nameObj - e.g. { CN: 'example.com', O: 'ICANN', C: 'US' }
 * @returns {string|null}
 */
function formatName(nameObj) {
  if (!nameObj || typeof nameObj !== 'object') return null;
  return nameObj.CN || nameObj.O || null;
}

/**
 * Converts a low-level TLS/socket error into a safe, user-facing message
 * without exposing internal codes or stack traces.
 *
 * @param {Error} err
 * @returns {string}
 */
function buildTlsErrorMessage(err) {
  const messages = {
    ECONNREFUSED:  'TLS connection was refused by the target.',
    ECONNRESET:    'TLS connection was reset by the target.',
    ETIMEDOUT:     'TLS connection timed out.',
    ENOTFOUND:     'TLS target hostname could not be resolved.',
    EPROTO:        'A TLS protocol error occurred.',
  };
  return messages[err.code] || 'TLS certificate could not be inspected.';
}

/**
 * Extracts and structures certificate metadata from an established TLS socket.
 * Returns a structured tls result object.
 *
 * @param {tls.TLSSocket} socket
 * @param {string} hostname
 * @returns {object}
 */
function extractTlsInfo(socket, hostname) {
  const cert = socket.getPeerCertificate(false);

  // getPeerCertificate returns {} when no cert is available
  if (!cert || !cert.subject) {
    return {
      analyzed: true,
      status: 'error',
      message: 'TLS certificate could not be inspected.',
    };
  }

  const validTo = cert.valid_to;
  const daysRemaining = calcDaysRemaining(validTo);
  const expired = daysRemaining === 0 && new Date(validTo) < new Date();
  const expiringSoon = !expired && daysRemaining <= EXPIRY_WARNING_DAYS;

  return {
    analyzed: true,
    protocol: socket.getProtocol() || null,
    certificate: {
      subject:       formatName(cert.subject),
      issuer:        formatName(cert.issuer),
      validFrom:     new Date(cert.valid_from).toISOString(),
      validTo:       new Date(validTo).toISOString(),
      expired,
      expiringSoon,
      daysRemaining,
      hostnameValid: checkHostnameValid(hostname, cert),
    },
  };
}

/**
 * Performs TLS analysis on an HTTPS URL.
 *
 * For HTTP URLs, returns immediately with analyzed: false — no connection
 * is made and no SSRF concern is introduced.
 *
 * For HTTPS URLs, opens a raw TLS socket (separate from the main HTTP scan)
 * with rejectUnauthorized: false so that certificates can be inspected even
 * when expired or self-signed. We use the SNI servername so virtual-hosted
 * servers return the correct certificate.
 *
 * NOTE: The caller (scannerService) is responsible for SSRF validation of the
 * hostname before calling this function. Do not call scanTls() with an
 * unvalidated URL.
 *
 * @param {string} url - A pre-validated URL (must have already passed SSRF checks).
 * @returns {Promise<object>} TLS result object.
 */
async function scanTls(url) {
  const parsed = new URL(url);

  if (parsed.protocol !== 'https:') {
    return {
      analyzed: false,
      reason: 'Target uses HTTP',
    };
  }

  const hostname = parsed.hostname;
  const port = parseInt(parsed.port, 10) || 443;

  return new Promise((resolve) => {
    let settled = false;

    // Ensure resolve is only called once, even if multiple events fire
    const finish = (result) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    const errorResult = (message) =>
      finish({ analyzed: true, status: 'error', message });

    // Hard timeout — destroy the socket if the handshake stalls
    const timer = setTimeout(() => {
      socket.destroy();
      errorResult('TLS connection timed out.');
    }, TLS_TIMEOUT_MS);

    // rejectUnauthorized: false lets us inspect expired/self-signed certs.
    // We report the validation result in the certificate.hostnameValid field
    // rather than refusing to connect.
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname, // SNI — required for virtual hosting
        rejectUnauthorized: false,
      },
      () => {
        // Callback fires on 'secureConnect' — handshake is complete
        clearTimeout(timer);
        try {
          const result = extractTlsInfo(socket, hostname);
          socket.destroy();
          finish(result);
        } catch {
          socket.destroy();
          errorResult('TLS certificate could not be inspected.');
        }
      }
    );

    socket.on('error', (err) => {
      clearTimeout(timer);
      errorResult(buildTlsErrorMessage(err));
    });

    socket.on('timeout', () => {
      clearTimeout(timer);
      socket.destroy();
      errorResult('TLS connection timed out.');
    });
  });
}

module.exports = { scanTls, calcDaysRemaining, checkHostnameValid, EXPIRY_WARNING_DAYS };
