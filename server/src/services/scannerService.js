const axios = require('axios');
const { SsrfError } = require('../errors/SsrfError');
const { isValidUrl, isBlockedHostname } = require('../utils/validators');
const { resolveAndValidate } = require('../utils/ipValidator');
const tlsScanner = require('./tlsScanner');
const headerScanner = require('./headerScanner');
const cookieScanner = require('./cookieScanner');
const disclosureScanner = require('./disclosureScanner');
const riskAnalyzer = require('./riskAnalyzer');

// Maximum time (ms) to wait for the target to respond
const REQUEST_TIMEOUT_MS = 10_000;

// Maximum number of redirects we will follow manually
const MAX_REDIRECTS = 5;

// Maximum response body size (bytes). We only use headers, so keep this tight.
// 10 MB is generous enough for any real target but prevents memory exhaustion.
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

/**
 * Performs a basic HTTP GET scan of the target URL.
 *
 * Security controls applied before each request (initial + every redirect hop):
 *   1. Protocol allow-list  — isValidUrl() rejects non-http(s) schemes
 *   2. Hostname blocklist   — isBlockedHostname() rejects obvious internal names
 *   3. DNS pre-resolution   — resolveAndValidate() rejects private/reserved IPs
 *
 * Redirects are followed manually so every hop passes all three controls.
 * maxRedirects is set to 0 in Axios so we receive the 3xx response directly
 * and decide ourselves whether to follow.
 *
 * ⚠️  DNS-rebinding: see ipValidator.js for the documented limitation.
 *
 * @param {string} url - A pre-validated HTTP/HTTPS URL.
 * @returns {Promise<object>} Structured scan result.
 */
async function performScan(url) {
  const startTime = Date.now();

  // --- Initial pre-flight checks on the supplied URL ---
  await validateTarget(url);

  // --- Manual redirect-following loop ---
  let currentUrl = url;
  let response;
  let hops = 0;

  while (true) {
    response = await makeRequest(currentUrl);

    const isRedirect =
      response.status >= 300 &&
      response.status < 400 &&
      response.headers['location'];

    if (!isRedirect || hops >= MAX_REDIRECTS) {
      // Not a redirect, or we've reached the hop limit — stop here.
      break;
    }

    // Resolve the Location header to an absolute URL, then validate it
    // through the full SSRF control stack before following.
    const rawLocation = response.headers['location'];
    let redirectUrl;
    try {
      redirectUrl = new URL(rawLocation, currentUrl).toString();
    } catch {
      // Malformed Location header — stop following
      break;
    }

    await validateTarget(redirectUrl);

    currentUrl = redirectUrl;
    hops++;
  }

  const responseTime = Date.now() - startTime;
  const isHttps = url.startsWith('https://');
  // Use the final URL's scheme for HSTS analysis context: a redirect from
  // HTTP → HTTPS means the headers we inspect came from an HTTPS response.
  const finalIsHttps = currentUrl.startsWith('https://');

  // Detect whether an HTTP target redirected to HTTPS through the safe
  // redirect chain (redirect validation already ran above).
  const redirectsToHttps =
    !isHttps && currentUrl.startsWith('https://') ? true : undefined;

  // TLS analysis runs after SSRF validation has already cleared the hostname.
  // scanTls() is safe to call here — it receives an already-validated URL.
  // For HTTP URLs, scanTls returns { analyzed: false } immediately.
  const tlsResult = await tlsScanner.scanTls(url);

  // Header analysis reuses the existing HTTP response — no second request.
  // We pass finalIsHttps so the HSTS analyzer has the correct context.
  const headersResult = headerScanner.analyzeHeaders(response.headers, finalIsHttps);

  // Cookie analysis also reuses the same response — no second request.
  // Cookie values are redacted inside cookieScanner; they never leave the service.
  const cookiesResult = cookieScanner.analyzeCookies(response.headers);

  // Information disclosure analysis reuses the existing headers — no second request.
  const disclosureResult = disclosureScanner.analyzeDisclosure(response.headers);

  // Risk assessment and security scoring
  const partialResult = {
    target: url,
    isHttps,
    tls: tlsResult,
    headers: headersResult,
    cookies: cookiesResult,
    disclosure: disclosureResult,
  };
  const normalizedFindings = riskAnalyzer.normalizeFindings(partialResult);
  const riskResult = riskAnalyzer.analyzeRisk(normalizedFindings);

  return {
    target: url,
    finalUrl: currentUrl !== url ? currentUrl : undefined,
    statusCode: response.status,
    statusText: response.statusText,
    responseTime,
    isHttps,
    redirectsToHttps,
    contentType: response.headers['content-type'] || null,
    server: response.headers['server'] || null,
    tls: tlsResult,
    headers: headersResult,
    cookies: cookiesResult,
    disclosure: disclosureResult,
    risk: riskResult,
  };
}

/**
 * Runs all three SSRF guards for a given URL in order:
 *   1. Protocol check (isValidUrl)
 *   2. Hostname blocklist (isBlockedHostname)
 *   3. DNS pre-resolution (resolveAndValidate)
 *
 * Throws SsrfError on any failure so the controller can map it to 403.
 *
 * @param {string} url
 */
async function validateTarget(url) {
  if (!isValidUrl(url)) {
    throw new SsrfError('Only HTTP and HTTPS URLs are allowed.');
  }

  const { hostname } = new URL(url);

  if (isBlockedHostname(hostname)) {
    throw new SsrfError('Scanning internal or local hostnames is not permitted.');
  }

  // DNS pre-resolution — throws SsrfError if any address is private/reserved.
  await resolveAndValidate(hostname);
}

/**
 * Makes a single HTTP GET request without following redirects.
 * All responses (including 4xx/5xx) are returned as data — errors are only
 * thrown for network-level failures (timeout, DNS failure, connection refused).
 *
 * @param {string} url
 * @returns {Promise<import('axios').AxiosResponse>}
 */
async function makeRequest(url) {
  try {
    return await axios.get(url, {
      timeout: REQUEST_TIMEOUT_MS,
      // We manage redirects manually — Axios must not follow them.
      maxRedirects: 0,
      // All HTTP status codes are resolved, not thrown.
      validateStatus: () => true,
      // We only need headers; avoid storing the response body.
      responseType: 'text',
      // Hard cap on response body size.
      maxContentLength: MAX_RESPONSE_BYTES,
      maxBodyLength: MAX_RESPONSE_BYTES,
    });
  } catch (err) {
    // SsrfErrors from validateTarget propagate as-is.
    if (err.isSsrfError) throw err;
    // Map Axios/network errors to safe user-facing messages.
    throw buildNetworkError(err);
  }
}

/**
 * Converts a low-level Axios or Node network error into a safe,
 * user-facing error without exposing stack traces or internal paths.
 *
 * @param {Error} err
 * @returns {Error} A plain Error with isTargetError = true.
 */
function buildNetworkError(err) {
  const messages = {
    ECONNABORTED:   'The target did not respond within the allowed time limit.',
    ENOTFOUND:      'The target host could not be resolved. Check the URL and try again.',
    ECONNREFUSED:   'The target refused the connection.',
    ERR_INVALID_URL:'The provided URL is malformed.',
    ERR_FR_TOO_MANY_REDIRECTS: 'The target redirected too many times.',
    EPROTO:         'A protocol error occurred while connecting to the target.',
    DEPTH_ZERO_SELF_SIGNED_CERT: 'The target uses an untrusted self-signed certificate.',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'The target certificate could not be verified.',
  };

  const message = messages[err.code] ||
    'Could not reach the target. It may be offline or blocking requests.';

  const safeError = new Error(message);
  safeError.isTargetError = true;
  return safeError;
}

module.exports = { performScan };
