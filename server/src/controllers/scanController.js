const { isValidUrl, isBlockedHostname } = require('../utils/validators');
const scannerService = require('../services/scannerService');

/**
 * POST /api/scan
 *
 * Validation order:
 *   1. Presence check
 *   2. Protocol / URL format (isValidUrl)
 *   3. Hostname blocklist (isBlockedHostname)  ← early reject before DNS
 *   4. DNS pre-resolution + IP check           ← inside scannerService
 *   5. Redirect validation                     ← inside scannerService per hop
 */
async function scan(req, res) {
  const { url } = req.body;

  // 1. Presence check
  if (!url || typeof url !== 'string' || url.trim() === '') {
    return res.status(400).json({ error: 'A URL is required.' });
  }

  const trimmedUrl = url.trim();

  // 2. Protocol / URL format
  if (!isValidUrl(trimmedUrl)) {
    return res.status(400).json({
      error: 'Invalid URL. Only HTTP and HTTPS URLs are accepted.',
    });
  }

  // 3. Hostname blocklist — fast reject before any network activity
  const { hostname } = new URL(trimmedUrl);
  if (isBlockedHostname(hostname)) {
    return res.status(403).json({
      error: 'Scanning internal or local addresses is not permitted.',
    });
  }

  try {
    const result = await scannerService.performScan(trimmedUrl);
    return res.json(result);
  } catch (err) {
    // Log the real error server-side; never send internals to the client.
    console.error('[ScanController] Scan failed:', err.message);

    // SSRF rejection → 403 Forbidden (target was never reached)
    if (err.isSsrfError) {
      return res.status(403).json({ error: err.message });
    }

    // Network / reachability failure → 502 Bad Gateway
    if (err.isTargetError) {
      return res.status(502).json({ error: err.message });
    }

    // Unexpected application error → 500, no details exposed
    return res.status(500).json({ error: 'Scan could not be completed.' });
  }
}

module.exports = { scan };
