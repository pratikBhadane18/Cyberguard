'use strict';

/**
 * POST /api/report
 *
 * Accepts a scan result JSON body, validates and sanitizes it, then generates
 * and streams a PDF security assessment report back to the client.
 *
 * Security guarantees:
 *   - The endpoint NEVER re-scans the target. Zero new network requests.
 *   - All input is validated and sanitized before PDF generation.
 *   - Sensitive values (cookie values, JWTs, Authorization headers) are
 *     redacted by the sanitization layer in reportService before any content
 *     reaches the PDF builder.
 *   - Errors are logged server-side; only safe messages are returned to callers.
 */

const { sanitizeScanResult, generateReport, sanitizeFilename } = require('../services/reportService');

/**
 * Handles POST /api/report
 *
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 */
async function generateReportHandler(req, res) {
  // 1. Presence check
  const { scanResult } = req.body;
  if (!scanResult || typeof scanResult !== 'object' || Array.isArray(scanResult)) {
    return res.status(400).json({ error: 'Request body must contain a scanResult object.' });
  }

  // 2. Validate and sanitize — all sensitive values are redacted here
  let sanitized;
  try {
    sanitized = sanitizeScanResult(scanResult);
  } catch (err) {
    // Validation errors are safe to surface (they describe structure, not data)
    console.error('[ReportController] Validation failed:', err.message);
    return res.status(400).json({ error: `Invalid scan result: ${err.message}` });
  }

  // 3. Generate PDF
  let pdfBuffer;
  try {
    pdfBuffer = await generateReport(sanitized);
  } catch (err) {
    console.error('[ReportController] PDF generation failed:', err.message);
    return res.status(500).json({ error: 'Report generation failed. Please try again.' });
  }

  // 4. Produce a safe filename from the target URL
  const filename = sanitizeFilename(sanitized.target);

  // 5. Stream the PDF to the client
  res.set({
    'Content-Type':        'application/pdf',
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Content-Length':      pdfBuffer.length,
    // Prevent the report from being cached
    'Cache-Control':       'no-store',
    'X-Content-Type-Options': 'nosniff',
  });

  return res.send(pdfBuffer);
}

module.exports = { generateReport: generateReportHandler };
