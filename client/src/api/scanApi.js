import axios from 'axios';

// Base URL for all API calls. Vite's proxy (vite.config.js) forwards /api
// requests to the Express server during development.
const api = axios.create({
  baseURL: '/api',
  timeout: 15000,
});

/**
 * Sends a scan request to the server.
 *
 * @param {string} url - The target URL to scan.
 * @returns {Promise<object>} The scan result returned by the server.
 */
export async function scanUrl(url) {
  const response = await api.post('/scan', { url });
  return response.data;
}

/**
 * Requests a PDF security assessment report from the server.
 *
 * The server generates the PDF entirely from the supplied scanResult —
 * no additional scan is performed.
 *
 * @param {object} scanResult - The completed scan result object.
 * @returns {Promise<{ blob: Blob, filename: string }>}
 */
export async function generateReport(scanResult) {
  const response = await api.post('/report', { scanResult }, {
    responseType: 'blob',   // Receive binary PDF data
    timeout: 30000,         // PDF generation may take a moment
  });

  // Extract filename from Content-Disposition header if available
  const disposition = response.headers['content-disposition'] || '';
  const filenameMatch = disposition.match(/filename="([^"]+)"/);
  const filename = filenameMatch
    ? filenameMatch[1]
    : 'CyberGuard-Report.pdf';

  return { blob: response.data, filename };
}

