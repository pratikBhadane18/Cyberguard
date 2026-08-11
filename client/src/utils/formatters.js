/**
 * Returns a CSS class name based on the HTTP status code range,
 * used to colour-code the status badge.
 */
export function statusClass(code) {
  if (code >= 200 && code < 300) return 'status-2xx';
  if (code >= 300 && code < 400) return 'status-3xx';
  if (code >= 400 && code < 500) return 'status-4xx';
  return 'status-5xx';
}

/**
 * Formats a response time in milliseconds into a readable string.
 * Under 1 second → "XXX ms", 1 second and over → "X.XXs"
 */
export function formatResponseTime(ms) {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}
