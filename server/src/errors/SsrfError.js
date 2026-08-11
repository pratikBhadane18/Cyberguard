/**
 * Thrown when a URL or redirect destination is rejected by SSRF protection.
 * Using a named subclass lets each layer (service, controller) distinguish
 * SSRF rejections from ordinary network errors without inspecting message strings.
 */
class SsrfError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SsrfError';
    this.isSsrfError = true;
  }
}

module.exports = { SsrfError };
