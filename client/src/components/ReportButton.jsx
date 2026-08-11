import { useState } from 'react';
import { generateReport } from '../api/scanApi';

/**
 * ReportButton — "Generate Security Report" button
 *
 * Sends the existing scan result to the server, receives a PDF blob,
 * and triggers a browser download. No new scan is performed.
 *
 * Props:
 *   scanResult {object} — the completed scan result from the dashboard
 */
export default function ReportButton({ scanResult }) {
  const [generating, setGenerating] = useState(false);
  const [error, setError]           = useState(null);
  const [success, setSuccess]       = useState(false);

  async function handleGenerate() {
    if (generating || !scanResult) return;

    setGenerating(true);
    setError(null);
    setSuccess(false);

    try {
      const { blob, filename } = await generateReport(scanResult);

      // Trigger browser download via a temporary <a> element
      const objectUrl = URL.createObjectURL(blob);
      const anchor    = document.createElement('a');
      anchor.href     = objectUrl;
      anchor.download = filename;
      anchor.style.display = 'none';
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(objectUrl);

      setSuccess(true);
      // Clear success message after 4 s
      setTimeout(() => setSuccess(false), 4000);
    } catch (err) {
      const message =
        err.response?.data instanceof Blob
          // When the server returned JSON error inside a blob response
          ? 'Report generation failed. Please try again.'
          : err.response?.data?.error ||
            err.message ||
            'Report generation failed. Please try again.';
      setError(message);
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="report-btn-wrapper">
      <button
        id="generate-report-btn"
        type="button"
        className={`report-btn ${generating ? 'report-btn--loading' : ''}`}
        onClick={handleGenerate}
        disabled={generating || !scanResult}
        aria-busy={generating}
        aria-label="Generate PDF Security Assessment Report"
      >
        {generating ? (
          <>
            <span className="report-btn-spinner" aria-hidden="true" />
            Generating Report…
          </>
        ) : (
          <>
            <span className="report-btn-icon" aria-hidden="true">📄</span>
            Generate Security Report
          </>
        )}
      </button>

      {success && (
        <div className="report-success-msg" role="status" aria-live="polite">
          ✅ Report downloaded successfully.
        </div>
      )}

      {error && (
        <div className="report-error-msg" role="alert">
          ⚠️ {error}
        </div>
      )}
    </div>
  );
}
