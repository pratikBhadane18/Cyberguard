import { useState } from 'react';
import { scanUrl } from './api/scanApi';
import ScanResults from './components/ScanResults';

export default function App() {
  const [url, setUrl]         = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);
  const [results, setResults] = useState(null);

  async function handleScan(e) {
    e.preventDefault();

    const trimmed = url.trim();
    if (!trimmed) return;

    setLoading(true);
    setError(null);
    setResults(null);

    try {
      const data = await scanUrl(trimmed);
      setResults(data);
    } catch (err) {
      // Extract server-provided error message without exposing stack traces
      const message =
        err.response?.data?.error ||
        'Could not complete the scan. Check the target URL and try again.';
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <div className="container">

        {/* ---- Header ---- */}
        <header className="header">
          <div className="header-badge">Security Assessment</div>
          <h1>Cyber<span>Guard</span></h1>
          <p>Web Security Assessment & Vulnerability Dashboard</p>
        </header>

        {/* ---- Scanner Input ---- */}
        <section className="scanner-card" aria-label="URL Security Scanner">
          <form onSubmit={handleScan}>
            <label htmlFor="url-input" className="form-label">Target URL</label>
            <div className="input-row">
              <input
                id="url-input"
                type="text"
                className="url-input"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={loading}
                autoComplete="off"
                spellCheck={false}
              />
              <button
                id="scan-btn"
                type="submit"
                className="scan-btn"
                disabled={loading || !url.trim()}
              >
                {loading ? 'Scanning…' : 'Start Scan'}
              </button>
            </div>
          </form>
        </section>

        {/* ---- Scan States ---- */}
        
        {/* 1. Initial State */}
        {!loading && !error && !results && (
          <div className="state-box state-initial" role="status">
            <span className="state-icon">ℹ️</span>
            No scan performed yet. Enter a valid public URL above and click <strong>Start Scan</strong> to analyze HTTPS, TLS, Security Headers, and Cookie protections.
          </div>
        )}

        {/* 2. Loading State */}
        {loading && (
          <div className="state-box state-loading" role="status" aria-live="polite">
            <div className="spinner" aria-hidden="true" />
            Scanning target and evaluating security controls…
          </div>
        )}

        {/* 3. Error State */}
        {error && (
          <div className="state-box state-error" role="alert">
            <span className="state-icon">⚠️</span>
            {error}
          </div>
        )}

        {/* 4. Success State (Full Dashboard) */}
        {results && <ScanResults data={results} />}

        {/* ---- Footer ---- */}
        <footer className="footer">
          CyberGuard v1.0 · For authorized security assessment only
        </footer>
      </div>
    </div>
  );
}
