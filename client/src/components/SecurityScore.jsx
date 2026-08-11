import { statusClass, formatResponseTime } from '../utils/formatters';

/**
 * Maps risk levels to CSS color variants.
 * @param {string} riskLevel - LOW | MEDIUM | HIGH | CRITICAL
 * @returns {string} 'green' | 'yellow' | 'red'
 */
export function getRiskColorClass(riskLevel) {
  switch (riskLevel?.toUpperCase()) {
    case 'LOW':
      return 'green';
    case 'MEDIUM':
      return 'yellow';
    case 'HIGH':
    case 'CRITICAL':
      return 'red';
    default:
      return 'neutral';
  }
}

/**
 * Section A & B: Target Summary and Security Score Card
 */
export default function SecurityScore({ data }) {
  const { target, finalUrl, statusCode, statusText, responseTime, isHttps, risk } = data;
  const score = risk?.score ?? 100;
  const riskLevel = risk?.riskLevel ?? 'LOW';
  const colorClass = getRiskColorClass(riskLevel);
  
  // Format current timestamp or simulated scan timestamp
  const scanTime = new Date().toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <div className="dashboard-hero-card">
      {/* Target Summary Row */}
      <div className="target-summary-bar">
        <div className="target-info">
          <div className="target-label">Target URL</div>
          <div className="target-url-text" title={target}>
            {target}
            {finalUrl && <span className="redirect-arrow"> → {finalUrl}</span>}
          </div>
        </div>
        <div className="target-meta">
          <span className={`status-badge ${statusClass(statusCode)}`}>
            {statusCode} {statusText}
          </span>
          <span className={`protocol-badge ${isHttps ? 'https-yes' : 'https-no'}`}>
            {isHttps ? '🔒 HTTPS' : '⚠️ HTTP'}
          </span>
          <span className="meta-pill">{formatResponseTime(responseTime)}</span>
          <span className="meta-pill text-muted">{scanTime}</span>
        </div>
      </div>

      {/* Security Score Card */}
      <div className="score-hero-grid">
        <div className="score-main-display">
          <div className="score-number-wrap">
            <span className={`score-number ${colorClass}`}>{score}</span>
            <span className="score-max">/ 100</span>
          </div>
          <div className="score-title">Security Score</div>
        </div>

        <div className="score-risk-display">
          <div className={`risk-level-banner ${colorClass}`}>
            <span className="risk-dot" />
            <span className="risk-text">{riskLevel} RISK</span>
          </div>
          <p className="score-explanation">
            Heuristic score based on the security controls evaluated by CyberGuard.
          </p>
        </div>
      </div>
    </div>
  );
}
