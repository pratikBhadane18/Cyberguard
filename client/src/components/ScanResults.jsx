import { useState } from 'react';
import SecurityScore from './SecurityScore';
import FindingSummary from './FindingSummary';
import SecurityControls from './SecurityControls';
import Recommendations from './Recommendations';
import FindingDetails from './FindingDetails';
import ReportButton from './ReportButton';

/**
 * Professional Security Assessment Dashboard
 */
export default function ScanResults({ data }) {
  const [activeTab, setActiveTab] = useState('dashboard');

  if (!data) return null;

  return (
    <div className="security-dashboard">
      {/* Dashboard View Mode Selector */}
      <div className="dashboard-nav-bar">
        <button
          type="button"
          className={`nav-tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setActiveTab('dashboard')}
        >
          🛡️ Executive Overview
        </button>
        <button
          type="button"
          className={`nav-tab-btn ${activeTab === 'technical' ? 'active' : ''}`}
          onClick={() => setActiveTab('technical')}
        >
          ⚙️ Technical Details
        </button>

        {/* Generate Report button — sits in the nav bar, always visible */}
        <div className="nav-bar-report-action">
          <ReportButton scanResult={data} />
        </div>
      </div>

      {activeTab === 'dashboard' && (
        <div className="dashboard-grid-layout">
          {/* Section A & B: Target Summary & Score Card */}
          <SecurityScore data={data} />

          {/* Section C: Finding Summary Counts */}
          <FindingSummary summary={data.risk?.summary} />

          {/* Section D: Security Controls Evaluation */}
          <SecurityControls data={data} />

          {/* Section E: Top Recommendations */}
          <Recommendations recommendations={data.risk?.topRecommendations} />

          {/* Section F: Detailed Normalized Findings */}
          <FindingDetails findings={data.risk?.findings} />
        </div>
      )}

      {activeTab === 'technical' && (
        <div className="technical-details-layout">
          {/* Raw JSON / Technical Inspection Summary */}
          <div className="technical-card">
            <div className="card-section-title">
              <span className="title-icon">💻</span> Technical Inspection Payload
            </div>
            <pre className="json-dump-box">
              {JSON.stringify(
                {
                  target: data.target,
                  finalUrl: data.finalUrl,
                  statusCode: data.statusCode,
                  statusText: data.statusText,
                  responseTime: data.responseTime,
                  isHttps: data.isHttps,
                  tls: data.tls,
                  headers: data.headers,
                  cookies: data.cookies,
                },
                null,
                2
              )}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

