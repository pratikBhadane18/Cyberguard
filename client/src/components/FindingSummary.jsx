/**
 * Section C: Finding Summary Counts
 */
export default function FindingSummary({ summary }) {
  const counts = summary || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  const cards = [
    { label: 'Critical', count: counts.critical, severity: 'CRITICAL', class: counts.critical > 0 ? 'sev-critical' : 'sev-none' },
    { label: 'High', count: counts.high, severity: 'HIGH', class: counts.high > 0 ? 'sev-high' : 'sev-none' },
    { label: 'Medium', count: counts.medium, severity: 'MEDIUM', class: counts.medium > 0 ? 'sev-medium' : 'sev-none' },
    { label: 'Low', count: counts.low, severity: 'LOW', class: counts.low > 0 ? 'sev-low' : 'sev-none' },
    { label: 'Info', count: counts.info, severity: 'INFO', class: 'sev-info' },
  ];

  return (
    <div className="finding-summary-card">
      <div className="card-section-title">
        <span className="title-icon">📊</span> Finding Summary
      </div>
      <div className="counts-grid">
        {cards.map((item) => (
          <div key={item.label} className={`count-card ${item.class}`}>
            <div className="count-num">{item.count}</div>
            <div className="count-label">{item.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
