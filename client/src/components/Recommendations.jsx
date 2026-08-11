/**
 * Section E: Top Recommendations List
 */
export default function Recommendations({ recommendations }) {
  const list = recommendations || [];

  return (
    <div className="recommendations-card">
      <div className="card-section-title">
        <span className="title-icon">💡</span> Top Recommendations
      </div>

      {list.length === 0 ? (
        <div className="recs-empty-box">
          ✅ No critical hardening recommendations required. All evaluated controls meet baseline security policies.
        </div>
      ) : (
        <div className="recs-list">
          {list.map((item, idx) => (
            <div key={item.id || idx} className="rec-row-item">
              <div className="rec-row-header">
                <span className="rec-number">{idx + 1}</span>
                <span className={`severity-tag ${item.severity}`}>{item.severity}</span>
                <span className="rec-item-title">{item.title}</span>
              </div>
              <p className="rec-item-text">{item.recommendation}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
