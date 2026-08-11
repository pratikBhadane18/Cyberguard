import { useState } from 'react';

/**
 * Section F: Detailed Findings (Expandable / Collapsible)
 */
export default function FindingDetails({ findings }) {
  const [isSectionOpen, setIsSectionOpen] = useState(true);
  const [expandedIds, setExpandedIds] = useState(new Set());
  const [activeCategory, setActiveCategory] = useState('ALL');

  const allFindings = findings || [];

  if (allFindings.length === 0) {
    return null;
  }

  // Filter categories
  const categories = ['ALL', ...new Set(allFindings.map(f => f.category))];
  const filteredFindings = activeCategory === 'ALL'
    ? allFindings
    : allFindings.filter(f => f.category === activeCategory);

  const toggleFinding = (idIndex) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(idIndex)) {
        next.delete(idIndex);
      } else {
        next.add(idIndex);
      }
      return next;
    });
  };

  const toggleExpandAll = () => {
    if (expandedIds.size === filteredFindings.length) {
      setExpandedIds(new Set());
    } else {
      setExpandedIds(new Set(filteredFindings.map((_, idx) => idx)));
    }
  };

  return (
    <div className="finding-details-card">
      <div className="card-section-header">
        <button
          type="button"
          className="section-toggle-btn"
          onClick={() => setIsSectionOpen(!isSectionOpen)}
          aria-expanded={isSectionOpen}
          aria-controls="detailed-findings-body"
        >
          <span className="title-icon">🔍</span> Detailed Findings ({allFindings.length})
          <span className="toggle-arrow">{isSectionOpen ? '▼' : '▶'}</span>
        </button>
      </div>

      {isSectionOpen && (
        <div id="detailed-findings-body" className="section-content-body">
          {/* Category Filter & Global Expand Button */}
          <div className="findings-toolbar">
            <div className="category-tabs" role="tablist" aria-label="Filter findings by category">
              {categories.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  role="tab"
                  aria-selected={activeCategory === cat}
                  className={`category-tab ${activeCategory === cat ? 'active' : ''}`}
                  onClick={() => setActiveCategory(cat)}
                >
                  {cat.toUpperCase()}
                </button>
              ))}
            </div>

            <button
              type="button"
              className="expand-all-btn"
              onClick={toggleExpandAll}
            >
              {expandedIds.size === filteredFindings.length ? 'Collapse All' : 'Expand All'}
            </button>
          </div>

          {/* List of Accordion Finding Items */}
          <div className="findings-accordion">
            {filteredFindings.map((item, idx) => {
              const isExpanded = expandedIds.has(idx);
              const itemKey = `${item.id}-${idx}`;

              return (
                <div key={itemKey} className={`finding-accordion-item ${isExpanded ? 'is-open' : ''}`}>
                  <button
                    type="button"
                    className="finding-header-btn"
                    onClick={() => toggleFinding(idx)}
                    aria-expanded={isExpanded}
                    aria-controls={`finding-body-${idx}`}
                  >
                    <span className={`severity-tag ${item.severity}`}>{item.severity}</span>
                    <span className="finding-item-title">{item.title}</span>
                    <span className="finding-category-tag">{item.category}</span>
                    <span className="accordion-chevron" aria-hidden="true">
                      {isExpanded ? '−' : '+'}
                    </span>
                  </button>

                  {isExpanded && (
                    <div id={`finding-body-${idx}`} className="finding-detail-panel">
                      <div className="detail-field">
                        <div className="field-label">Description</div>
                        <div className="field-value">{item.description}</div>
                      </div>

                      <div className="detail-field">
                        <div className="field-label">Impact</div>
                        <div className="field-value impact-highlight">{item.impact}</div>
                      </div>

                      <div className="detail-field">
                        <div className="field-label">Recommendation</div>
                        <div className="field-value rec-highlight">{item.recommendation}</div>
                      </div>

                      {item.evidence && (
                        <div className="detail-field">
                          <div className="field-label">Evidence</div>
                          <div className="evidence-code-box">{item.evidence}</div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
