/**
 * Section D: Security Controls Status
 */
export default function SecurityControls({ data }) {
  const { isHttps, redirectsToHttps, tls, headers, cookies } = data;

  // 1. HTTPS Control
  let httpsStatus = 'PASS';
  let httpsExplanation = 'Target uses encrypted HTTPS protocol.';
  if (!isHttps) {
    if (redirectsToHttps) {
      httpsStatus = 'WARNING';
      httpsExplanation = 'HTTP origin target redirects to HTTPS.';
    } else {
      httpsStatus = 'WARNING';
      httpsExplanation = 'Plain unencrypted HTTP connection.';
    }
  }

  // 2. TLS Control
  let tlsStatus = 'PASS';
  let tlsExplanation = 'Valid TLS certificate with matching hostname.';
  if (!tls?.analyzed) {
    tlsStatus = 'INFO';
    tlsExplanation = 'TLS analysis not performed on plain HTTP origin.';
  } else if (tls.status === 'error') {
    tlsStatus = 'WARNING';
    tlsExplanation = tls.message || 'TLS certificate inspection error.';
  } else if (tls.certificate) {
    if (tls.certificate.expired) {
      tlsStatus = 'WARNING';
      tlsExplanation = 'TLS certificate has expired.';
    } else if (!tls.certificate.hostnameValid) {
      tlsStatus = 'WARNING';
      tlsExplanation = 'TLS certificate hostname mismatch.';
    } else if (tls.certificate.expiringSoon) {
      tlsStatus = 'WARNING';
      tlsExplanation = `TLS certificate expires in ${tls.certificate.daysRemaining} days.`;
    }
  }

  // 3. Headers Control
  let headersStatus = 'PASS';
  let headersExplanation = 'All analyzed security headers are configured.';
  if (headers?.analyzed && Array.isArray(headers.findings)) {
    const hasMedium = headers.findings.some(f => f.severity === 'MEDIUM');
    const hasLow = headers.findings.some(f => f.severity === 'LOW');
    if (hasMedium) {
      headersStatus = 'WARNING';
      headersExplanation = 'Essential security headers (e.g. CSP or HSTS) missing.';
    } else if (hasLow) {
      headersStatus = 'INFO';
      headersExplanation = 'Minor security header hardening opportunities identified.';
    }
  }

  // 4. Cookies Control
  let cookiesStatus = 'PASS';
  let cookiesExplanation = 'Cookies configured with Secure, HttpOnly, and SameSite.';
  if (cookies?.analyzed) {
    if (cookies.count === 0) {
      cookiesStatus = 'PASS';
      cookiesExplanation = 'No Set-Cookie headers returned by target.';
    } else {
      const allCookieFindings = cookies.cookies.flatMap(c => c.findings || []);
      const hasMedium = allCookieFindings.some(f => f.severity === 'MEDIUM');
      const hasLow = allCookieFindings.some(f => f.severity === 'LOW');

      if (hasMedium) {
        cookiesStatus = 'WARNING';
        cookiesExplanation = 'Session cookies missing Secure or HttpOnly attribute.';
      } else if (hasLow) {
        cookiesStatus = 'INFO';
        cookiesExplanation = 'Cookies missing SameSite or Secure attribute.';
      }
    }
  }

  // 5. Technology Exposure Control
  const { disclosure } = data;
  let disclosureStatus = 'PASS';
  let disclosureExplanation = 'No common technology-disclosure headers detected.';
  if (disclosure?.analyzed && Array.isArray(disclosure.findings) && disclosure.findings.length > 0) {
    disclosureStatus = 'INFO';
    const names = disclosure.findings.map(f => f.header || 'header').slice(0, 3).join(', ');
    disclosureExplanation = `Technology disclosure headers present (${names}).`;
  }

  const controls = [
    { title: 'HTTPS Protocol', status: httpsStatus, explanation: httpsExplanation },
    { title: 'TLS & Certificate', status: tlsStatus, explanation: tlsExplanation },
    { title: 'Security Headers', status: headersStatus, explanation: headersExplanation },
    { title: 'Cookie Security', status: cookiesStatus, explanation: cookiesExplanation },
    { title: 'Technology Exposure', status: disclosureStatus, explanation: disclosureExplanation },
  ];

  return (
    <div className="security-controls-card">
      <div className="card-section-title">
        <span className="title-icon">🛡️</span> Security Controls Evaluation
      </div>
      <div className="controls-grid">
        {controls.map((ctrl) => (
          <div key={ctrl.title} className="control-item-box">
            <div className="control-header">
              <span className="control-title">{ctrl.title}</span>
              <span className={`control-status-badge status-${ctrl.status.toLowerCase()}`}>
                {ctrl.status}
              </span>
            </div>
            <p className="control-explanation">{ctrl.explanation}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
