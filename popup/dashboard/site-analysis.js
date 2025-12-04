// ============================================
// Gone Phishin' - Site Analysis Module
// Comprehensive Academic Analysis View
// ============================================

// Load comprehensive site analysis
async function loadSiteAnalysis(hostname) {
    try {
        const storageData = await chrome.storage.local.get();
        
        // Get all data for this hostname
        const auditKeys = Object.keys(storageData)
            .filter(key => key.startsWith('audit_') && storageData[key].hostname === hostname)
            .sort((a, b) => storageData[b].timestamp - storageData[a].timestamp);
        
        const heuristicsKeys = Object.keys(storageData)
            .filter(key => key.startsWith('heuristics_') && storageData[key].hostname === hostname)
            .sort((a, b) => storageData[b].timestamp - storageData[a].timestamp);
        
        if (auditKeys.length === 0 && heuristicsKeys.length === 0) {
            return {
                error: `No analysis data found for ${hostname}. Visit this site to generate analysis data.`
            };
        }
        
        // Get most recent audit and heuristics
        const latestAudit = auditKeys.length > 0 ? storageData[auditKeys[0]] : null;
        const latestHeuristics = heuristicsKeys.length > 0 ? storageData[heuristicsKeys[0]] : null;
        
        return {
            hostname,
            audit: latestAudit,
            heuristics: latestHeuristics,
            allAudits: auditKeys.map(k => storageData[k]),
            allHeuristics: heuristicsKeys.map(k => storageData[k])
        };
    } catch (error) {
        console.error('Error loading site analysis:', error);
        return { error: error.message };
    }
}

// Generate comprehensive site analysis HTML
function generateSiteAnalysisHTML(analysis) {
    if (analysis.error) {
        return `
            <div class="analysis-error">
                <div class="error-icon">⚠️</div>
                <h3>${analysis.error}</h3>
            </div>
        `;
    }
    
    const { hostname, audit, heuristics } = analysis;
    
    return `
        <!-- Site Header -->
        <div class="site-analysis-header">
            <div class="site-header-content">
                <h2 class="site-title">${hostname}</h2>
                <div class="site-meta">
                    ${audit ? `<span class="meta-item">Last Analyzed: ${new Date(audit.timestamp).toLocaleString()}</span>` : ''}
                    ${audit ? `<span class="meta-badge ${audit.severity}">${audit.severity.toUpperCase()}</span>` : ''}
                </div>
            </div>
        </div>
        
        <!-- Overview Section -->
        ${audit ? generateOverviewSection(audit, heuristics) : ''}
        
        <!-- How It Works - Academic Explanation -->
        ${generateHowItWorksSection()}
        
        <!-- TLS Certificate Analysis -->
        ${audit ? generateTLSAnalysisSection(audit) : ''}
        
        <!-- Heuristics Analysis -->
        ${heuristics ? generateHeuristicsAnalysisSection(heuristics) : ''}
        
        <!-- Protection Layers Summary -->
        ${generateProtectionLayersSummary(audit, heuristics)}
    `;
}

function generateOverviewSection(audit, heuristics) {
    return `
        <div class="analysis-section overview-section">
            <h3 class="section-title">
                <span class="section-icon">📊</span>
                Analysis Overview
            </h3>
            <div class="overview-grid">
                <div class="overview-card">
                    <div class="overview-label">Overall Security Status</div>
                    <div class="overview-value ${audit.severity}">${audit.severity.toUpperCase()}</div>
                    <div class="overview-description">
                        ${audit.severity === 'secure' ? 'All protection layers verified the site as secure.' : 
                          audit.severity === 'warning' ? 'Some security concerns were detected but are not critical.' : 
                          'Critical security threats were detected. Proceed with caution.'}
                    </div>
                </div>
                <div class="overview-card">
                    <div class="overview-label">TLS Verification</div>
                    <div class="overview-value">${audit.protocol || 'N/A'}</div>
                    <div class="overview-description">TLS protocol version used for encryption</div>
                </div>
                <div class="overview-card">
                    <div class="overview-label">Heuristics Score</div>
                    <div class="overview-value">${heuristics ? heuristics.anomalyScore || 0 : 'N/A'}</div>
                    <div class="overview-description">${heuristics ? `Anomaly score: ${heuristics.anomalyScore || 0} (${heuristics.severity || 'unknown'})` : 'No heuristics data'}</div>
                </div>
            </div>
        </div>
    `;
}

function generateHowItWorksSection() {
    return `
        <div class="analysis-section how-it-works-section">
            <h3 class="section-title">
                <span class="section-icon">🎓</span>
                How Gone Phishin' Works
            </h3>
            
            <div class="explanation-card">
                <h4>1. HTTPS Enforcement Layer</h4>
                <p><strong>Purpose:</strong> Prevents SSL stripping attacks by ensuring all connections use HTTPS.</p>
                <p><strong>How it works:</strong></p>
                <ol>
                    <li>The extension intercepts all navigation requests using Chrome's <code>webRequest</code> API</li>
                    <li>When an HTTP request is detected, it checks if an HTTPS version is available</li>
                    <li>If available, automatically redirects to HTTPS before the request completes</li>
                    <li>Blocks mixed content (HTTP resources on HTTPS pages)</li>
                </ol>
                <div class="code-example">
                    <div class="code-label">Implementation:</div>
                    <pre><code>chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.url.startsWith('http://')) {
      // Check for HTTPS version and redirect
      return { redirectUrl: details.url.replace('http://', 'https://') };
    }
  },
  { urls: ["&lt;all_urls&gt;"] },
  ["blocking"]
);</code></pre>
                </div>
            </div>
            
            <div class="explanation-card">
                <h4>2. Connection Security Check</h4>
                <p><strong>Purpose:</strong> Verifies that the site uses HTTPS with a valid certificate.</p>
                <p><strong>How it works:</strong></p>
                <ol>
                    <li>Checks if the connection uses HTTPS protocol</li>
                    <li>The browser automatically validates certificates, checks expiration, and verifies certificate authority trust</li>
                    <li>In Chrome MV3, certificate validation is handled entirely by the browser</li>
                    <li><strong>Note:</strong> Advanced certificate monitoring (fingerprint tracking, issuer drift detection) is available in Firefox MV2 version only</li>
                </ol>
                <div class="code-example">
                    <div class="code-label">Connection Check:</div>
                    <pre><code>// Simple HTTPS check (Chrome MV3)
if (url.startsWith('https://')) {
  // Browser validates certificate automatically
  return { secure: true, note: 'Certificate validated by browser' };
}</code></pre>
                </div>
            </div>
            
            <div class="explanation-card">
                <h4>3. Heuristic Analysis System</h4>
                <p><strong>Purpose:</strong> Detects potential phishing and malicious websites using behavioral analysis and pattern recognition.</p>
                <p><strong>Algorithm:</strong></p>
                <ol>
                    <li><strong>Content Analysis:</strong> Analyzes page content for suspicious patterns</li>
                    <li><strong>Behavioral Detection:</strong> Monitors form submissions and external links</li>
                    <li><strong>Pattern Matching:</strong>
                        <ul>
                            <li>Detects suspicious form submissions → <strong>Warning</strong></li>
                            <li>Identifies external link patterns → <strong>Analysis</strong></li>
                            <li>Checks for phishing indicators → <strong>Threat Detection</strong></li>
                        </ul>
                    </li>
                    <li><strong>Scoring:</strong> Calculates anomaly score based on detected patterns</li>
                </ol>
                <div class="code-example">
                    <div class="code-label">Heuristic Algorithm:</div>
                    <pre><code>function analyzeHeuristics(pageContent) {
  const patterns = detectSuspiciousPatterns(pageContent);
  const score = calculateAnomalyScore(patterns);
  
  if (score > 80) {
    return { severity: 'critical', threat: 'high' };
  } else if (score > 50) {
    return { severity: 'warning', threat: 'medium' };
  } else {
    return { severity: 'secure', threat: 'low' };
  }
  
  // Check for majority consensus
    const counts = countFingerprints(votes);
    const majority = findMajority(counts, votes.length);
    return majority ? 
      { consensus: 'consistent', severity: 'low' } :
      { consensus: 'mixed', severity: 'medium' };
  }
}</code></pre>
                </div>
            </div>
            
            <div class="explanation-card">
                <h4>4. Heuristic Analysis Engine</h4>
                <p><strong>Purpose:</strong> Detects phishing attempts and suspicious behavior through content analysis and pattern matching.</p>
                <p><strong>Analysis Methods:</strong></p>
                <ol>
                    <li><strong>Form Analysis:</strong> Detects forms submitting to external domains</li>
                    <li><strong>Link Analysis:</strong> Identifies suspicious external links and URL shorteners</li>
                    <li><strong>DOM Monitoring:</strong> Uses MutationObserver to detect dynamically added malicious elements</li>
                    <li><strong>Network Interception:</strong> Monitors fetch() and XMLHttpRequest for data exfiltration</li>
                    <li><strong>Pattern Matching:</strong> Checks for suspicious domain patterns (shorteners, IP addresses, etc.)</li>
                </ol>
                <div class="code-example">
                    <div class="code-label">Anomaly Score Calculation:</div>
                    <pre><code>// Scoring system (cumulative)
- External form submission: +90 points
- Password form to external: +50 points
- Hidden iframe: +60 points
- External POST request: +80 points
- Suspicious link: +20 points
- Sensitive data in POST: +40 points

// Severity determination
if (score >= 100) → 'critical'
if (score >= 50) → 'high'
if (score >= 20) → 'warning'
else → 'secure'</code></pre>
                </div>
            </div>
        </div>
    `;
}

function generateTLSAnalysisSection(audit) {
    const isHttps = audit.url && audit.url.startsWith('https://');
    
    return `
        <div class="analysis-section tls-section">
            <h3 class="section-title">
                <span class="section-icon">🔐</span>
                Connection Security Analysis
            </h3>
            
            <div class="tls-details-grid">
                <div class="tls-detail-item">
                    <div class="detail-label">Protocol</div>
                    <div class="detail-value code">${isHttps ? 'HTTPS' : 'HTTP'}</div>
                    <div class="detail-explanation">
                        The connection protocol used. HTTPS encrypts data in transit, while HTTP sends data in plaintext.
                    </div>
                </div>
                
                <div class="tls-detail-item">
                    <div class="detail-label">Hostname</div>
                    <div class="detail-value">${audit.hostname || 'N/A'}</div>
                    <div class="detail-explanation">
                        The domain name of the site being accessed.
                    </div>
                </div>
                
                <div class="tls-detail-item">
                    <div class="detail-label">Certificate Status</div>
                    <div class="detail-value">${isHttps ? 'Valid (verified by browser)' : 'Not applicable'}</div>
                    <div class="detail-explanation">
                        ${isHttps 
                            ? 'The browser has validated the certificate. Certificate validation, expiration checks, and CA trust verification are handled automatically by Chrome.' 
                            : 'HTTP connections do not use certificates.'}
                    </div>
                </div>
                
                <div class="tls-detail-item">
                    <div class="detail-label">Browser Validation</div>
                    <div class="detail-value">${isHttps ? 'Active' : 'N/A'}</div>
                    <div class="detail-explanation">
                        Chrome automatically validates certificates, checks expiration dates, verifies certificate authority trust, and ensures proper certificate chain. This extension supplements browser security but does not replace it.
                    </div>
                </div>
            </div>
            
            <div class="tls-status-good">
                <div class="status-icon">ℹ️</div>
                <div class="status-message">
                    <strong>Chrome MV3 Limitation:</strong> Advanced certificate monitoring (fingerprint tracking, issuer drift detection, weak TLS detection) is not available in Chrome Manifest V3 due to API restrictions. These features are available in the Firefox MV2 version of this extension.
                </div>
            </div>
        </div>
    `;
}


function generateHeuristicsAnalysisSection(heuristics) {
    const detailed = heuristics.detailedAnalysis || {};
    
    return `
        <div class="analysis-section heuristics-section">
            <h3 class="section-title">
                <span class="section-icon">🔍</span>
                Heuristic Analysis - DOM & Behavior Analysis
            </h3>
            
            <div class="heuristics-overview">
                <div class="heuristic-stat">
                    <div class="stat-value ${heuristics.anomalyScore >= 100 ? 'error' : heuristics.anomalyScore >= 50 ? 'warning' : 'success'}">${heuristics.anomalyScore || 0}</div>
                    <div class="stat-label">Anomaly Score</div>
                    <div class="stat-explanation">
                        Cumulative score based on detected suspicious patterns. Higher scores indicate higher risk.
                    </div>
                </div>
                <div class="heuristic-stat">
                    <div class="stat-value">${heuristics.severity || 'unknown'}</div>
                    <div class="stat-label">Severity Assessment</div>
                    <div class="stat-explanation">
                        ${heuristics.severity === 'critical' ? 'Critical threats detected - high risk of phishing or data exfiltration' :
                          heuristics.severity === 'high' ? 'High risk indicators present' :
                          heuristics.severity === 'warning' ? 'Some suspicious patterns detected' :
                          'No significant threats detected'}
                    </div>
                </div>
                <div class="heuristic-stat">
                    <div class="stat-value">${heuristics.externalLinks || 0}</div>
                    <div class="stat-label">External Links Found</div>
                    <div class="stat-explanation">
                        Links pointing to domains other than the current site
                    </div>
                </div>
                <div class="heuristic-stat">
                    <div class="stat-value">${heuristics.externalPosts || 0}</div>
                    <div class="stat-label">External POST Requests</div>
                    <div class="stat-explanation">
                        POST requests to external domains (potential data exfiltration)
                    </div>
                </div>
            </div>
            
            ${detailed.totalForms !== undefined ? `
            <div class="dom-stats">
                <h4>DOM Element Analysis</h4>
                <div class="dom-stats-grid">
                    <div class="dom-stat-item">
                        <div class="dom-stat-label">Total Forms Analyzed</div>
                        <div class="dom-stat-value">${detailed.totalForms || 0}</div>
                    </div>
                    <div class="dom-stat-item">
                        <div class="dom-stat-label">Total Links Scanned</div>
                        <div class="dom-stat-value">${detailed.totalLinks || 0}</div>
                    </div>
                    <div class="dom-stat-item">
                        <div class="dom-stat-label">Total Iframes Found</div>
                        <div class="dom-stat-value">${detailed.totalIframes || 0}</div>
                    </div>
                    <div class="dom-stat-item">
                        <div class="dom-stat-label">External Domains</div>
                        <div class="dom-stat-value">${heuristics.linkDomains ? heuristics.linkDomains.length : 0}</div>
                    </div>
                </div>
            </div>
            ` : ''}
            
            ${detailed.forms && detailed.forms.length > 0 ? `
            <div class="forms-analysis">
                <h4>Form Analysis Details</h4>
                <p><strong>Functions Used:</strong> <code>document.querySelectorAll('form')</code>, <code>form.getAttribute('action')</code>, <code>form.querySelector('input[type="password"]')</code>, <code>window.getComputedStyle(form)</code></p>
                ${detailed.forms.map((form, idx) => `
                    <div class="form-analysis-card ${form.isExternal ? 'external' : 'internal'}">
                        <div class="form-header">
                            <span class="form-number">Form #${form.index + 1}</span>
                            ${form.isExternal ? '<span class="form-badge danger">EXTERNAL</span>' : '<span class="form-badge success">INTERNAL</span>'}
                            ${form.hasPassword ? '<span class="form-badge warning">PASSWORD</span>' : ''}
                            ${form.isHidden ? '<span class="form-badge warning">HIDDEN</span>' : ''}
                        </div>
                        <div class="form-details">
                            <div class="form-detail-row">
                                <span class="detail-label">Action URL:</span>
                                <span class="detail-value code">${form.action || 'No action (defaults to current page)'}</span>
                            </div>
                            ${form.isExternal ? `
                            <div class="form-detail-row">
                                <span class="detail-label">Target Domain:</span>
                                <span class="detail-value warning">${form.targetDomain}</span>
                            </div>
                            <div class="form-detail-row">
                                <span class="detail-label">Risk Score:</span>
                                <span class="detail-value">${90 + (form.hasPassword ? 50 : 0) + (form.isHidden ? 30 : 0)} points</span>
                            </div>
                            ` : ''}
                            <div class="form-detail-row">
                                <span class="detail-label">Method:</span>
                                <span class="detail-value">${form.method || 'GET'}</span>
                            </div>
                            <div class="form-detail-row">
                                <span class="detail-label">Input Fields:</span>
                                <span class="detail-value">${form.inputCount || 0}</span>
                            </div>
                            <div class="form-detail-row">
                                <span class="detail-label">Visibility:</span>
                                <span class="detail-value">${form.isHidden ? 'Hidden (display: none or visibility: hidden)' : 'Visible'}</span>
                            </div>
                        </div>
                        ${form.isExternal ? `
                        <div class="form-explanation">
                            <strong>Analysis:</strong> This form submits data to an external domain (${form.targetDomain}). 
                            ${form.hasPassword ? '⚠️ <strong>CRITICAL:</strong> Form contains password fields - credential theft risk!' : ''}
                            ${form.isHidden ? '⚠️ Form is hidden - suspicious behavior!' : ''}
                        </div>
                        ` : `
                        <div class="form-explanation">
                            <strong>Analysis:</strong> This form submits to the same domain (${window.location.hostname}). This is normal and safe.
                        </div>
                        `}
                    </div>
                `).join('')}
            </div>
            ` : ''}
            
            ${detailed.links && detailed.links.length > 0 ? `
            <div class="links-analysis">
                <h4>External Links Analysis</h4>
                <p><strong>Functions Used:</strong> <code>document.querySelectorAll('a[href]')</code>, <code>link.getAttribute('href')</code>, <code>new URL(href, location.origin)</code>, <code>isSuspiciousDomain()</code></p>
                <div class="links-summary-stats">
                    <div class="summary-stat">
                        <strong>Total External Links:</strong> ${detailed.links.length}
                    </div>
                    <div class="summary-stat">
                        <strong>Suspicious Links:</strong> ${detailed.links.filter(l => l.isSuspicious).length}
                    </div>
                    <div class="summary-stat">
                        <strong>Visible Links:</strong> ${detailed.links.filter(l => l.isVisible).length}
                    </div>
                    <div class="summary-stat">
                        <strong>Hidden Links:</strong> ${detailed.links.filter(l => !l.isVisible).length}
                    </div>
                </div>
                ${detailed.links.length > 0 && detailed.links.length <= 50 ? `
                <div class="links-list">
                    ${detailed.links.map((link, idx) => `
                        <div class="link-analysis-item ${link.isSuspicious ? 'suspicious' : ''}">
                            <div class="link-header">
                                <span class="link-number">Link #${idx + 1}</span>
                                ${link.isSuspicious ? '<span class="link-badge danger">SUSPICIOUS</span>' : ''}
                                ${link.isVisible ? '<span class="link-badge success">VISIBLE</span>' : '<span class="link-badge warning">HIDDEN</span>'}
                            </div>
                            <div class="link-details">
                                <div class="link-detail-row">
                                    <span class="detail-label">URL:</span>
                                    <span class="detail-value code">${link.url}</span>
                                </div>
                                <div class="link-detail-row">
                                    <span class="detail-label">Domain:</span>
                                    <span class="detail-value">${link.domain}</span>
                                </div>
                                <div class="link-detail-row">
                                    <span class="detail-label">Link Text:</span>
                                    <span class="detail-value">${link.text || '(empty)'}</span>
                                </div>
                                ${link.isSuspicious ? `
                                <div class="link-detail-row">
                                    <span class="detail-label">Risk Score:</span>
                                    <span class="detail-value warning">+20 points (suspicious domain pattern detected)</span>
                                </div>
                                <div class="link-explanation">
                                    <strong>Why Suspicious:</strong> Domain matches suspicious patterns (URL shortener, IP address, suspicious TLD, or very short domain name).
                                </div>
                                ` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
                ` : detailed.links.length > 50 ? `
                <div class="links-too-many">
                    <p>Too many links to display (${detailed.links.length} total). Showing summary:</p>
                    ${detailed.domainCounts ? `
                    <div class="domain-counts">
                        <h5>Link Counts by Domain:</h5>
                        <div class="domain-count-list">
                            ${Object.entries(detailed.domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([domain, count]) => `
                                <div class="domain-count-item">
                                    <span class="domain-name">${domain}</span>
                                    <span class="domain-count">${count} link${count !== 1 ? 's' : ''}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                </div>
                ` : ''}
            </div>
            ` : ''}
            
            ${detailed.iframes && detailed.iframes.length > 0 ? `
            <div class="iframes-analysis">
                <h4>Iframe Analysis</h4>
                <p><strong>Functions Used:</strong> <code>document.querySelectorAll('iframe')</code>, <code>window.getComputedStyle(iframe)</code>, <code>iframe.src</code></p>
                ${detailed.iframes.map((iframe, idx) => `
                    <div class="iframe-analysis-item ${iframe.isExternal && iframe.isHidden ? 'danger' : iframe.isExternal ? 'warning' : 'safe'}">
                        <div class="iframe-header">
                            <span class="iframe-number">Iframe #${idx + 1}</span>
                            ${iframe.isExternal ? '<span class="iframe-badge warning">EXTERNAL</span>' : '<span class="iframe-badge success">INTERNAL</span>'}
                            ${iframe.isHidden ? '<span class="iframe-badge danger">HIDDEN</span>' : '<span class="iframe-badge success">VISIBLE</span>'}
                        </div>
                        <div class="iframe-details">
                            <div class="iframe-detail-row">
                                <span class="detail-label">Source:</span>
                                <span class="detail-value code">${iframe.src || 'No src attribute'}</span>
                            </div>
                            ${iframe.isExternal ? `
                            <div class="iframe-detail-row">
                                <span class="detail-label">Target Domain:</span>
                                <span class="detail-value">${iframe.targetDomain}</span>
                            </div>
                            <div class="iframe-detail-row">
                                <span class="detail-label">Risk Score:</span>
                                <span class="detail-value">${iframe.isHidden ? '+60 points (hidden external iframe)' : 'Low (visible iframe)'}</span>
                            </div>
                            ` : ''}
                        </div>
                        ${iframe.isExternal && iframe.isHidden ? `
                        <div class="iframe-explanation danger">
                            <strong>⚠️ HIGH RISK:</strong> Hidden external iframe detected. This is often used for tracking, data collection, or malicious purposes.
                        </div>
                        ` : iframe.isExternal ? `
                        <div class="iframe-explanation">
                            <strong>Analysis:</strong> External iframe from ${iframe.targetDomain}. Visible iframes are typically used for legitimate purposes (ads, embeds, etc.).
                        </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
            ` : ''}
            
            ${detailed.externalPosts && detailed.externalPosts.length > 0 ? `
            <div class="posts-analysis">
                <h4>Network Request Interception</h4>
                <p><strong>Functions Used:</strong> Intercepted <code>window.fetch()</code> and <code>XMLHttpRequest</code> APIs</p>
                <div class="posts-list">
                    ${detailed.externalPosts.map((post, idx) => `
                        <div class="post-analysis-item">
                            <div class="post-header">
                                <span class="post-number">POST Request #${idx + 1}</span>
                                <span class="post-method">${post.method || 'fetch'}</span>
                            </div>
                            <div class="post-details">
                                <div class="post-detail-row">
                                    <span class="detail-label">Target URL:</span>
                                    <span class="detail-value code">${post.url}</span>
                                </div>
                                <div class="post-detail-row">
                                    <span class="detail-label">Target Domain:</span>
                                    <span class="detail-value warning">${post.domain}</span>
                                </div>
                                <div class="post-detail-row">
                                    <span class="detail-label">Risk Score:</span>
                                    <span class="detail-value">+80 points (external POST request)</span>
                                </div>
                                <div class="post-detail-row">
                                    <span class="detail-label">Timestamp:</span>
                                    <span class="detail-value">${new Date(post.timestamp).toLocaleString()}</span>
                                </div>
                            </div>
                            <div class="post-explanation">
                                <strong>⚠️ WARNING:</strong> POST request to external domain detected. This could indicate data exfiltration. The request body was checked for sensitive data patterns.
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
            ` : ''}
            
            <div class="heuristics-explanation">
                <h4>How Heuristic Analysis Works</h4>
                <p>The heuristics engine performs comprehensive analysis of the webpage to detect phishing and data exfiltration attempts:</p>
                
                <div class="heuristic-method">
                    <h5>1. Form Analysis (checkFormSubmissions)</h5>
                    <p><strong>Function:</strong> <code>checkFormSubmissions()</code></p>
                    <p><strong>What it does:</strong></p>
                    <ul>
                        <li>Queries all <code>&lt;form&gt;</code> elements using <code>document.querySelectorAll('form')</code></p>
                        <li>Extracts the <code>action</code> attribute from each form</li>
                        <li>Checks if the form submits to an external domain (different origin)</li>
                        <li>If external: Adds +90 to anomaly score</li>
                        <li>If form contains password field: Adds additional +50 points (critical)</li>
                        <li>If form is hidden: Adds +30 points (suspicious behavior)</li>
                    </ul>
                    <div class="code-example">
                        <div class="code-label">Algorithm:</div>
                        <pre><code>forms.forEach(form => {
  const action = form.getAttribute('action');
  const formUrl = new URL(action, location.origin);
  
  if (formUrl.origin !== location.origin) {
    anomalyScore += 90; // External submission
    if (form.querySelector('input[type="password"]')) {
      anomalyScore += 50; // Password form
    }
  }
});</code></pre>
                    </div>
                </div>
                
                <div class="heuristic-method">
                    <h5>2. Link Analysis (checkExternalLinks)</h5>
                    <p><strong>Function:</strong> <code>checkExternalLinks()</code></p>
                    <p><strong>What it does:</strong></p>
                    <ul>
                        <li>Queries all <code>&lt;a href&gt;</code> elements</li>
                        <li>Extracts URLs and checks if they point to external domains</li>
                        <li>Checks for suspicious domain patterns:
                            <ul>
                                <li>URL shorteners (bit.ly, tinyurl, goo.gl, etc.)</li>
                                <li>IP addresses (e.g., 192.168.1.1)</li>
                                <li>Suspicious TLDs (.tk, .ml, .ga, .cf, .xyz)</li>
                                <li>Very short domain names</li>
                            </ul>
                        </li>
                        <li>For each suspicious link: Adds +20 to anomaly score</li>
                        <li>Tracks all external links for pattern analysis</li>
                    </ul>
                    <div class="code-example">
                        <div class="code-label">Suspicious Domain Detection:</div>
                        <pre><code>function isSuspiciousDomain(hostname) {
  const patterns = [
    /bit\\.ly|tinyurl|goo\\.gl|t\\.co|ow\\.ly/gi,  // URL shorteners
    /^\\d+\\.\\d+\\.\\d+\\.\\d+$/g,                 // IP addresses
    /\\.tk$|\\.ml$|\\.ga$|\\.cf$|\\.xyz$/gi,       // Suspicious TLDs
    /^[a-z0-9-]{1,10}\\.[a-z]{2,3}$/gi             // Short domains
  ];
  return patterns.some(pattern => pattern.test(hostname));
}</code></pre>
                    </div>
                </div>
                
                <div class="heuristic-method">
                    <h5>3. Hidden Element Detection (checkHiddenIframes)</h5>
                    <p><strong>Function:</strong> <code>checkHiddenIframes()</code></p>
                    <p><strong>What it does:</strong></p>
                    <ul>
                        <li>Queries all <code>&lt;iframe&gt;</code> elements</li>
                        <li>Uses <code>window.getComputedStyle()</code> to check visibility</li>
                        <li>Checks if iframe is hidden (display: none, visibility: hidden, opacity: 0)</li>
                        <li>If hidden iframe points to external domain: Adds +60 points (critical)</li>
                        <li>Hidden external iframes are often used for tracking or data collection</li>
                    </ul>
                </div>
                
                <div class="heuristic-method">
                    <h5>4. Network Request Interception (interceptNetworkRequests)</h5>
                    <p><strong>Function:</strong> <code>interceptNetworkRequests()</code></p>
                    <p><strong>What it does:</strong></p>
                    <ul>
                        <li>Intercepts <code>window.fetch()</code> API calls</li>
                        <li>Intercepts <code>XMLHttpRequest</code> (XHR) calls</li>
                        <li>Monitors all POST requests to external domains</li>
                        <li>For each external POST: Adds +80 to anomaly score</li>
                        <li>Checks request body for sensitive data patterns:
                            <ul>
                                <li>password, credit, ssn, pin, cvv, card, account, routing</li>
                            </ul>
                        </li>
                        <li>If sensitive data detected: Adds additional +40 points</li>
                    </ul>
                    <div class="code-example">
                        <div class="code-label">Fetch Interception:</div>
                        <pre><code>const originalFetch = window.fetch;
window.fetch = function(url, options = {}) {
  if (options.method === 'POST') {
    const reqUrl = new URL(url, location.origin);
    if (reqUrl.origin !== location.origin) {
      anomalyScore += 80; // External POST
      if (containsSensitiveData(options.body)) {
        anomalyScore += 40; // Sensitive data
      }
    }
  }
  return originalFetch.apply(this, arguments);
};</code></pre>
                    </div>
                </div>
                
                <div class="heuristic-method">
                    <h5>5. Dynamic DOM Monitoring (setupMutationObserver)</h5>
                    <p><strong>Function:</strong> <code>setupMutationObserver()</code></p>
                    <p><strong>What it does:</strong></p>
                    <ul>
                        <li>Uses <code>MutationObserver</code> API to watch for DOM changes</li>
                        <li>Monitors <code>childList</code> and <code>subtree</code> mutations</li>
                        <li>Detects dynamically added forms or links (common in phishing)</li>
                        <li>If dynamic form added externally: Adds +90 points</li>
                        <li>If dynamic suspicious link added: Adds +20 points</li>
                        <li>Re-runs analysis when changes are detected</li>
                    </ul>
                    <div class="code-example">
                        <div class="code-label">MutationObserver Setup:</div>
                        <pre><code>const observer = new MutationObserver(mutations => {
  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      if (node.tagName === 'FORM') {
        // Check if external submission
        const action = node.getAttribute('action');
        const formUrl = new URL(action, location.origin);
        if (formUrl.origin !== location.origin) {
          anomalyScore += 90;
        }
      }
    });
  });
});

observer.observe(document.body, { 
  childList: true, 
  subtree: true 
});</code></pre>
                    </div>
                </div>
            </div>
            
            ${heuristics.externalLinks > 0 ? `
            <div class="external-links-section">
                <h4>External Links Analysis</h4>
                <div class="links-summary">
                    <div class="summary-item">
                        <strong>Total External Links:</strong> ${heuristics.externalLinks}
                    </div>
                    <div class="summary-item">
                        <strong>Unique Domains:</strong> ${heuristics.linkDomains ? heuristics.linkDomains.length : 0}
                    </div>
                    ${heuristics.linkDomains && heuristics.linkDomains.length > 0 ? `
                    <div class="domains-list">
                        <strong>External Domains Found:</strong>
                        <div class="domain-tags">
                            ${heuristics.linkDomains.map(domain => `
                                <span class="domain-tag">${domain}</span>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                </div>
            </div>
            ` : ''}
            
            ${heuristics.detectedIssues && heuristics.detectedIssues.length > 0 ? `
            <div class="heuristics-issues">
                <h4>Detected Issues</h4>
                ${heuristics.detectedIssues.map((issue, idx) => `
                    <div class="issue-card ${issue.severity}">
                        <div class="issue-header">
                            <span class="issue-number">#${idx + 1}</span>
                            <span class="issue-type">${issue.type}</span>
                            <span class="issue-severity-badge">${issue.severity}</span>
                        </div>
                        <div class="issue-message">${issue.message}</div>
                    </div>
                `).join('')}
            </div>
            ` : `
            <div class="heuristics-status-good">
                <div class="status-icon">✅</div>
                <div class="status-message">No suspicious patterns detected. The page appears legitimate based on heuristic analysis.</div>
            </div>
            `}
            
            <div class="scoring-explanation">
                <h4>Anomaly Score Calculation</h4>
                <div class="score-breakdown">
                    <table class="score-table">
                        <thead>
                            <tr>
                                <th>Detection</th>
                                <th>Score</th>
                                <th>Explanation</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>Password form to different TLD (external)</td>
                                <td class="score-value">+80</td>
                                <td>Password forms submitting to different TLD indicate potential typosquatting/phishing</td>
                            </tr>
                            <tr>
                                <td>Hidden form with sensitive fields</td>
                                <td class="score-value">+50</td>
                                <td>Hidden forms with password/payment fields are suspicious</td>
                            </tr>
                            <tr>
                                <td>Sensitive data POST (external, non-legitimate)</td>
                                <td class="score-value">+60</td>
                                <td>Credit cards, passwords, SSN being sent to non-whitelisted external domains</td>
                            </tr>
                            <tr>
                                <td>Link clone pattern (>70% to one domain)</td>
                                <td class="score-value">+100</td>
                                <td>Most links point to single external domain (likely full-site clone)</td>
                            </tr>
                            <tr>
                                <td>URL shortener chain (multiple)</td>
                                <td class="score-value">+25</td>
                                <td>Multiple different URL shorteners detected (potential obfuscation)</td>
                            </tr>
                            <tr>
                                <td>Suspicious domain patterns</td>
                                <td class="score-value">+10-20</td>
                                <td>High-risk TLDs (.tk, .ml, .ga, .cf), homograph attacks, very short domains</td>
                            </tr>
                        </tbody>
                    </table>
                    <div class="severity-thresholds">
                        <div class="threshold">
                            <strong>CRITICAL:</strong> <span class="severity-critical">Block/Warn</span> - URLScan.io marks as malicious, password form to brand-new domain, 70%+ links to single domain
                        </div>
                        <div class="threshold">
                            <strong>WARNING:</strong> <span class="severity-warning">Notify User</span> - Mixed content, suspicious URL patterns, forms with suspicious fields going external
                        </div>
                        <div class="threshold">
                            <strong>INFORMATIONAL:</strong> <span class="severity-secure">Passive Logging</span> - HTTPS upgrade occurred, external form to legitimate service, normal external links
                        </div>
                        <div class="threshold" style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #ddd;">
                            <strong>Note:</strong> Scoring uses confidence-adjusted values. Legitimate services (Stripe, PayPal, OAuth providers) are whitelisted to reduce false positives.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function generateProtectionLayersSummary(audit, heuristics) {
    return `
        <div class="analysis-section protection-summary-section">
            <h3 class="section-title">
                <span class="section-icon">🛡️</span>
                Protection Layers Summary
            </h3>
            
            <div class="layers-summary">
                <div class="layer-summary-card">
                    <div class="layer-icon">🔒</div>
                    <div class="layer-info">
                        <h4>HTTPS Enforcement</h4>
                        <div class="layer-status active">Active</div>
                        <p>Automatically upgrades HTTP to HTTPS connections to prevent SSL stripping attacks.</p>
                    </div>
                </div>
                
                <div class="layer-summary-card">
                    <div class="layer-icon">🔐</div>
                    <div class="layer-info">
                        <h4>Connection Security</h4>
                        <div class="layer-status ${audit && audit.url && audit.url.startsWith('https://') ? 'active' : 'inactive'}">${audit && audit.url && audit.url.startsWith('https://') ? 'HTTPS Valid' : 'HTTP'}</div>
                        <p>${audit && audit.url && audit.url.startsWith('https://') ? 'Certificate validated by browser (Chrome MV3 limitation)' : 'Uses HTTP or not analyzed'}</p>
                    </div>
                </div>
                
                <div class="layer-summary-card">
                    <div class="layer-icon">🔍</div>
                    <div class="layer-info">
                        <h4>Heuristic Analysis</h4>
                        <div class="layer-status ${heuristics?.severity === 'secure' ? 'active' : heuristics?.severity === 'critical' ? 'error' : 'warning'}">${heuristics?.severity || 'Not Analyzed'}</div>
                        <p>Anomaly score: ${heuristics?.anomalyScore || 0} (${heuristics?.externalLinks || 0} external links, ${heuristics?.externalPosts || 0} external POSTs)</p>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Export functions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { loadSiteAnalysis, generateSiteAnalysisHTML };
}

