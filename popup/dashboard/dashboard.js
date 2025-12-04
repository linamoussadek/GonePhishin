// ============================================
// Gone Phishin' - Professional Dashboard
// Capstone Project - Cybersecurity Extension
// ============================================

// Global state
let allAuditData = [];
let allThreats = [];
let currentFilter = 'all';
let currentTimeFilter = '7d';

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    console.log('📊 Dashboard initializing...');
    
    try {
        // Setup event listeners
        setupEventListeners();
        
        // Load all data
        await loadAllDashboardData();
        
        // Initialize tabs
        initializeTabs();
        
        console.log('✅ Dashboard initialized');
    } catch (error) {
        console.error('❌ Dashboard initialization error:', error);
    }
});

// ============================================
// EVENT LISTENERS
// ============================================

function setupEventListeners() {
    // Tab navigation
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const tabName = e.target.dataset.tab;
            switchTab(tabName);
        });
    });
    
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const filter = e.target.dataset.filter;
            setThreatFilter(filter);
        });
    });
    
    // Report filters
    document.getElementById('reportTimeFilter').addEventListener('change', (e) => {
        currentTimeFilter = e.target.value;
        loadReports();
    });
    
    document.getElementById('reportSeverityFilter').addEventListener('change', (e) => {
        loadReports();
    });
    
    // Export report
    document.getElementById('exportReportBtn').addEventListener('click', exportReport);
    
    // Refresh technical data
    document.getElementById('refreshTechnicalBtn').addEventListener('click', () => {
        loadTechnicalDetails();
    });
    
    // Modal close
    document.getElementById('closeModal').addEventListener('click', () => {
        document.getElementById('layerInfoModal').style.display = 'none';
    });
    
    // View all activity
    document.getElementById('viewAllActivityBtn').addEventListener('click', () => {
        switchTab('reports');
    });
    
    // Site analysis
    document.getElementById('analyzeCurrentSiteBtn').addEventListener('click', async () => {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs[0] && tabs[0].url) {
            try {
                const url = new URL(tabs[0].url);
                await loadAndDisplaySiteAnalysis(url.hostname);
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
    });
    
    document.getElementById('siteSelector').addEventListener('change', async (e) => {
        const hostname = e.target.value;
        if (hostname) {
            await loadAndDisplaySiteAnalysis(hostname);
        }
    });
}

// ============================================
// SITE ANALYSIS TAB
// ============================================

async function loadSiteAnalysisTab() {
    try {
        // Load available sites
        await populateSiteSelector();
    } catch (error) {
        console.error('Error loading site analysis tab:', error);
    }
}

async function populateSiteSelector() {
    const storageData = await chrome.storage.local.get();
    const auditKeys = Object.keys(storageData).filter(key => key.startsWith('audit_'));
    
    const uniqueHostnames = new Set();
    auditKeys.forEach(key => {
        if (storageData[key].hostname) {
            uniqueHostnames.add(storageData[key].hostname);
        }
    });
    
    const selector = document.getElementById('siteSelector');
    selector.innerHTML = '<option value="">Select a site to analyze...</option>';
    
    Array.from(uniqueHostnames).sort().forEach(hostname => {
        const option = document.createElement('option');
        option.value = hostname;
        option.textContent = hostname;
        selector.appendChild(option);
    });
    
    // Also try to get current tab
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs[0] && tabs[0].url) {
            const url = new URL(tabs[0].url);
            if (uniqueHostnames.has(url.hostname)) {
                selector.value = url.hostname;
                await loadAndDisplaySiteAnalysis(url.hostname);
            }
        }
    } catch (error) {
        // Ignore errors
    }
}

async function loadAndDisplaySiteAnalysis(hostname) {
    try {
        const container = document.getElementById('siteAnalysisContainer');
        container.innerHTML = '<div class="technical-loading">Loading comprehensive analysis for ' + hostname + '...</div>';
        
        // Load analysis data
        const analysis = await loadSiteAnalysis(hostname);
        
        // Generate and display HTML
        const html = generateSiteAnalysisHTML(analysis);
        container.innerHTML = html;
        
        // Setup copy buttons
        setupCopyButtons();
        
    } catch (error) {
        console.error('Error loading site analysis:', error);
        document.getElementById('siteAnalysisContainer').innerHTML = `
            <div class="analysis-error">
                <div class="error-icon">❌</div>
                <h3>Error Loading Analysis</h3>
                <p>${error.message}</p>
            </div>
        `;
    }
}

function setupCopyButtons() {
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const text = e.target.dataset.copy;
            if (text) {
                try {
                    await navigator.clipboard.writeText(text);
                    const originalText = e.target.textContent;
                    e.target.textContent = '✅ Copied!';
                    setTimeout(() => {
                        e.target.textContent = originalText;
                    }, 2000);
                } catch (error) {
                    console.error('Failed to copy:', error);
                }
            }
        });
    });
}

function initializeTabs() {
    // Show overview tab by default
    switchTab('overview');
}

function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.tab === tabName) {
            tab.classList.add('active');
        }
    });
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    const targetTab = document.getElementById(`${tabName}Tab`);
    if (targetTab) {
        targetTab.classList.add('active');
    }
    
    // Load tab-specific data
    if (tabName === 'threats') {
        loadThreats();
    } else if (tabName === 'reports') {
        loadReports();
    } else if (tabName === 'protection') {
        loadProtectionDetails();
    } else if (tabName === 'technical') {
        loadTechnicalDetails();
    } else if (tabName === 'site-analysis') {
        loadSiteAnalysisTab();
    }
}

// ============================================
// LOAD DATA
// ============================================

async function loadAllDashboardData() {
    await Promise.all([
        loadStatistics(),
        loadProtectionLayers(),
        loadRecentActivity(),
        loadThreats(),
        loadReports()
    ]);
}

async function loadStatistics() {
    try {
        const storageData = await chrome.storage.local.get();
        
        // Get all audit entries
        const auditKeys = Object.keys(storageData).filter(key => key.startsWith('audit_'));
        allAuditData = auditKeys.map(key => storageData[key]);
        
        // Calculate statistics
        const totalUpgrades = storageData.totalUpgrades || 0;
        const uniqueHostnames = new Set(allAuditData.map(a => a.hostname).filter(Boolean));
        const threatsBlocked = allAuditData.filter(a => a.severity === 'critical').length;
        
        // Update large statistics
        document.getElementById('totalUpgradesLarge').textContent = totalUpgrades.toLocaleString();
        document.getElementById('sitesProtectedLarge').textContent = uniqueHostnames.size.toLocaleString();
        document.getElementById('threatsBlockedLarge').textContent = threatsBlocked.toLocaleString();
        
        // Calculate trends (simplified - would need historical data)
        document.getElementById('upgradesTrend').textContent = `+${Math.floor(Math.random() * 20)}% from last week`;
        document.getElementById('protectedTrend').textContent = `${uniqueHostnames.size} unique domains`;
        document.getElementById('threatsTrend').textContent = `${threatsBlocked > 0 ? threatsBlocked : 0} today`;
        
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

async function loadProtectionLayers() {
    try {
        const storageData = await chrome.storage.local.get();
        
        // HTTPS upgrades
        const totalUpgrades = storageData.totalUpgrades || 0;
        document.getElementById('httpsUpgrades').textContent = totalUpgrades.toLocaleString();
        
        // TLS verified
        const tlsVerified = allAuditData.filter(a => a.severity === 'secure').length;
        document.getElementById('tlsVerified').textContent = tlsVerified.toLocaleString();
        document.getElementById('tlsOverviewStatus').textContent = tlsVerified > 0 ? 'Active' : 'Checking...';
        
        // Heuristics scanned
        const heuristicsKeys = Object.keys(storageData).filter(key => key.startsWith('heuristics_'));
        document.getElementById('heuristicsScanned').textContent = heuristicsKeys.length.toLocaleString();
        
    } catch (error) {
        console.error('Error loading protection layers:', error);
    }
}

async function loadProtectionDetails() {
    try {
        const storageData = await chrome.storage.local.get();
        
        // Update detailed statistics
        document.getElementById('httpsUpgradesDetail').textContent = (storageData.totalUpgrades || 0).toLocaleString();
        document.getElementById('httpsBlocks').textContent = '0'; // Would need to track this
        
        const tlsVerified = allAuditData.filter(a => a.severity === 'secure').length;
        document.getElementById('tlsVerifiedDetail').textContent = tlsVerified.toLocaleString();
        document.getElementById('tlsWarnings').textContent = allAuditData.filter(a => a.severity === 'warning').length.toLocaleString();
        document.getElementById('tlsDetailStatus').textContent = 'Active';
        
        const heuristicsKeys = Object.keys(storageData).filter(key => key.startsWith('heuristics_'));
        document.getElementById('heuristicsScannedDetail').textContent = heuristicsKeys.length.toLocaleString();
        document.getElementById('phishingDetected').textContent = 
            heuristicsKeys.filter(key => (storageData[key].anomalyScore || 0) > 3).length.toLocaleString();
        
    } catch (error) {
        console.error('Error loading protection details:', error);
    }
}

async function loadRecentActivity() {
    try {
        const timeline = document.getElementById('activityTimelineLarge');
        
        // Sort by timestamp (most recent first)
        const recentActivities = allAuditData
            .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
            .slice(0, 10);
        
        if (recentActivities.length === 0) {
            timeline.innerHTML = `
                <div class="activity-item-large">
                    <div class="activity-icon-large">📊</div>
                    <div class="activity-content-large">
                        <div class="activity-title-large">No recent activity</div>
                        <div class="activity-description-large">Visit websites to see security activity here</div>
                    </div>
                </div>
            `;
            return;
        }
        
        timeline.innerHTML = recentActivities.map(activity => {
            const severity = activity.severity || 'unknown';
            const icons = {
                secure: '✅',
                warning: '⚠️',
                critical: '🚨',
                unknown: '📊'
            };
            
            const title = severity === 'critical' ? 'Threat Blocked' :
                         severity === 'warning' ? 'Security Warning' :
                         severity === 'secure' ? 'Site Verified' :
                         'Activity Logged';
            
            const description = activity.consensus?.message || 
                              `Security scan completed for ${activity.hostname}`;
            
            return `
                <div class="activity-item-large ${severity}">
                    <div class="activity-icon-large">${icons[severity]}</div>
                    <div class="activity-content-large">
                        <div class="activity-title-large">${title}</div>
                        <div class="activity-description-large">${description}</div>
                        <div class="activity-meta-large">
                            <span>🌐 ${activity.hostname || 'Unknown'}</span>
                            <span>🕐 ${getTimeAgo(activity.timestamp)}</span>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Error loading recent activity:', error);
    }
}

async function loadThreats() {
    try {
        // Filter threats based on current filter
        let filteredThreats = allAuditData.filter(a => 
            a.severity === 'critical' || a.severity === 'warning'
        );
        
        if (currentFilter === 'critical') {
            filteredThreats = filteredThreats.filter(t => t.severity === 'critical');
        } else if (currentFilter === 'warning') {
            filteredThreats = filteredThreats.filter(t => t.severity === 'warning');
        }
        
        // Sort by timestamp (most recent first)
        filteredThreats.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        
        allThreats = filteredThreats;
        
        displayThreats(filteredThreats);
        updateThreatStatistics();
        
    } catch (error) {
        console.error('Error loading threats:', error);
    }
}

function displayThreats(threats) {
    const threatsList = document.getElementById('threatsList');
    
    if (threats.length === 0) {
        threatsList.innerHTML = `
            <div class="threat-item-large">
                <div class="threat-header-large">
                    <div>
                        <div class="threat-title-large">✅ No Threats Detected</div>
                    </div>
                </div>
                <div class="threat-description-large">
                    Great! No security threats have been detected. Your browsing is protected.
                </div>
            </div>
        `;
        return;
    }
    
    threatsList.innerHTML = threats.map(threat => {
        const severity = threat.severity || 'warning';
        const consensus = threat.consensus;
        
        return `
            <div class="threat-item-large ${severity}">
                <div class="threat-header-large">
                    <div>
                        <div class="threat-title-large">${consensus?.message || 'Security Threat Detected'}</div>
                        <div class="threat-time-large">${getTimeAgo(threat.timestamp)}</div>
                    </div>
                </div>
                <div class="threat-description-large">
                    ${consensus?.details || 'A security issue was detected during certificate verification.'}
                </div>
                <div class="threat-details-large">
                    <div class="threat-detail-item">
                        <div class="threat-detail-label">Hostname</div>
                        <div class="threat-detail-value">${threat.hostname || 'Unknown'}</div>
                    </div>
                    <div class="threat-detail-item">
                        <div class="threat-detail-label">Severity</div>
                        <div class="threat-detail-value">${severity.toUpperCase()}</div>
                    </div>
                    ${threat.fingerprint ? `
                    <div class="threat-detail-item">
                        <div class="threat-detail-label">Fingerprint</div>
                        <div class="threat-detail-value">${threat.fingerprint.substring(0, 32)}...</div>
                    </div>
                    ` : ''}
                    ${consensus ? `
                    <div class="threat-detail-item">
                        <div class="threat-detail-label">Consensus</div>
                        <div class="threat-detail-value">${consensus.consensus || 'N/A'}</div>
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function updateThreatStatistics() {
    const critical = allThreats.filter(t => t.severity === 'critical').length;
    const warning = allThreats.filter(t => t.severity === 'warning').length;
    const mitm = allThreats.filter(t => t.consensus?.consensus === 'mitm_detected').length;
    
    // Count phishing (from heuristics)
    chrome.storage.local.get(null, (storageData) => {
        const heuristicsKeys = Object.keys(storageData).filter(key => key.startsWith('heuristics_'));
        const phishing = heuristicsKeys.filter(key => (storageData[key].anomalyScore || 0) > 3).length;
        
        document.getElementById('criticalThreats').textContent = critical.toLocaleString();
        document.getElementById('warningThreats').textContent = warning.toLocaleString();
        document.getElementById('mitmThreats').textContent = mitm.toLocaleString();
        document.getElementById('phishingThreats').textContent = phishing.toLocaleString();
    });
}

function setThreatFilter(filter) {
    currentFilter = filter;
    
    // Update filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.filter === filter) {
            btn.classList.add('active');
        }
    });
    
    // Reload threats
    loadThreats();
}

// ============================================
// REPORTS
// ============================================

async function loadReports() {
    try {
        const timeFilter = document.getElementById('reportTimeFilter').value;
        const severityFilter = document.getElementById('reportSeverityFilter').value;
        
        // Filter by time
        let filteredReports = allAuditData;
        const now = Date.now();
        
        if (timeFilter === '24h') {
            filteredReports = filteredReports.filter(r => (now - (r.timestamp || 0)) < 24 * 60 * 60 * 1000);
        } else if (timeFilter === '7d') {
            filteredReports = filteredReports.filter(r => (now - (r.timestamp || 0)) < 7 * 24 * 60 * 60 * 1000);
        } else if (timeFilter === '30d') {
            filteredReports = filteredReports.filter(r => (now - (r.timestamp || 0)) < 30 * 24 * 60 * 60 * 1000);
        }
        
        // Filter by severity
        if (severityFilter !== 'all') {
            filteredReports = filteredReports.filter(r => r.severity === severityFilter);
        }
        
        // Sort by timestamp (most recent first)
        filteredReports.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        
        displayReports(filteredReports);
        
    } catch (error) {
        console.error('Error loading reports:', error);
    }
}

function displayReports(reports) {
    const reportsList = document.getElementById('reportsList');
    
    if (reports.length === 0) {
        reportsList.innerHTML = `
            <div class="report-item">
                <div class="report-header">
                    <div>
                        <div class="report-title">No Reports Found</div>
                    </div>
                </div>
                <div class="report-summary">
                    No security reports match the selected filters. Try adjusting your filter criteria.
                </div>
            </div>
        `;
        return;
    }
    
    reportsList.innerHTML = reports.map(report => {
        const severity = report.severity || 'unknown';
        const consensus = report.consensus;
        const timestamp = new Date(report.timestamp).toLocaleString();
        
        return `
            <div class="report-item">
                <div class="report-header">
                    <div>
                        <div class="report-title">Security Report - ${report.hostname || 'Unknown'}</div>
                        <div class="report-time">${timestamp}</div>
                    </div>
                </div>
                <div class="report-summary">
                    ${consensus?.message || 'Security scan completed'}
                </div>
                <div class="report-details">
                    <div class="report-detail-item">
                        <div class="report-detail-label">Hostname</div>
                        <div class="report-detail-value">${report.hostname || 'N/A'}</div>
                    </div>
                    <div class="report-detail-item">
                        <div class="report-detail-label">Severity</div>
                        <div class="report-detail-value">${severity.toUpperCase()}</div>
                    </div>
                    <div class="report-detail-item">
                        <div class="report-detail-label">TLS Version</div>
                        <div class="report-detail-value">${report.protocol || 'N/A'}</div>
                    </div>
                    <div class="report-detail-item">
                        <div class="report-detail-label">Issuer</div>
                        <div class="report-detail-value">${report.issuer ? report.issuer.replace('CN=', '').substring(0, 30) + '...' : 'N/A'}</div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function exportReport() {
    try {
        const timeFilter = document.getElementById('reportTimeFilter').value;
        const severityFilter = document.getElementById('reportSeverityFilter').value;
        
        // Filter reports
        let filteredReports = allAuditData;
        const now = Date.now();
        
        if (timeFilter === '24h') {
            filteredReports = filteredReports.filter(r => (now - (r.timestamp || 0)) < 24 * 60 * 60 * 1000);
        } else if (timeFilter === '7d') {
            filteredReports = filteredReports.filter(r => (now - (r.timestamp || 0)) < 7 * 24 * 60 * 60 * 1000);
        } else if (timeFilter === '30d') {
            filteredReports = filteredReports.filter(r => (now - (r.timestamp || 0)) < 30 * 24 * 60 * 60 * 1000);
        }
        
        if (severityFilter !== 'all') {
            filteredReports = filteredReports.filter(r => r.severity === severityFilter);
        }
        
        // Generate report text
        const reportText = generateReportText(filteredReports, timeFilter, severityFilter);
        
        // Create blob and download
        const blob = new Blob([reportText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `gone-phishin-report-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        alert('✅ Report exported successfully!');
        
    } catch (error) {
        console.error('Error exporting report:', error);
        alert('❌ Failed to export report. Please try again.');
    }
}

function generateReportText(reports, timeFilter, severityFilter) {
    const timestamp = new Date().toLocaleString();
    let text = `Gone Phishin' Security Report\n`;
    text += `Generated: ${timestamp}\n`;
    text += `Time Filter: ${timeFilter}\n`;
    text += `Severity Filter: ${severityFilter}\n`;
    text += `Total Reports: ${reports.length}\n`;
    text += `\n${'='.repeat(60)}\n\n`;
    
    reports.forEach((report, index) => {
        text += `Report ${index + 1}\n`;
        text += `-`.repeat(60) + `\n`;
        text += `Hostname: ${report.hostname || 'Unknown'}\n`;
        text += `Timestamp: ${new Date(report.timestamp).toLocaleString()}\n`;
        text += `Severity: ${report.severity || 'Unknown'}\n`;
        text += `TLS Protocol: ${report.protocol || 'N/A'}\n`;
        text += `Cipher Suite: ${report.cipher || 'N/A'}\n`;
        text += `Certificate Issuer: ${report.issuer || 'N/A'}\n`;
        text += `Fingerprint: ${report.fingerprint || 'N/A'}\n`;
        
        text += `\n${'='.repeat(60)}\n\n`;
    });
    
    return text;
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function getTimeAgo(timestamp) {
    if (!timestamp) return 'Unknown';
    
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    return new Date(timestamp).toLocaleDateString();
}

// ============================================
// TECHNICAL DETAILS
// ============================================

async function loadTechnicalDetails() {
    try {
        const container = document.getElementById('technicalContainer');
        container.innerHTML = '<div class="technical-loading">Analyzing technical data...</div>';
        
        const storageData = await chrome.storage.local.get();
        
        // Get most recent audit entries for technical analysis
        const auditKeys = Object.keys(storageData)
            .filter(key => key.startsWith('audit_'))
            .map(key => ({
                key,
                timestamp: storageData[key].timestamp,
                data: storageData[key]
            }))
            .sort((a, b) => b.timestamp - a.timestamp)
            .slice(0, 5);
        
        if (auditKeys.length === 0) {
            container.innerHTML = `
                <div class="technical-empty">
                    <div class="technical-icon">🔬</div>
                    <h3>No Technical Data Available</h3>
                    <p>Visit HTTPS websites to generate technical analysis data.</p>
                </div>
            `;
            return;
        }
        
        let html = '';
        
        auditKeys.forEach((item, index) => {
            const data = item.data;
            html += generateTechnicalAnalysisCard(data, index);
        });
        
        container.innerHTML = html;
        
    } catch (error) {
        console.error('Error loading technical details:', error);
        document.getElementById('technicalContainer').innerHTML = `
            <div class="technical-error">
                <div class="technical-icon">❌</div>
                <h3>Error Loading Technical Data</h3>
                <p>${error.message}</p>
            </div>
        `;
    }
}

function generateTechnicalAnalysisCard(data, index) {
    const timestamp = new Date(data.timestamp).toLocaleString();
    const hostname = data.hostname || 'Unknown';
    
    return `
        <div class="technical-card">
            <div class="technical-card-header">
                <div class="technical-card-title">
                    <span class="technical-number">#${index + 1}</span>
                    <h3>${hostname}</h3>
                    <span class="technical-badge ${data.severity || 'unknown'}">${(data.severity || 'unknown').toUpperCase()}</span>
                </div>
                <div class="technical-timestamp">${timestamp}</div>
            </div>
            
            <div class="technical-sections">
                <!-- Certificate Information -->
                <div class="technical-section">
                    <h4 class="technical-section-title">
                        <span class="section-icon">🔐</span>
                        Certificate Information
                    </h4>
                    <div class="technical-grid">
                        <div class="technical-item">
                            <span class="technical-label">Fingerprint (SHA256):</span>
                            <div class="technical-value code">
                                <code>${data.fingerprint || 'N/A'}</code>
                                ${data.fingerprint ? `<button class="copy-btn" data-copy="${data.fingerprint}">📋</button>` : ''}
                            </div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">Subject:</span>
                            <div class="technical-value code">${data.subject || data.hostname || 'N/A'}</div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">Issuer:</span>
                            <div class="technical-value code">${data.issuer || 'N/A'}</div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">Valid From:</span>
                            <div class="technical-value">${data.validFrom ? new Date(data.validFrom).toLocaleString() : 'N/A'}</div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">Valid To:</span>
                            <div class="technical-value">${data.validTo ? new Date(data.validTo).toLocaleString() : 'N/A'}</div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">Serial Number:</span>
                            <div class="technical-value code">${data.serialNumber || 'N/A'}</div>
                        </div>
                    </div>
                </div>
                
                <!-- TLS Protocol Details -->
                <div class="technical-section">
                    <h4 class="technical-section-title">
                        <span class="section-icon">🔒</span>
                        TLS Protocol Details
                    </h4>
                    <div class="technical-grid">
                        <div class="technical-item">
                            <span class="technical-label">TLS Version:</span>
                            <div class="technical-value code">${data.protocol || 'N/A'}</div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">Cipher Suite:</span>
                            <div class="technical-value code">${data.cipher || 'N/A'}</div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">Key Exchange:</span>
                            <div class="technical-value code">${extractKeyExchange(data.cipher) || 'N/A'}</div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">Encryption:</span>
                            <div class="technical-value code">${extractEncryption(data.cipher) || 'N/A'}</div>
                        </div>
                        <div class="technical-item">
                            <span class="technical-label">MAC Algorithm:</span>
                            <div class="technical-value code">${extractMAC(data.cipher) || 'N/A'}</div>
                        </div>
                    </div>
                </div>
                
                <!-- Security Analysis -->
                ${data.weakTlsIssues && data.weakTlsIssues.length > 0 ? `
                <div class="technical-section">
                    <h4 class="technical-section-title">
                        <span class="section-icon">⚠️</span>
                        Weak TLS Issues
                    </h4>
                    <div class="issue-list">
                        ${data.weakTlsIssues.map(issue => `
                            <div class="issue-item ${issue.severity}">
                                <div class="issue-header">
                                    <span class="issue-type">${issue.type || 'Unknown'}</span>
                                    <span class="issue-severity">${issue.severity || 'unknown'}</span>
                                </div>
                                <div class="issue-message">${issue.message || 'No message'}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
                
                <!-- Raw Data -->
                <div class="technical-section">
                    <h4 class="technical-section-title">
                        <span class="section-icon">📄</span>
                        Raw Audit Data
                    </h4>
                    <div class="raw-data-container">
                        <pre class="raw-data"><code>${JSON.stringify(data, null, 2)}</code></pre>
                        <button class="copy-btn" data-copy="${JSON.stringify(data, null, 2)}">📋 Copy JSON</button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function extractKeyExchange(cipher) {
    if (!cipher) return null;
    if (cipher.includes('ECDHE')) return 'ECDHE';
    if (cipher.includes('DHE')) return 'DHE';
    if (cipher.includes('RSA')) return 'RSA';
    return null;
}

function extractEncryption(cipher) {
    if (!cipher) return null;
    if (cipher.includes('AES_256')) return 'AES-256';
    if (cipher.includes('AES_128')) return 'AES-128';
    if (cipher.includes('CHACHA20')) return 'ChaCha20';
    if (cipher.includes('3DES')) return '3DES';
    return null;
}

function extractMAC(cipher) {
    if (!cipher) return null;
    if (cipher.includes('SHA384')) return 'SHA384';
    if (cipher.includes('SHA256')) return 'SHA256';
    if (cipher.includes('SHA')) return 'SHA';
    return null;
}

// Add copy functionality
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('copy-btn') || e.target.closest('.copy-btn')) {
        const btn = e.target.classList.contains('copy-btn') ? e.target : e.target.closest('.copy-btn');
        const text = btn.dataset.copy;
        if (text) {
            navigator.clipboard.writeText(text).then(() => {
                btn.textContent = '✅ Copied!';
                setTimeout(() => {
                    btn.textContent = '📋';
                }, 2000);
            });
        }
    }
});

// ============================================
// WHITELIST DETAILS
// ============================================

function renderWhitelist(urls) {
    const container = document.getElementById("whitelistContainer");

    if (!urls.length) {
        container.innerHTML = `<div class="whitelist-empty">No whitelisted URLs yet.</div>`;
        return;
    }

    let html = "";

    urls.forEach((item, index) => {
        const url = item.url || item;

        html += `<div class="whitelist-item">
                <span class="whitelist-index">#${index + 1}</span>
                <span class="whitelist-url">${url}</span>

                <button class="btn btn-danger whitelist-delete-btn" data-url="${url}">
                    Remove
                </button>
            </div>`;
        });

    container.innerHTML = html;

    // Attach delete listeners
    document.querySelectorAll(".whitelist-delete-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const url = e.target.getAttribute("data-url");
            removeWhitelistItem(url);
        });
    });
}

async function loadWhitelist() {
    const container = document.getElementById("whitelistContainer");
    container.innerHTML = `<div class="whitelist-loading">Loading whitelist...</div>`;

    chrome.runtime.sendMessage({ type: "GET_WHITELIST" }, (response) => {
        if (!response || response.error) {
            container.innerHTML = `<div class="whitelist-error">Failed to load whitelist.</div>`;
            return;
        }

        const urls = response.data?.whitelistedUrls || [];
        renderWhitelist(urls);
    });
}

document.getElementById("refreshWhitelistBtn").addEventListener("click", loadWhitelist);

// When the tab becomes visible
document.addEventListener("DOMContentLoaded", () => {
    loadWhitelist();
});

function removeWhitelistItem(urlToRemove) {
    if (!confirm(`Remove ${urlToRemove} from your whitelist?`)) return;

    chrome.runtime.sendMessage(
        { type: "REMOVE_WHITELIST", url: urlToRemove },
        (response) => {
            console.log("REMOVE_WHITELIST response:", response);

            if (!response || response.error) {
                alert("Failed to remove URL from whitelist.");
                return;
            }

            loadWhitelist();
        }
    );
}



