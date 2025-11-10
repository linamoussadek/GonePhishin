// ============================================
// Gone Phishin' - Professional Popup UI
// Capstone Project - Cybersecurity Extension
// ============================================

// Global state
let currentTab = null;
let currentSiteData = null;
let protectionLayersData = {};

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🛡️ Gone Phishin\' Extension - Initializing...');
    
    try {
        // Get current tab
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        currentTab = tabs[0];
        
        // Initialize UI
        await initializeUI();
        
        // Load all data
        await loadAllData();
        
        // Setup event listeners
        setupEventListeners();
        
        // Start auto-refresh
        startAutoRefresh();
        
        console.log('✅ Extension initialized successfully');
    } catch (error) {
        console.error('❌ Initialization error:', error);
        showError('Failed to initialize extension');
    }
});

// ============================================
// INITIALIZATION
// ============================================

async function initializeUI() {
    // Set initial states
    updateGlobalStatus('active');
    updateCurrentSite('Loading...', 'checking');
}

async function loadAllData() {
    // Load in parallel for better performance
    await Promise.all([
        loadCurrentSiteData(),
        loadProtectionLayers(),
        loadStatistics(),
        loadRecentActivity()
    ]);
}

// ============================================
// CURRENT SITE DATA
// ============================================

async function loadCurrentSiteData() {
    if (!currentTab || !currentTab.url) {
        updateCurrentSite('No active tab', 'inactive');
        return;
    }

    try {
        const url = new URL(currentTab.url);
        const hostname = url.hostname;
        
        // Update site URL
        document.getElementById('currentSiteUrl').textContent = hostname;
        
        // Only process HTTPS sites
        if (!url.protocol.startsWith('https:')) {
            updateCurrentSite('Not HTTPS', 'warning');
            hideQuickStats();
            return;
        }

        // Get audit data from storage
        const storageData = await chrome.storage.local.get();
        
        // Try test data first (for debugging)
        const testKey = `test_${hostname}`;
        if (storageData[testKey]) {
            currentSiteData = storageData[testKey];
            updateCurrentSiteFromData(currentSiteData, hostname);
            return;
        }
        
        // Get most recent audit entry
        const auditKeys = Object.keys(storageData).filter(key => 
            key.startsWith('audit_') && storageData[key].hostname === hostname
        );

        if (auditKeys.length > 0) {
            const recentAudit = auditKeys
                .map(key => ({ key, timestamp: storageData[key].timestamp }))
                .sort((a, b) => b.timestamp - a.timestamp)[0];

            currentSiteData = storageData[recentAudit.key];
            updateCurrentSiteFromData(currentSiteData, hostname);
        } else {
            updateCurrentSite('No security data', 'checking');
            hideQuickStats();
        }
    } catch (error) {
        console.error('Error loading current site data:', error);
        updateCurrentSite('Error loading data', 'error');
    }
}

function updateCurrentSiteFromData(data, hostname) {
    const severity = data.severity || 'unknown';
    const statusText = getSeverityText(severity);
    
    updateCurrentSite(statusText, severity);
    updateSecurityBadge(severity, statusText);
    updateQuickStats(data);
    updateTimestamp(data.timestamp);
    
    // Show alerts if needed
    if (severity === 'critical' || severity === 'warning') {
        showAlerts(data);
    } else {
        hideAlerts();
    }
}

function updateCurrentSite(statusText, severity) {
    const statusIndicator = document.getElementById('siteStatusIndicator');
    const statusTextEl = document.getElementById('siteStatusText');
    const siteCard = document.getElementById('currentSiteCard');
    
    statusTextEl.textContent = statusText;
    statusIndicator.className = `status-indicator ${severity}`;
    siteCard.className = `card current-site-card ${severity}`;
}

function updateSecurityBadge(severity, text) {
    const badge = document.getElementById('securityBadge');
    const badgeIcon = document.getElementById('badgeIcon');
    const badgeText = document.getElementById('badgeText');
    
    badge.className = `security-badge ${severity}`;
    
    const icons = {
        secure: '🔒',
        warning: '⚠️',
        critical: '🚨',
        checking: '⏳'
    };
    
    badgeIcon.textContent = icons[severity] || '🔒';
    badgeText.textContent = text;
}

function updateQuickStats(data) {
    const quickStats = document.getElementById('quickStats');
    quickStats.style.display = 'grid';
    
    document.getElementById('tlsVersionQuick').textContent = data.protocol || '-';
    document.getElementById('certIssuerQuick').textContent = 
        data.issuer ? data.issuer.replace('CN=', '').substring(0, 20) + '...' : '-';
    
    const consensus = data.consensus?.message || 'No data';
    document.getElementById('notaryConsensusQuick').textContent = 
        consensus.length > 15 ? consensus.substring(0, 15) + '...' : consensus;
}

function hideQuickStats() {
    document.getElementById('quickStats').style.display = 'none';
}

function updateTimestamp(timestamp) {
    if (!timestamp) return;
    
    const timeAgo = getTimeAgo(timestamp);
    document.getElementById('siteTimestamp').textContent = timeAgo;
}

function getSeverityText(severity) {
    const texts = {
        secure: 'Secure connection verified',
        warning: 'Security warnings detected',
        critical: 'Critical security threat detected',
        checking: 'Analyzing security...',
        unknown: 'Unknown security status'
    };
    return texts[severity] || texts.unknown;
}

// ============================================
// PROTECTION LAYERS
// ============================================

async function loadProtectionLayers() {
    await Promise.all([
        updateHTTPSLayer(),
        updateTLSLayer(),
        updateNotaryLayer(),
        updateHeuristicsLayer()
    ]);
}

async function updateHTTPSLayer() {
    const layer = document.getElementById('layerHttps');
    const status = document.getElementById('httpsStatus');
    const indicator = document.getElementById('httpsIndicator');
    const progress = document.getElementById('httpsProgress').querySelector('.progress-bar');
    
    // HTTPS enforcement is always active
    status.querySelector('.status-text').textContent = 'Active';
    indicator.className = 'layer-status-indicator secure';
    progress.className = 'progress-bar secure';
    progress.style.width = '100%';
    
    protectionLayersData.https = { status: 'active', secure: true };
}

async function updateTLSLayer() {
    if (!currentSiteData) {
        setLayerChecking('layerTls', 'tls');
        return;
    }
    
    const layer = document.getElementById('layerTls');
    const status = document.getElementById('tlsStatus');
    const indicator = document.getElementById('tlsIndicator');
    const progress = document.getElementById('tlsProgress').querySelector('.progress-bar');
    
    const severity = currentSiteData.severity || 'checking';
    const statusText = severity === 'secure' ? 'Verified' : 
                      severity === 'warning' ? 'Warnings' : 
                      severity === 'critical' ? 'Threat Detected' : 'Verifying...';
    
    status.querySelector('.status-text').textContent = statusText;
    indicator.className = `layer-status-indicator ${severity}`;
    progress.className = `progress-bar ${severity}`;
    progress.style.width = severity === 'secure' ? '100%' : severity === 'checking' ? '50%' : '75%';
    
    protectionLayersData.tls = { 
        status: severity, 
        secure: severity === 'secure',
        data: currentSiteData 
    };
}

async function updateNotaryLayer() {
    if (!currentSiteData || !currentSiteData.notaryResults) {
        setLayerChecking('layerNotary', 'notary');
        return;
    }
    
    const notaryResults = currentSiteData.notaryResults;
    const consensus = currentSiteData.consensus;
    
    const layer = document.getElementById('layerNotary');
    const status = document.getElementById('notaryStatus');
    const indicator = document.getElementById('notaryIndicator');
    const progress = document.getElementById('notaryProgress').querySelector('.progress-bar');
    const metrics = document.getElementById('notaryMetrics');
    
    let severity = 'checking';
    let statusText = 'Querying...';
    
    if (consensus) {
        severity = consensus.severity === 'low' ? 'secure' : 
                  consensus.severity === 'medium' ? 'warning' : 
                  consensus.severity === 'critical' ? 'critical' : 'checking';
        statusText = consensus.message || 'Verifying...';
    }
    
    if (notaryResults.successful > 0) {
        statusText = `${notaryResults.successful}/${notaryResults.total} notaries responded`;
        metrics.style.display = 'flex';
        document.getElementById('notaryQueried').textContent = `${notaryResults.successful}/${notaryResults.total}`;
        document.getElementById('notaryConsensusValue').textContent = 
            consensus?.consensus === 'consistent' ? 'Agree' : 
            consensus?.consensus === 'mitm_detected' ? 'Disagree' : 'Mixed';
    }
    
    status.querySelector('.status-text').textContent = statusText;
    indicator.className = `layer-status-indicator ${severity}`;
    progress.className = `progress-bar ${severity}`;
    progress.style.width = notaryResults.successful > 0 ? '100%' : '50%';
    
    protectionLayersData.notary = { 
        status: severity, 
        secure: severity === 'secure',
        data: { notaryResults, consensus }
    };
}

async function updateHeuristicsLayer() {
    if (!currentTab || !currentTab.url) {
        setLayerChecking('layerHeuristics', 'heuristics');
        return;
    }
    
    try {
        const url = new URL(currentTab.url);
        const hostname = url.hostname;
        
        const storageData = await chrome.storage.local.get();
        const heuristicsKeys = Object.keys(storageData).filter(key => 
            key.startsWith('heuristics_') && storageData[key].hostname === hostname
        );
        
        if (heuristicsKeys.length === 0) {
            setLayerChecking('layerHeuristics', 'heuristics');
            return;
        }
        
        const recentHeuristics = heuristicsKeys
            .map(key => ({ key, timestamp: storageData[key].timestamp }))
            .sort((a, b) => b.timestamp - a.timestamp)[0];
        
        const heuristicsData = storageData[recentHeuristics.key];
        
        const layer = document.getElementById('layerHeuristics');
        const status = document.getElementById('heuristicsStatus');
        const indicator = document.getElementById('heuristicsIndicator');
        const progress = document.getElementById('heuristicsProgress').querySelector('.progress-bar');
        const metrics = document.getElementById('heuristicsMetrics');
        
        const anomalyScore = heuristicsData.anomalyScore || 0;
        const severity = anomalyScore === 0 ? 'secure' : 
                        anomalyScore < 3 ? 'warning' : 'critical';
        const statusText = anomalyScore === 0 ? 'No threats detected' : 
                         `Anomaly score: ${anomalyScore}`;
        
        status.querySelector('.status-text').textContent = statusText;
        indicator.className = `layer-status-indicator ${severity}`;
        progress.className = `progress-bar ${severity}`;
        progress.style.width = '100%';
        
        metrics.style.display = 'flex';
        document.getElementById('anomalyScore').textContent = anomalyScore;
        document.getElementById('externalLinksCount').textContent = heuristicsData.externalLinks || 0;
        
        protectionLayersData.heuristics = { 
            status: severity, 
            secure: severity === 'secure',
            data: heuristicsData 
        };
    } catch (error) {
        console.error('Error loading heuristics:', error);
        setLayerChecking('layerHeuristics', 'heuristics');
    }
}

function setLayerChecking(layerId, layerName) {
    const layer = document.getElementById(layerId);
    const status = document.getElementById(`${layerName}Status`);
    const indicator = document.getElementById(`${layerName}Indicator`);
    const progress = document.getElementById(`${layerName}Progress`).querySelector('.progress-bar');
    
    status.querySelector('.status-text').textContent = 'Checking...';
    indicator.className = 'layer-status-indicator checking';
    progress.className = 'progress-bar';
    progress.style.width = '50%';
}

// ============================================
// STATISTICS
// ============================================

async function loadStatistics() {
    try {
        const storageData = await chrome.storage.local.get();
        
        // Count HTTPS upgrades
        const totalUpgrades = storageData.totalUpgrades || 0;
        document.getElementById('totalUpgrades').textContent = totalUpgrades.toLocaleString();
        
        // Count protected sites (unique hostnames in audit logs)
        const auditKeys = Object.keys(storageData).filter(key => key.startsWith('audit_'));
        const uniqueHostnames = new Set();
        auditKeys.forEach(key => {
            if (storageData[key].hostname) {
                uniqueHostnames.add(storageData[key].hostname);
            }
        });
        document.getElementById('sitesProtected').textContent = uniqueHostnames.size.toLocaleString();
        
        // Count threats blocked (critical severity audits)
        const threatsBlocked = auditKeys.filter(key => 
            storageData[key].severity === 'critical'
        ).length;
        document.getElementById('threatsBlocked').textContent = threatsBlocked.toLocaleString();
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

// ============================================
// RECENT ACTIVITY
// ============================================

async function loadRecentActivity() {
    try {
        const storageData = await chrome.storage.local.get();
        const timeline = document.getElementById('activityTimeline');
        
        // Get all audit entries
        const auditKeys = Object.keys(storageData)
            .filter(key => key.startsWith('audit_'))
            .map(key => ({
                key,
                timestamp: storageData[key].timestamp,
                data: storageData[key]
            }))
            .sort((a, b) => b.timestamp - a.timestamp)
            .slice(0, 5); // Show last 5
        
        if (auditKeys.length === 0) {
            timeline.innerHTML = `
                <div class="activity-item">
                    <div class="activity-icon">📊</div>
                    <div class="activity-content">
                        <div class="activity-title">No recent activity</div>
                        <div class="activity-time">Visit a website to see activity</div>
                    </div>
                </div>
            `;
            return;
        }
        
        timeline.innerHTML = auditKeys.map(item => {
            const { data, timestamp } = item;
            const severity = data.severity || 'unknown';
            const icons = {
                secure: '✅',
                warning: '⚠️',
                critical: '🚨',
                unknown: '📊'
            };
            
            const title = severity === 'critical' ? 'Threat blocked' :
                         severity === 'warning' ? 'Security warning' :
                         severity === 'secure' ? 'Site verified' :
                         'Activity logged';
            
            return `
                <div class="activity-item">
                    <div class="activity-icon">${icons[severity]}</div>
                    <div class="activity-content">
                        <div class="activity-title">${title} - ${data.hostname}</div>
                        <div class="activity-time">${getTimeAgo(timestamp)}</div>
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading recent activity:', error);
    }
}

// ============================================
// ALERTS
// ============================================

function showAlerts(data) {
    const alertsCard = document.getElementById('alertsCard');
    const alertsList = document.getElementById('alertsList');
    const alertCount = document.getElementById('alertCount');
    
    alertsCard.style.display = 'block';
    alertsList.innerHTML = '';
    
    let alertCountNum = 0;
    
    // Notary consensus alerts
    if (data.consensus && data.consensus.severity !== 'low') {
        const alertItem = createAlertItem(
            data.consensus.message,
            data.consensus.details || `Consensus: ${data.consensus.consensus}`,
            data.consensus.severity
        );
        alertsList.appendChild(alertItem);
        alertCountNum++;
    }
    
    // Weak TLS issues
    if (data.weakTlsIssues && data.weakTlsIssues.length > 0) {
        data.weakTlsIssues.forEach(issue => {
            const alertItem = createAlertItem(
                issue.message,
                `Type: ${issue.type}, Severity: ${issue.severity}`,
                issue.severity
            );
            alertsList.appendChild(alertItem);
            alertCountNum++;
        });
    }
    
    // Heuristics issues
    if (data.detectedIssues && data.detectedIssues.length > 0) {
        data.detectedIssues.forEach(issue => {
            const alertItem = createAlertItem(
                issue.message,
                `Type: ${issue.type}`,
                issue.severity
            );
            alertsList.appendChild(alertItem);
            alertCountNum++;
        });
    }
    
    alertCount.textContent = alertCountNum;
}

function createAlertItem(title, details, severity) {
    const item = document.createElement('div');
    item.className = `alert-item ${severity === 'critical' ? '' : 'warning'}`;
    item.innerHTML = `
        <div class="alert-title">${title}</div>
        <div class="alert-details">${details}</div>
    `;
    return item;
}

function hideAlerts() {
    document.getElementById('alertsCard').style.display = 'none';
}

// ============================================
// EVENT LISTENERS
// ============================================

function setupEventListeners() {
    // Refresh button
    document.getElementById('refreshStatus').addEventListener('click', async () => {
        const btn = document.getElementById('refreshStatus');
        btn.disabled = true;
        btn.querySelector('.btn-icon').textContent = '⏳';
        
        await loadAllData();
        
        setTimeout(() => {
            btn.disabled = false;
            btn.querySelector('.btn-icon').textContent = '🔄';
        }, 1000);
    });
    
    // Dashboard button
    document.getElementById('openDashboard').addEventListener('click', async () => {
        const url = chrome.runtime.getURL('popup/dashboard/dashboard.html');
        await chrome.tabs.create({ url });
    });

    // login button
    document.getElementById("login").addEventListener("click", async () => {
        alert("login button clicked");
        // this token shouldn't be here - to be removed
        const token = 'bla';
        chrome.runtime.sendMessage({ type: "GET_ACCOUNT_CREATION_DATE", token }); // replace action w/ LOGIN
    });
    
    // View all activity
    document.getElementById('viewAllActivity').addEventListener('click', async () => {
        const url = chrome.runtime.getURL('popup/dashboard/dashboard.html');
        await chrome.tabs.create({ url });
    });
    
    // Site info button
    document.getElementById('siteInfoBtn').addEventListener('click', () => {
        showSiteInfoModal();
    });
    
    // Protection layer info buttons
    document.getElementById('layersInfoBtn').addEventListener('click', () => {
        showLayersInfoModal();
    });
    
    // Layer detail buttons
    document.querySelectorAll('.layer-details-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const layerName = e.target.dataset.layer;
            showLayerDetailsModal(layerName);
        });
    });
    
    // Modal close buttons
    document.getElementById('closeModal').addEventListener('click', () => {
        document.getElementById('layerModal').style.display = 'none';
    });
    
    document.getElementById('closeSiteModal').addEventListener('click', () => {
        document.getElementById('siteInfoModal').style.display = 'none';
    });
    
    // Close modals on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.closest('.modal').style.display = 'none';
            }
        });
    });
}

// ============================================
// MODALS
// ============================================

function showSiteInfoModal() {
    if (!currentSiteData) {
        alert('No site data available');
        return;
    }
    
    const modal = document.getElementById('siteInfoModal');
    const body = document.getElementById('siteInfoBody');
    
    body.innerHTML = `
        <div class="info-section">
            <h3>🔐 Certificate Information</h3>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Fingerprint:</span>
                    <span class="info-value">${currentSiteData.fingerprint || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Issuer:</span>
                    <span class="info-value">${currentSiteData.issuer || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">TLS Version:</span>
                    <span class="info-value">${currentSiteData.protocol || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Cipher Suite:</span>
                    <span class="info-value">${currentSiteData.cipher || 'N/A'}</span>
                </div>
            </div>
        </div>
        
        ${currentSiteData.notaryResults ? `
        <div class="info-section">
            <h3>🌐 Notary Consensus</h3>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Status:</span>
                    <span class="info-value">${currentSiteData.consensus?.message || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Notaries Queried:</span>
                    <span class="info-value">${currentSiteData.notaryResults.successful}/${currentSiteData.notaryResults.total}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Consensus:</span>
                    <span class="info-value">${currentSiteData.consensus?.consensus || 'N/A'}</span>
                </div>
            </div>
        </div>
        ` : ''}
        
        <div class="info-section">
            <h3>📊 Security Assessment</h3>
            <div class="assessment-badge ${currentSiteData.severity}">
                <span class="assessment-icon">${currentSiteData.severity === 'secure' ? '✅' : currentSiteData.severity === 'warning' ? '⚠️' : '🚨'}</span>
                <span class="assessment-text">${getSeverityText(currentSiteData.severity)}</span>
            </div>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function showLayersInfoModal() {
    const modal = document.getElementById('layerModal');
    const body = document.getElementById('modalBody');
    const title = document.getElementById('modalTitle');
    
    title.textContent = '🛡️ Protection Layers Explained';
    
    body.innerHTML = `
        <div class="layer-explanation">
            <div class="explanation-item">
                <div class="explanation-header">
                    <span class="explanation-icon">🔒</span>
                    <h3>HTTPS Enforcement</h3>
                </div>
                <p>Automatically upgrades insecure HTTP connections to secure HTTPS, preventing data interception and man-in-the-middle attacks. This is the first line of defense.</p>
                <div class="explanation-details">
                    <strong>How it works:</strong> Monitors all network requests and automatically redirects HTTP to HTTPS when available.
                </div>
            </div>
            
            <div class="explanation-item">
                <div class="explanation-header">
                    <span class="explanation-icon">🔐</span>
                    <h3>TLS Certificate Verification</h3>
                </div>
                <p>Validates SSL/TLS certificates to ensure they're legitimate, properly signed, and haven't been tampered with or expired.</p>
                <div class="explanation-details">
                    <strong>How it works:</strong> Analyzes certificate chain, validates signatures, checks expiration dates, and verifies certificate authority trust.
                </div>
            </div>
            
            <div class="explanation-item">
                <div class="explanation-header">
                    <span class="explanation-icon">🌐</span>
                    <h3>Notary Consensus</h3>
                </div>
                <p>Cross-validates certificates with multiple independent notary servers to detect man-in-the-middle attacks and certificate pinning violations.</p>
                <div class="explanation-details">
                    <strong>How it works:</strong> Queries multiple notary services simultaneously and compares their responses. If notaries disagree, it indicates a potential MITM attack.
                </div>
            </div>
            
            <div class="explanation-item">
                <div class="explanation-header">
                    <span class="explanation-icon">🔍</span>
                    <h3>Heuristic Analysis</h3>
                </div>
                <p>AI-powered content analysis that detects phishing attempts, suspicious patterns, and malicious behavior through machine learning algorithms.</p>
                <div class="explanation-details">
                    <strong>How it works:</strong> Analyzes page content, link patterns, form behavior, and other heuristics to identify potential threats that bypass traditional security checks.
                </div>
            </div>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function showLayerDetailsModal(layerName) {
    const modal = document.getElementById('layerModal');
    const body = document.getElementById('modalBody');
    const title = document.getElementById('modalTitle');
    
    const layerData = protectionLayersData[layerName];
    
    const layerInfo = {
        https: {
            title: '🔒 HTTPS Enforcement Details',
            description: 'Real-time HTTP to HTTPS upgrade protection',
            data: layerData
        },
        tls: {
            title: '🔐 TLS Verification Details',
            description: 'Certificate validation and security analysis',
            data: layerData
        },
        notary: {
            title: '🌐 Notary Consensus Details',
            description: 'Multi-notary cross-validation results',
            data: layerData
        },
        heuristics: {
            title: '🔍 Heuristic Analysis Details',
            description: 'AI-powered threat detection results',
            data: layerData
        }
    };
    
    const info = layerInfo[layerName] || layerInfo.https;
    title.textContent = info.title;
    
    if (layerData && layerData.data) {
        body.innerHTML = `
            <div class="layer-details">
                <p class="layer-description">${info.description}</p>
                <div class="details-section">
                    <h4>Status</h4>
                    <div class="status-badge ${layerData.status}">
                        ${layerData.secure ? '✅ Secure' : layerData.status === 'warning' ? '⚠️ Warning' : '🚨 Threat Detected'}
                    </div>
                </div>
                <div class="details-section">
                    <h4>Raw Data</h4>
                    <pre class="data-preview">${JSON.stringify(layerData.data, null, 2)}</pre>
                </div>
            </div>
        `;
    } else {
        body.innerHTML = `
            <div class="layer-details">
                <p class="layer-description">${info.description}</p>
                <div class="details-section">
                    <p>No detailed data available for this layer yet.</p>
                </div>
            </div>
        `;
    }
    
    modal.style.display = 'flex';
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function updateGlobalStatus(status) {
    const statusLabel = document.getElementById('statusLabel');
    const statusPulse = document.getElementById('statusPulse');
    
    statusLabel.textContent = status === 'active' ? 'Active' : 'Inactive';
    statusPulse.style.background = status === 'active' ? 'var(--status-secure)' : 'var(--status-warning)';
}

function getTimeAgo(timestamp) {
    if (!timestamp) return 'Unknown';
    
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    return new Date(timestamp).toLocaleDateString();
}

function showError(message) {
    const siteCard = document.getElementById('currentSiteCard');
    siteCard.innerHTML = `
        <div class="card-header">
            <h2>❌ Error</h2>
        </div>
        <div class="site-info" style="padding: 2rem; text-align: center;">
            <p style="color: var(--danger);">${message}</p>
        </div>
    `;
}

function startAutoRefresh() {
    // Refresh every 5 seconds
    setInterval(async () => {
        await loadCurrentSiteData();
        await loadProtectionLayers();
    }, 5000);
}

// ============================================
// STYLES FOR MODAL CONTENT
// ============================================

// Add dynamic styles for modal content
const style = document.createElement('style');
style.textContent = `
    .info-section {
        margin-bottom: 1.5rem;
        padding-bottom: 1.5rem;
        border-bottom: 1px solid var(--border);
    }
    
    .info-section:last-child {
        border-bottom: none;
    }
    
    .info-section h3 {
        font-size: 1rem;
        font-weight: 600;
        margin-bottom: 1rem;
        color: var(--text-primary);
    }
    
    .info-grid {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
    }
    
    .info-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.5rem;
        background: var(--bg-secondary);
        border-radius: var(--radius);
    }
    
    .info-label {
        font-weight: 500;
        color: var(--text-secondary);
        font-size: 0.875rem;
    }
    
    .info-value {
        font-family: 'Courier New', monospace;
        font-size: 0.75rem;
        color: var(--text-primary);
        word-break: break-all;
        text-align: right;
        max-width: 60%;
    }
    
    .assessment-badge {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 1rem;
        border-radius: var(--radius-md);
        font-weight: 600;
    }
    
    .assessment-badge.secure {
        background: rgba(16, 185, 129, 0.1);
        color: var(--status-secure);
    }
    
    .assessment-badge.warning {
        background: rgba(245, 158, 11, 0.1);
        color: var(--status-warning);
    }
    
    .assessment-badge.critical {
        background: rgba(239, 68, 68, 0.1);
        color: var(--status-critical);
    }
    
    .layer-explanation {
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
    }
    
    .explanation-item {
        padding: 1rem;
        background: var(--bg-secondary);
        border-radius: var(--radius-md);
        border-left: 4px solid var(--primary);
    }
    
    .explanation-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 0.5rem;
    }
    
    .explanation-icon {
        font-size: 1.5rem;
    }
    
    .explanation-item h3 {
        font-size: 1rem;
        font-weight: 600;
        color: var(--text-primary);
    }
    
    .explanation-item p {
        font-size: 0.875rem;
        color: var(--text-secondary);
        line-height: 1.6;
        margin-bottom: 0.5rem;
    }
    
    .explanation-details {
        font-size: 0.75rem;
        color: var(--text-tertiary);
        padding: 0.5rem;
        background: var(--bg-tertiary);
        border-radius: var(--radius);
        margin-top: 0.5rem;
    }
    
    .layer-details {
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }
    
    .layer-description {
        font-size: 0.875rem;
        color: var(--text-secondary);
        line-height: 1.6;
    }
    
    .details-section h4 {
        font-size: 0.875rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
        color: var(--text-primary);
    }
    
    .status-badge {
        display: inline-block;
        padding: 0.5rem 1rem;
        border-radius: var(--radius);
        font-size: 0.875rem;
        font-weight: 600;
    }
    
    .status-badge.secure {
        background: rgba(16, 185, 129, 0.1);
        color: var(--status-secure);
    }
    
    .status-badge.warning {
        background: rgba(245, 158, 11, 0.1);
        color: var(--status-warning);
    }
    
    .status-badge.critical {
        background: rgba(239, 68, 68, 0.1);
        color: var(--status-critical);
    }
    
    .data-preview {
        background: var(--bg-tertiary);
        padding: 1rem;
        border-radius: var(--radius);
        font-size: 0.75rem;
        overflow-x: auto;
        max-height: 300px;
        overflow-y: auto;
    }
`;
document.head.appendChild(style);
