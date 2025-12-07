// ============================================
// Gone Phishin' - Simplified Dashboard
// ============================================

let currentFilter = 'all';

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    console.log('📊 Dashboard initializing...');
    
    try {
        setupEventListeners();
        await loadOverview();
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
            setFilter(filter);
        });
    });
    
    // View all history button
    const viewAllBtn = document.getElementById('viewAllHistoryBtn');
    if (viewAllBtn) {
        viewAllBtn.addEventListener('click', () => {
            switchTab('history');
        });
    }
    
    // Whitelist refresh
    const refreshWhitelistBtn = document.getElementById('refreshWhitelistBtn');
    if (refreshWhitelistBtn) {
        refreshWhitelistBtn.addEventListener('click', () => {
            loadWhitelist();
        });
    }
}

function initializeTabs() {
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
    if (tabName === 'overview') {
        loadOverview();
    } else if (tabName === 'history') {
        loadHistory();
    } else if (tabName === 'whitelist') {
        loadWhitelist();
    }
    // How It Works and Transparency tabs are static HTML, no data loading needed
}

// ============================================
// OVERVIEW TAB
// ============================================

async function loadOverview() {
    try {
        await loadStatistics();
        await loadProtectionStatus();
        await loadRecentActivityPreview();
    } catch (error) {
        console.error('Error loading overview:', error);
    }
}

async function loadStatistics() {
    try {
        const storageData = await chrome.storage.local.get();
        
        // HTTPS upgrades
        const totalUpgrades = storageData.totalUpgrades || 0;
        document.getElementById('totalUpgrades').textContent = totalUpgrades.toLocaleString();
        
        // Threats detected (from heuristics)
        const heuristicsKeys = Object.keys(storageData).filter(key => key.startsWith('heuristics_'));
        const threatsCount = heuristicsKeys.filter(key => {
            const data = storageData[key];
            return data && (data.severity === 'critical' || data.severity === 'warning' || data.severity === 'high');
        }).length;
        document.getElementById('threatsDetected').textContent = threatsCount.toLocaleString();
        
        // Sites analyzed (unique hostnames)
        const uniqueHostnames = new Set();
        heuristicsKeys.forEach(key => {
            if (storageData[key] && storageData[key].hostname) {
                uniqueHostnames.add(storageData[key].hostname);
            }
        });
        document.getElementById('sitesProtected').textContent = uniqueHostnames.size.toLocaleString();
        
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

async function loadProtectionStatus() {
    try {
        // Check URLScan.io status
        const storageData = await chrome.storage.local.get();
        const urlScanKeys = Object.keys(storageData).filter(key => key.startsWith('urlscan_'));
        
        let urlScanStatus = 'Checking...';
        if (urlScanKeys.length > 0) {
            // Get the most recent URLScan result
            const latestKey = urlScanKeys.sort().pop();
            const urlScanData = storageData[latestKey];
            
            if (urlScanData) {
                if (urlScanData.unavailable) {
                    urlScanStatus = 'Unavailable';
                } else if (urlScanData.malicious) {
                    urlScanStatus = 'Active';
                } else {
                    urlScanStatus = 'Active';
                }
            }
        }
        
        const badge = document.getElementById('urlScanStatusBadge');
        if (badge) {
            badge.textContent = urlScanStatus;
            if (urlScanStatus === 'Unavailable') {
                badge.classList.remove('active');
            } else {
                badge.classList.add('active');
            }
        }
    } catch (error) {
        console.error('Error loading protection status:', error);
    }
}

async function loadRecentActivityPreview() {
    try {
        const storageData = await chrome.storage.local.get();
        
        // Get all heuristics entries
        const heuristicsKeys = Object.keys(storageData)
            .filter(key => key.startsWith('heuristics_'))
            .map(key => ({
                key,
                data: storageData[key],
                timestamp: storageData[key].timestamp || 0
            }))
            .sort((a, b) => b.timestamp - a.timestamp)
            .slice(0, 5); // Show only 5 most recent
        
        const container = document.getElementById('activityPreview');
        
        if (heuristicsKeys.length === 0) {
            container.innerHTML = `
                <div class="activity-empty">
                    <div class="empty-icon">📊</div>
                    <p>No activity yet. Visit websites to see analysis results here.</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = heuristicsKeys.map(item => {
            const data = item.data;
            const severity = data.severity || 'secure';
            const icon = severity === 'critical' ? '🚨' :
                        severity === 'warning' ? '⚠️' :
                        severity === 'high' ? '⚠️' :
                        '✅';
            
            return `
                <div class="activity-item-preview ${severity}">
                    <div class="activity-icon">${icon}</div>
                    <div class="activity-content">
                        <div class="activity-title">${data.hostname || 'Unknown'}</div>
                        <div class="activity-details">
                            <span class="activity-score">Score: ${data.threatScore !== undefined ? data.threatScore : (data.anomalyScore || 0)}</span>
                            <span class="activity-severity">${severity.toUpperCase()}</span>
                        </div>
                        <div class="activity-time">${getTimeAgo(data.timestamp)}</div>
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading recent activity preview:', error);
    }
}

// ============================================
// HISTORY TAB
// ============================================

async function loadHistory() {
    try {
        const storageData = await chrome.storage.local.get();
        
        // Get all heuristics entries
        const heuristicsKeys = Object.keys(storageData)
            .filter(key => key.startsWith('heuristics_'))
            .map(key => ({
                key,
                data: storageData[key],
                timestamp: storageData[key].timestamp || 0
            }))
            .sort((a, b) => b.timestamp - a.timestamp);
        
        // Filter by severity
        let filtered = heuristicsKeys;
        if (currentFilter === 'critical') {
            filtered = heuristicsKeys.filter(item => 
                item.data.severity === 'critical' || item.data.severity === 'high'
            );
        } else if (currentFilter === 'warning') {
            filtered = heuristicsKeys.filter(item => item.data.severity === 'warning');
        } else if (currentFilter === 'secure') {
            filtered = heuristicsKeys.filter(item => 
                item.data.severity === 'secure' || (!item.data.severity && ((item.data.threatScore !== undefined ? item.data.threatScore : item.data.anomalyScore) || 0) < 20)
            );
        }
        
        displayHistory(filtered);
    } catch (error) {
        console.error('Error loading history:', error);
    }
}

function displayHistory(items) {
    const container = document.getElementById('historyList');
    
    if (items.length === 0) {
        container.innerHTML = `
            <div class="activity-empty">
                <div class="empty-icon">📊</div>
                <h3>No History Found</h3>
                <p>No websites match the selected filter. Visit websites to see analysis results here.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = items.map(item => {
        const data = item.data;
        const severity = data.severity || 'secure';
        const icon = severity === 'critical' ? '🚨' :
                    severity === 'warning' ? '⚠️' :
                    severity === 'high' ? '⚠️' :
                    '✅';
        
        const issues = data.detectedIssues || [];
        const topIssues = issues.slice(0, 3);
        
        return `
            <div class="history-item ${severity}">
                <div class="history-icon">${icon}</div>
                <div class="history-content">
                    <div class="history-header">
                        <div class="history-title">${data.hostname || 'Unknown'}</div>
                        <div class="history-meta">
                            <span class="history-score">Score: ${data.threatScore !== undefined ? data.threatScore : (data.anomalyScore || 0)}</span>
                            <span class="history-severity">${severity.toUpperCase()}</span>
                        </div>
                    </div>
                    ${data.urlScan ? `
                        <div class="history-urlscan">
                            ${data.urlScan.unavailable ? 
                                '<span class="urlscan-status unavailable">⚠️ URLScan: Unavailable (backend not running)</span>' :
                                data.urlScan.malicious ? 
                                '<span class="urlscan-status malicious">🚨 URLScan: Malicious</span>' :
                                '<span class="urlscan-status safe">✅ URLScan: Verified Safe</span>'
                            }
                        </div>
                    ` : ''}
                    ${topIssues.length > 0 ? `
                        <div class="history-issues">
                            ${topIssues.map(issue => `
                                <span class="issue-tag">${issue.type || issue.message}</span>
                            `).join('')}
                            ${issues.length > 3 ? `<span class="more-issues">+${issues.length - 3} more</span>` : ''}
                        </div>
                    ` : ''}
                    <div class="history-footer">
                        <span class="history-time">${getTimeAgo(data.timestamp)}</span>
                        ${data.confidenceScore ? `<span class="history-confidence">Confidence: ${data.confidenceScore}%</span>` : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function setFilter(filter) {
    currentFilter = filter;
    
    // Update filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.filter === filter) {
            btn.classList.add('active');
        }
    });
    
    // Reload history
    loadHistory();
}

// ============================================
// WHITELIST TAB
// ============================================

async function loadWhitelist() {
    const container = document.getElementById('whitelistContainer');
    container.innerHTML = '<div class="whitelist-loading">Loading whitelist...</div>';

    chrome.runtime.sendMessage({ type: "GET_WHITELIST" }, (response) => {
        if (!response || response.error) {
            container.innerHTML = '<div class="whitelist-error">Failed to load whitelist.</div>';
            return;
        }

        const urls = response.data?.whitelistedUrls || [];
        renderWhitelist(urls);
    });
}

function renderWhitelist(urls) {
    const container = document.getElementById('whitelistContainer');

    if (!urls.length) {
        container.innerHTML = '<div class="whitelist-empty">No whitelisted URLs yet. Sites you trust can be added to bypass some security checks.</div>';
        return;
    }

    let html = '<div class="whitelist-list">';
    urls.forEach((item, index) => {
        const url = item.url || item;
        html += `
            <div class="whitelist-item">
                <span class="whitelist-url">${url}</span>
                <button class="btn btn-danger whitelist-delete-btn" data-url="${url}">
                    Remove
                </button>
            </div>
        `;
    });
    html += '</div>';
    container.innerHTML = html;

    // Attach delete listeners
    document.querySelectorAll(".whitelist-delete-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const url = e.target.getAttribute("data-url");
            removeWhitelistItem(url);
        });
    });
}

function removeWhitelistItem(urlToRemove) {
    if (!confirm(`Remove ${urlToRemove} from your whitelist?`)) return;

    chrome.runtime.sendMessage(
        { type: "REMOVE_WHITELIST", url: urlToRemove },
        (response) => {
            if (!response || response.error) {
                alert("Failed to remove URL from whitelist.");
                return;
            }
            loadWhitelist();
        }
    );
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
