// ============================================
// Gone Phishin' - Concise Popup with Real-time Updates
// ============================================

let currentTab = null;
let updateInterval = null;
let lastAnomalyScore = 0;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🛡️ Gone Phishin\' Extension - Initializing...');
    
    try {
        // Get current active tab
        await refreshCurrentTab();
        
        // Initial load
        await updatePopup();
        
        // Setup event listeners
        setupEventListeners();
        
        // Start real-time updates (every 1 second)
        startRealTimeUpdates();
        
        // Listen for tab changes
        chrome.tabs.onActivated.addListener(async () => {
            await refreshCurrentTab();
            await updatePopup();
        });
        
        chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
            if (changeInfo.status === 'complete' && tabId === currentTab?.id) {
                await updatePopup();
            }
        });
        
        console.log('✅ Extension initialized');
    } catch (error) {
        console.error('❌ Initialization error:', error);
        showError('Failed to initialize');
    }
});

// Refresh current tab reference
async function refreshCurrentTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tabs[0];
    console.log('📑 Current active tab:', currentTab?.id, currentTab?.url);
}

function getCurrentHostname() {
    try {
        if (!currentTab || !currentTab.url) return null;

        // Ignore browser / extension internal pages
        const url = new URL(currentTab.url);
        if (['chrome:', 'edge:', 'about:', 'chrome-extension:']
            .some(p => url.protocol.startsWith(p))) {
            return null;
        }
        return url.hostname;
    } catch (e) {
        console.error('Failed to get hostname:', e);
        return null;
    }
}


// Setup event listeners
function setupEventListeners() {
    document.getElementById('refreshBtn').addEventListener('click', async () => {
        await updatePopup();
    });
    
    document.getElementById('openDashboard').addEventListener('click', () => {
        chrome.tabs.create({ url: chrome.runtime.getURL('popup/dashboard/dashboard.html') });
    });

    // login button
    document.getElementById("loginBtn").addEventListener("click", async () => {
        chrome.runtime.sendMessage({ type: "LOGIN" },
            (res) => {
                if (!res || !res.success) {
                    return alert("Failed to login: " + (res?.message || "Unknown error"));
                }
                if (res.data?.loginUrl) {
                    // opens a google login window
                    chrome.windows.create({
                    url: res.data.loginUrl,
                    type: "popup",
                    width: 500,
                    height: 700,
                    });
                }
            }
        ); 
    });

    const whitelistBtn = document.getElementById('whitelistBtn');
    if (whitelistBtn) {
        whitelistBtn.addEventListener('click', () => {
            const hostname = getCurrentHostname();
            if (!hostname) {
                alert('No active website to whitelist.');
                return;
            }

            const fullUrl = currentTab.url

            chrome.runtime.sendMessage(
                { type: "ADD_WHITELIST", url: fullUrl }, // need to full url, backend takes care of stripping it
                (res) => {
                    if (!res) {
                        alert('No response from background script.');
                        return;
                    }

                    if (res.error) {
                        // Handle invalid / expired token
                        if (res.status === 401 || res.status === 403) {
                            alert('Your login token is invalid or expired. Please hit "Login" again and then retry whitelisting.');
                        } else {
                            alert('Failed to add to whitelist:\n' + (res.text || res.message || 'Unknown error'));
                        }
                        return;
                    }

                    if (res.success) {
                        alert(`${hostname} was added to your whitelist ✅`);
                    } else {
                        alert('Unexpected response from whitelist API.');
                    }
                }
            );
        });
    }

    
    document.getElementById('closeSiteModal').addEventListener('click', () => {
        document.getElementById('siteInfoModal').style.display = 'none';
    });
}

// Start real-time updates
function startRealTimeUpdates() {
    // Update immediately
    updatePopup();
    
    // Then update every second
    updateInterval = setInterval(async () => {
        await updatePopup();
    }, 1000);
}

// Stop updates when popup closes
window.addEventListener('beforeunload', () => {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
});

// Main update function
async function updatePopup() {
    if (!currentTab || !currentTab.url) {
        updateSiteInfo('No active tab', 'Inactive');
        return;
    }

    try {
        const url = new URL(currentTab.url);
        const hostname = url.hostname;
        
        // Update site URL
        document.getElementById('currentSiteUrl').textContent = hostname;
        
        // Update connection status
        const isHttps = url.protocol.startsWith('https:');
        document.getElementById('connectionStatus').textContent = isHttps ? 'HTTPS' : 'HTTP';
        
        // Get heuristics data
        const heuristicsData = await getHeuristicsData(hostname);
        
        if (heuristicsData && heuristicsData.tabId === currentTab.id) {
            updateAnomalyScore(heuristicsData);
            updateThreats(heuristicsData);
            updateStatus(heuristicsData);
            updateUrlScanStatus(heuristicsData);
        } else {
            // No heuristics data yet - show initial state
            updateAnomalyScore({ threatScore: 0, confidenceScore: 0, severity: 'secure' });
            document.getElementById('siteStatus').textContent = 'No threats detected';
            document.getElementById('threatsSection').style.display = 'none';
            document.getElementById('urlScanItem').style.display = 'none';
            
            // Show a helpful message
            console.log('⏳ No heuristics data found for this tab yet');
        }
        
        // Update last scan time
        updateLastScan(heuristicsData?.timestamp);
        
    } catch (error) {
        console.error('Error updating popup:', error);
        showError('Error loading data');
    }
}

// Get heuristics data for current tab
async function getHeuristicsData(hostname) {
    if (!currentTab || !currentTab.id) {
        console.log('⚠️ No current tab available');
        return null;
    }
    
    const tabId = currentTab.id;
    const storageData = await chrome.storage.local.get();
    
    console.log('🔍 Looking for heuristics data:', {
        tabId,
        hostname,
        totalKeys: Object.keys(storageData).length,
        heuristicsKeys: Object.keys(storageData).filter(k => k.startsWith('heuristics_')).length
    });
    
    // Find most recent heuristics entry for this specific tab
    const heuristicsKeys = Object.keys(storageData).filter(key => {
        const data = storageData[key];
        return key.startsWith(`heuristics_${tabId}_`) && 
               data.hostname === hostname &&
               data.tabId === tabId;
    });
    
    console.log('📊 Found heuristics keys for this tab:', heuristicsKeys.length);
        
        if (heuristicsKeys.length === 0) {
        // Fallback: try to find any heuristics for this hostname (in case tab ID changed)
        const fallbackKeys = Object.keys(storageData).filter(key => {
            const data = storageData[key];
            return key.startsWith('heuristics_') && data.hostname === hostname;
        });
        
        if (fallbackKeys.length > 0) {
            console.log('⚠️ Found fallback heuristics (tab ID mismatch):', fallbackKeys.length);
            const recentKey = fallbackKeys
                .map(key => ({ key, timestamp: storageData[key].timestamp || 0 }))
                .sort((a, b) => b.timestamp - a.timestamp)[0];
            return storageData[recentKey.key];
        }
        
        return null;
    }
    
    // Get most recent
    const recentKey = heuristicsKeys
        .map(key => ({ key, timestamp: storageData[key].timestamp || 0 }))
        .sort((a, b) => b.timestamp - a.timestamp)[0];
    
    console.log('✅ Found heuristics data:', {
        key: recentKey.key,
        threatScore: storageData[recentKey.key].threatScore || storageData[recentKey.key].anomalyScore,
        severity: storageData[recentKey.key].severity
    });
    
    return storageData[recentKey.key];
}

// Update anomaly score display (now uses unified threatScore)
function updateAnomalyScore(data) {
    // Support both unified threatScore and legacy anomalyScore
    const score = data.threatScore !== undefined ? data.threatScore : (data.anomalyScore || 0);
    const confidence = data.confidenceScore || 0;
    const severity = data.severity || 'secure';
    
    const scoreElement = document.getElementById('anomalyScore');
    const confidenceElement = document.getElementById('confidenceScore');
    const severityElement = document.getElementById('severityBadge');
    const scoreSection = document.querySelector('.score-section');
    
    // Animate score change
    if (score !== lastAnomalyScore) {
        scoreElement.classList.add('updating');
        setTimeout(() => {
            scoreElement.classList.remove('updating');
        }, 300);
        lastAnomalyScore = score;
    }
    
    // Update values
    scoreElement.textContent = score;
    confidenceElement.textContent = `Confidence: ${confidence}%`;
    severityElement.textContent = severity.toUpperCase();
    
    // Update severity badge class
    severityElement.className = 'severity-badge ' + severity;
    
    // Update section styling
    scoreSection.className = 'score-section ' + severity;
    
    // Update status dot
    const statusDot = document.getElementById('statusDot');
    statusDot.className = 'status-dot ' + severity;
}

// Update threats display
function updateThreats(data) {
    const threatsSection = document.getElementById('threatsSection');
    const threatsList = document.getElementById('threatsList');
    const threatCount = document.getElementById('threatCount');
    
    const issues = data.detectedIssues || [];
    
    if (issues.length === 0) {
        threatsSection.style.display = 'none';
        return;
    }
    
    threatsSection.style.display = 'block';
    threatCount.textContent = issues.length;
    
    // Clear and populate threats list
    threatsList.innerHTML = '';
    
    issues.forEach(issue => {
        const threatItem = document.createElement('div');
        threatItem.className = 'threat-item';
        
        const message = issue.message || issue.type || 'Unknown threat';
        const confidence = issue.confidence || 0;
        
        threatItem.innerHTML = `
            <span class="threat-message">${message}</span>
            <span class="threat-confidence">${confidence}%</span>
        `;
        
        threatsList.appendChild(threatItem);
    });
}

// Update status
function updateStatus(data) {
    const severity = data.severity || 'secure';
    const statusText = document.getElementById('siteStatus');
    const statusBadge = document.getElementById('statusText');
    
    const statusMessages = {
        secure: '✅ Site appears safe',
        warning: '⚠️ Suspicious patterns detected',
        critical: '🚨 High-risk threats detected'
    };
    
    statusText.textContent = statusMessages[severity] || 'Analyzing...';
    statusBadge.textContent = severity === 'secure' ? 'Active' : 'Alert';
}

// Update site info
function updateSiteInfo(url, status) {
    document.getElementById('currentSiteUrl').textContent = url;
    document.getElementById('siteStatus').textContent = status;
}

// Update last scan time
function updateLastScan(timestamp) {
    const lastScanElement = document.getElementById('lastScan');
    
    if (!timestamp) {
        lastScanElement.textContent = 'Never';
        return;
    }
    
    const now = Date.now();
    const diff = now - timestamp;
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    
    if (seconds < 10) {
        lastScanElement.textContent = 'Just now';
    } else if (seconds < 60) {
        lastScanElement.textContent = `${seconds}s ago`;
    } else if (minutes < 60) {
        lastScanElement.textContent = `${minutes}m ago`;
    } else {
        const hours = Math.floor(minutes / 60);
        lastScanElement.textContent = `${hours}h ago`;
    }
}

// Update URLScan status
function updateUrlScanStatus(heuristicsData) {
    const urlScanItem = document.getElementById('urlScanItem');
    const urlScanStatus = document.getElementById('urlScanStatus');
    
    if (!heuristicsData.urlScan) {
        // No URLScan data yet
        urlScanItem.style.display = 'none';
        return;
    }
    
    urlScanItem.style.display = 'flex';
    
    if (heuristicsData.urlScan.unavailable) {
        // URLScan backend unavailable
        urlScanStatus.textContent = '⚠️ Unavailable (backend not running)';
        urlScanStatus.className = 'info-value warning';
        urlScanStatus.title = 'URLScan.io service is unavailable. The backend server may not be running. This feature should be used when available.';
    } else if (heuristicsData.urlScan.malicious) {
        // URLScan marked as malicious
        urlScanStatus.textContent = '🚨 Malicious';
        urlScanStatus.className = 'info-value critical';
        urlScanStatus.title = 'URLScan.io flagged this URL as malicious';
    } else if (heuristicsData.urlScan.whitelisted) {
        // URL is whitelisted
        urlScanStatus.textContent = '☑️ Whitelisted';
        urlScanStatus.className = 'info-value secure';
        urlScanStatus.title = 'This URL is in your whitelist';

    } else {
        // URLScan marked as safe
        urlScanStatus.textContent = '✅ Verified Safe';
        urlScanStatus.className = 'info-value secure';
        urlScanStatus.title = 'URLScan.io verified this URL as safe';
    }
}

// Show error
function showError(message) {
    document.getElementById('siteStatus').textContent = `❌ ${message}`;
    document.getElementById('siteStatus').style.color = 'var(--danger)';
}

// Listen for heuristics updates from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'heuristicsResults') {
        // Trigger immediate update
        updatePopup();
    }
});
