// Gone Phishin' - Basic Setup
document.addEventListener('DOMContentLoaded', function() {
    console.log('Gone Phishin\' extension loaded');
    
    // Initialize extension
    initializeExtension();
    
    // Load HTTPS upgrade statistics
    loadHttpsStats();
    
    // Load TLS security status
    loadTlsStatus();
});

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});

function initializeExtension() {
    console.log('Initializing Gone Phishin\' extension...');
    
    // Basic setup complete
    // Core MITM detection features will be added in future commits
}

// Load and display HTTPS upgrade statistics
async function loadHttpsStats() {
    try {
        const data = await chrome.storage.local.get(['totalUpgrades', 'lastUpgrade']);
        
        // Update total upgrades count
        const totalUpgrades = data.totalUpgrades || 0;
        document.getElementById('totalUpgrades').textContent = totalUpgrades;
        
        // Update last upgrade info
        if (data.lastUpgrade) {
            const lastUpgradeSection = document.getElementById('lastUpgradeSection');
            const lastUpgradeElement = document.getElementById('lastUpgrade');
            
            const url = new URL(data.lastUpgrade.url);
            const timeAgo = getTimeAgo(data.lastUpgrade.timestamp);
            
            lastUpgradeElement.textContent = `${url.hostname} (${timeAgo})`;
            lastUpgradeSection.style.display = 'flex';
        }
    } catch (error) {
        console.error('Error loading HTTPS stats:', error);
    }
}

// Load and display TLS security status
async function loadTlsStatus() {
    try {
        // Get current active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});
        
        if (!tab || !tab.url) {
            document.getElementById('currentSite').textContent = 'No active tab';
            return;
        }

        const url = new URL(tab.url);
        document.getElementById('currentSite').textContent = url.hostname;

        // Only show TLS info for HTTPS sites
        if (!url.protocol.startsWith('https:')) {
            document.getElementById('certStatus').textContent = 'Not HTTPS';
            document.getElementById('notaryConsensus').textContent = 'N/A';
            document.getElementById('tlsVersion').textContent = 'N/A';
            document.getElementById('certIssuer').textContent = 'N/A';
            return;
        }

        // Get recent audit logs for this hostname
        const storageData = await chrome.storage.local.get();
        
        // First try to get test data (for debugging)
        const testKey = `test_${url.hostname}`;
        if (storageData[testKey]) {
            console.log('🧪 Using test data for popup:', storageData[testKey]);
            const testData = storageData[testKey];
            
            // Update TLS status display
            document.getElementById('certStatus').textContent = testData.severity || 'Unknown';
            document.getElementById('tlsVersion').textContent = testData.protocol || 'Unknown';
            document.getElementById('certIssuer').textContent = testData.issuer || 'Unknown';
            document.getElementById('notaryConsensus').textContent = 'Test mode - notary data available';
            
            return;
        }
        
        const auditKeys = Object.keys(storageData).filter(key => 
            key.startsWith('audit_') && storageData[key].hostname === url.hostname
        );

        if (auditKeys.length > 0) {
            // Get the most recent audit entry
            const recentAudit = auditKeys
                .map(key => ({ key, timestamp: storageData[key].timestamp }))
                .sort((a, b) => b.timestamp - a.timestamp)[0];

            const auditData = storageData[recentAudit.key];
            
            // Update TLS status display
            document.getElementById('certStatus').textContent = auditData.severity || 'Unknown';
            document.getElementById('tlsVersion').textContent = auditData.protocol || 'Unknown';
            document.getElementById('certIssuer').textContent = auditData.issuer || 'Unknown';
            
            if (auditData.consensus) {
                const consensus = auditData.consensus;
                let consensusText = consensus.message || 'Unknown';
                
                // Add warning for unreachable notaries
                if (consensus.consensus === 'no_data') {
                    consensusText = '⚠️ Notary servers unreachable';
                } else if (consensus.consensus === 'mitm_detected') {
                    consensusText = '🚨 MITM detected';
                } else if (consensus.consensus === 'mixed') {
                    consensusText = '⚠️ Mixed notary responses';
                }
                
                document.getElementById('notaryConsensus').textContent = consensusText;
            } else {
                document.getElementById('notaryConsensus').textContent = 'No notary data';
            }

            // Show security alerts if any
            if (auditData.severity === 'critical' || auditData.severity === 'warning') {
                showSecurityAlerts(auditData);
            }
        } else {
            document.getElementById('certStatus').textContent = 'No data';
            document.getElementById('notaryConsensus').textContent = 'No data';
            document.getElementById('tlsVersion').textContent = 'No data';
            document.getElementById('certIssuer').textContent = 'No data';
        }

    } catch (error) {
        console.error('Error loading TLS status:', error);
        document.getElementById('currentSite').textContent = 'Error loading status';
    }
}

// Show security alerts in the popup
function showSecurityAlerts(auditData) {
    const alertsSection = document.getElementById('securityAlerts');
    const alertsList = document.getElementById('alertsList');
    
    alertsSection.style.display = 'block';
    alertsList.innerHTML = '';

    // Create alert items
    if (auditData.consensus && auditData.consensus.severity !== 'low') {
        const alertItem = document.createElement('div');
        alertItem.className = 'alert-item';
        alertItem.innerHTML = `
            <div class="alert-title">${auditData.consensus.message}</div>
            <div class="alert-details">Notary consensus: ${auditData.consensus.consensus}</div>
        `;
        alertsList.appendChild(alertItem);
    }

    if (auditData.weakTlsIssues && auditData.weakTlsIssues.length > 0) {
        auditData.weakTlsIssues.forEach(issue => {
            const alertItem = document.createElement('div');
            alertItem.className = 'alert-item';
            alertItem.innerHTML = `
                <div class="alert-title">${issue.message}</div>
                <div class="alert-details">Type: ${issue.type}, Severity: ${issue.severity}</div>
            `;
            alertsList.appendChild(alertItem);
        });

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});
    }
}

// Helper function to format time ago
function getTimeAgo(timestamp) {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

document.getElementById("openDashboard").addEventListener("click", async () => {
  const url = chrome.runtime.getURL("popup/dashboard/dashboard.html");
  await chrome.tabs.create({ url }); 
});

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});

// Test TLS button
document.getElementById("testTls").addEventListener("click", async () => {
  console.log('🧪 Manual TLS test button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});
  
  if (tab && tab.url) {
    console.log('🧪 Testing TLS for:', tab.url);
    
    // Send message to background script
    chrome.runtime.sendMessage({
      action: 'testTls',
      url: tab.url
    }, (response) => {
      console.log('🧪 Test response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});
  } else {
    console.log('❌ No active tab found');
  }
});

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});

// Clear rate limit button
document.getElementById("clearRateLimit").addEventListener("click", async () => {
  console.log('🧹 Clear rate limit button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🧹 Clearing rate limit for:', hostname);
    
    // Send message to background script
    chrome.runtime.sendMessage({
      action: 'clearRateLimit',
      hostname: hostname
    }, (response) => {
      console.log('🧹 Clear rate limit response:', response);
    });

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});
  } else {
    console.log('❌ No active tab found');
  }
});

// Retry notary check button
document.getElementById("retryNotary").addEventListener("click", async () => {
  console.log('🔄 Retry notary check button clicked');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    const hostname = new URL(tab.url).hostname;
    console.log('🔄 Retrying notary check for:', hostname);
    
    // Send message to background script to retry with bypass cache
    chrome.runtime.sendMessage({
      action: 'retryNotary',
      hostname: hostname
    }, (response) => {
      console.log('🔄 Retry notary response:', response);
      
      // Reload the TLS status after a short delay
      setTimeout(() => {
        loadTlsStatus();
      }, 2000);
    });
  } else {
    console.log('❌ No active tab found');
  }
});

