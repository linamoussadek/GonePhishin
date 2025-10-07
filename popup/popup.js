// Gone Phishin' - Basic Setup
document.addEventListener('DOMContentLoaded', function() {
    console.log('Gone Phishin\' extension loaded');
    
    // Initialize extension
    initializeExtension();
    
    // Load HTTPS upgrade statistics
    loadHttpsStats();
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

