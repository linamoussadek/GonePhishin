// ============================================
// Gone Phishin' - Warning Page
// HTTPS Downgrade Block Handler
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🔒 Warning page loaded');
    
    // Parse target URL from query parameters
    const params = new URLSearchParams(location.search);
    const original = params.get("original") || "";
    
    // Display target URL
    if (original) {
        document.getElementById("targetUrl").textContent = original;
    } else {
        document.getElementById("targetUrl").textContent = "Unknown target URL";
    }
    
    // Set up event listeners
    setupEventListeners();
});

function setupEventListeners() {
    // Go Back button
    document.getElementById("goBack").addEventListener("click", () => {
        if (history.length > 1) {
            history.back();
        } else {
            window.close();
        }
    });

    // Proceed button (with warning)
    document.getElementById("proceed").addEventListener("click", async () => {
        const params = new URLSearchParams(location.search);
        const original = params.get("original") || "";
        
        if (!original) {
            alert('No target URL available');
            return;
        }
        
        // Show confirmation dialog
        if (confirm('⚠️ WARNING: You are about to proceed to an insecure HTTP connection. Your data could be intercepted or modified. Are you absolutely sure you want to proceed?')) {
            // Log the override
            try {
                const url = new URL(original);
                const auditKey = `downgrade_override_${url.hostname}_${Date.now()}`;
                chrome.storage.local.set({
                    [auditKey]: {
                        type: 'downgrade_override',
                        hostname: url.hostname,
                        targetUrl: original,
                        timestamp: Date.now(),
                        userAction: 'proceed_anyway'
                    }
                });
            } catch (error) {
                console.error('Error logging override:', error);
            }
            
            // Open the HTTP URL in a new tab
            await chrome.tabs.create({ url: original, active: true });
            window.close();
        }
    });
}
