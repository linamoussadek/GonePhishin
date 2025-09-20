// Gone Phishin' - Basic Setup
document.addEventListener('DOMContentLoaded', function() {
    console.log('Gone Phishin\' extension loaded');
    
    // Initialize extension
    initializeExtension();
});

function initializeExtension() {
    console.log('Initializing Gone Phishin\' extension...');
    
    // Basic setup complete
    // Core MITM detection features will be added in future commits
}

document.getElementById("openDashboard").addEventListener("click", async () => {
  const url = chrome.runtime.getURL("dashboard/dashboard.html");
  await chrome.tabs.create({ url }); 
});

