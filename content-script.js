// Content script to trigger TLS verification on page load
console.log('🔧 Content script loaded for notary requests');

// Listen for page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', triggerTlsCheck);
} else {
  triggerTlsCheck();
}

function triggerTlsCheck() {
  console.log('🔧 Content script ready for notary requests');
  
  // Only trigger for HTTPS pages
  if (location.protocol === 'https:') {
    console.log('🌐 HTTPS page detected, triggering TLS check');
    
    // Send message to background script
    chrome.runtime.sendMessage({
      action: 'triggerTlsCheck',
      url: location.href,
      hostname: location.hostname
    });
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'executeNotaryRequest') {
    // Execute notary request in page context
    fetch(request.url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'GonePhishin-Extension/1.0'
      }
    })
    .then(response => response.json())
    .then(data => {
      sendResponse({ success: true, data });
    })
    .catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    
    return true; // Keep message channel open for async response
  }
});