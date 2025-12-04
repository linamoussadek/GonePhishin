// Content script to trigger TLS verification on page load
console.log('🔧 Content script loaded');

// Listen for page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', triggerTlsCheck);
} else {
  triggerTlsCheck();
}

function triggerTlsCheck() {
  console.log('🔧 Content script ready');
  
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
