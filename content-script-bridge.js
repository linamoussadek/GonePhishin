// Content script bridge to expose extension storage to page
// This allows the phishing test site to read heuristics data

(function() {
  'use strict';
  
  // Expose heuristics data to page via custom events (only for active tab)
  function exposeHeuristicsData() {
    // Get current tab ID
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) return;
      
      const currentTabId = tabs[0].id;
      const hostname = window.location.hostname;
      
      chrome.storage.local.get(null, (storageData) => {
        // Find most recent heuristics entry for this specific tab
        const heuristicsKeys = Object.keys(storageData).filter(key => {
          const data = storageData[key];
          return key.startsWith(`heuristics_${currentTabId}_`) && 
                 data.hostname === hostname &&
                 data.tabId === currentTabId;
        });
        
        if (heuristicsKeys.length > 0) {
          // Get most recent
          const recentKey = heuristicsKeys
            .map(key => ({ key, timestamp: storageData[key].timestamp || 0 }))
            .sort((a, b) => b.timestamp - a.timestamp)[0];
          
          const heuristicsData = storageData[recentKey.key];
          
          // Only expose if this is the active tab
          if (heuristicsData.tabId === currentTabId) {
            // Dispatch custom event with heuristics data
            window.dispatchEvent(new CustomEvent('extension-heuristics-update', {
              detail: heuristicsData
            }));
            
            // Also expose via window property for direct access
            window.extensionHeuristicsData = heuristicsData;
          }
        } else {
          // No data yet
          window.dispatchEvent(new CustomEvent('extension-heuristics-update', {
            detail: null
          }));
          window.extensionHeuristicsData = null;
        }
      });
    });
  }
  
  // Listen for storage changes
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local') {
      const heuristicsChanged = Object.keys(changes).some(key => 
        key.startsWith('heuristics_')
      );
      if (heuristicsChanged) {
        exposeHeuristicsData();
      }
    }
  });
  
  // Expose data immediately and then periodically
  exposeHeuristicsData();
  setInterval(exposeHeuristicsData, 500); // Update every 500ms
  
  console.log('🌉 Content script bridge active - exposing heuristics data to page');
})();

