// ============================================
// Firefox Background Script - Certificate Analysis Only
// ============================================
// 
// This script ONLY handles certificate analysis for Firefox.
// All other features (heuristics, URLScan) are Chrome-only.

const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

// Store security info for each tab
const tabSecurityInfo = new Map();

// Track all requestIds for each tab (most recent first)
const tabRequestIds = new Map();

// Listen for headers received to capture certificate info
browserAPI.webRequest.onHeadersReceived.addListener(
  async (details) => {
    // Process all HTTPS requests, prioritize main_frame
    if (details.url.startsWith('https://') && details.tabId >= 0) {
      try {
        // Get security info using the requestId from this event
        const securityInfo = await browserAPI.webRequest.getSecurityInfo(
          details.requestId,
          { certificateChain: true, rawDER: false }
        );
        
        // Store the security info for this tab (prioritize main_frame)
        if (securityInfo && securityInfo.certificates) {
          const existing = tabSecurityInfo.get(details.tabId);
          if (!existing || details.type === "main_frame") {
            tabSecurityInfo.set(details.tabId, {
              securityInfo: securityInfo,
              url: details.url,
              requestId: details.requestId,
              type: details.type,
              timestamp: Date.now()
            });
            
            // Also store in chrome.storage.local for popup access
            const hostname = new URL(details.url).hostname;
            const certData = extractCertificateData(securityInfo, hostname);
            
            browserAPI.storage.local.set({
              [`certificate_${hostname}_${Date.now()}`]: {
                ...certData,
                hostname,
                tabId: details.tabId,
                timestamp: Date.now()
              }
            });
            
            console.log('🔐 Certificate info stored for', hostname);
          }
        }
      } catch (error) {
        console.error('Error getting security info:', error);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

// Track all requestIds for each tab
browserAPI.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.url.startsWith('https://') && details.tabId >= 0) {
      // Store requestIds, with main_frame requests first in the array
      if (!tabRequestIds.has(details.tabId)) {
        tabRequestIds.set(details.tabId, []);
      }
      const requestIds = tabRequestIds.get(details.tabId);
      if (details.type === "main_frame") {
        requestIds.unshift(details.requestId); // Add main_frame requests at the beginning
      } else {
        requestIds.push(details.requestId); // Add other requests at the end
      }
    }
  },
  { urls: ["<all_urls>"] }
);

// Clean up when tabs are closed or updated
browserAPI.tabs.onRemoved.addListener((tabId) => {
  tabSecurityInfo.delete(tabId);
  tabRequestIds.delete(tabId);
});

browserAPI.tabs.onUpdated.addListener((tabId, changeInfo) => {
  // Clear security info when navigation starts (but keep requestIds for a bit)
  if (changeInfo.status === 'loading' && changeInfo.url) {
    tabSecurityInfo.delete(tabId);
  }
});

// Extract certificate data from securityInfo
function extractCertificateData(securityInfo, hostname) {
  if (!securityInfo || !securityInfo.certificates || securityInfo.certificates.length === 0) {
    return {
      secure: false,
      error: 'No certificate information available'
    };
  }

  const cert = securityInfo.certificates[0]; // Server certificate
  const issuer = securityInfo.certificates.length > 1 ? securityInfo.certificates[1] : cert;

  // Extract certificate fields
  const certData = {
    subject: cert.subject || cert.subjectPublicKeyInfo?.subject || 'Unknown',
    issuer: issuer.subject || issuer.subjectPublicKeyInfo?.subject || cert.issuer || 'Unknown',
    serialNumber: cert.serialNumber || 'Unknown',
    fingerprint: generateFingerprint(cert),
    tlsVersion: securityInfo.protocolVersion || 'Unknown',
    cipherSuite: securityInfo.cipherSuite || 'Unknown',
    validity: {
      notBefore: cert.validity?.start || null,
      notAfter: cert.validity?.end || null
    },
    publicKey: {
      algorithm: cert.subjectPublicKeyInfo?.algorithm || 'Unknown',
      keySize: cert.subjectPublicKeyInfo?.keySize || 0
    }
  };

  // Check expiration
  const expiration = checkExpiration(certData.validity);
  
  // Determine severity
  let severity = 'secure';
  const issues = [];
  
  if (expiration.expired) {
    severity = 'critical';
    issues.push({
      type: 'certificate_expired',
      severity: 'critical',
      message: `Certificate expired ${Math.abs(expiration.daysUntilExpiration)} days ago`
    });
  } else if (expiration.expiresSoon) {
    severity = 'warning';
    issues.push({
      type: 'certificate_expiring_soon',
      severity: 'warning',
      message: `Certificate expires in ${expiration.daysUntilExpiration} days`
    });
  }

  // Check TLS version
  if (certData.tlsVersion && certData.tlsVersion < 'TLSv1.2') {
    severity = severity === 'secure' ? 'warning' : severity;
    issues.push({
      type: 'weak_tls',
      severity: 'warning',
      message: `Using ${certData.tlsVersion} (should use TLS 1.2 or higher)`
    });
  }

  return {
    secure: severity === 'secure',
    severity,
    certificate: certData,
    expiration,
    issues,
    issuerDrift: false,
    sessionFlip: false
  };
}

// Generate fingerprint from certificate
function generateFingerprint(cert) {
  try {
    const certData = `${cert.subject || ''}_${cert.issuer || ''}_${cert.serialNumber || ''}`;
    let hash = 0;
    for (let i = 0; i < certData.length; i++) {
      const char = certData.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(16, '0');
  } catch (error) {
    return 'unknown';
  }
}

// Check certificate expiration
function checkExpiration(validity) {
  if (!validity || !validity.notAfter) {
    return { expired: false, warning: false };
  }

  const expirationDate = new Date(validity.notAfter);
  const now = new Date();
  const daysUntilExpiration = Math.floor((expirationDate - now) / (1000 * 60 * 60 * 24));

  return {
    expired: expirationDate < now,
    expiresSoon: daysUntilExpiration <= 30 && daysUntilExpiration > 0,
    daysUntilExpiration: daysUntilExpiration
  };
}

// Listen for messages from popup
browserAPI.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getSecurityInfo') {
    // Handle the request asynchronously
    handleGetSecurityInfo(message.tabId)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ 
        success: false, 
        error: error.message || 'Unknown error' 
      }));
    
    // Return true to indicate we will send a response asynchronously
    return true;
  }
  
  if (message.action === 'getCertificateData') {
    // Get certificate data from storage for a hostname
    const hostname = message.hostname;
    browserAPI.storage.local.get().then(storageData => {
      const certKeys = Object.keys(storageData).filter(key => 
        key.startsWith(`certificate_${hostname}_`)
      );
      
      if (certKeys.length === 0) {
        sendResponse({ success: false, error: 'No certificate data found' });
        return;
      }
      
      const recentKey = certKeys
        .map(key => ({ key, timestamp: storageData[key].timestamp || 0 }))
        .sort((a, b) => b.timestamp - a.timestamp)[0];
      
      sendResponse({ success: true, data: storageData[recentKey.key] });
    });
    return true;
  }
  
  return false;
});

// Async function to handle getting security info
async function handleGetSecurityInfo(tabId) {
  // First, check if we have stored security info
  const stored = tabSecurityInfo.get(tabId);
  
  if (stored && stored.securityInfo) {
    return { 
      success: true, 
      securityInfo: stored.securityInfo 
    };
  }
  
  // Fallback: try to get it using requestIds (try most recent first)
  const requestIds = tabRequestIds.get(tabId);
  if (requestIds && requestIds.length > 0) {
    // Try each requestId until we find one that works
    for (const requestId of requestIds) {
      try {
        const securityInfo = await browserAPI.webRequest.getSecurityInfo(
          requestId,
          { certificateChain: true, rawDER: false }
        );
        
        if (securityInfo && securityInfo.certificates) {
          // Store it for future use
          tabSecurityInfo.set(tabId, {
            securityInfo: securityInfo,
            url: null,
            requestId: requestId,
            type: null,
            timestamp: Date.now()
          });
          
          return { 
            success: true, 
            securityInfo: securityInfo 
          };
        }
      } catch (error) {
        // This requestId didn't work, try the next one
        console.log('RequestId failed, trying next:', error);
        continue;
      }
    }
  }
  
  // No security info available
  return { 
    success: false, 
    error: 'No security info available. Please refresh the page and try again.' 
  };
}
