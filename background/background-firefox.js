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
            
            // Get certificate history for scoring
            const certHistory = await getCertificateHistory(hostname);
            
            // Calculate anomaly score
            const analysis = calculateAnomalyScore(securityInfo, hostname, certHistory);
            certData.anomalyScore = analysis;
            
            browserAPI.storage.local.set({
              [`certificate_${hostname}_${Date.now()}`]: {
                ...certData,
                hostname,
                tabId: details.tabId,
                timestamp: Date.now()
              }
            });
            
            console.log('🔐 Certificate info stored for', hostname, 'Score:', analysis.score);
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

// Get certificate history for a hostname
async function getCertificateHistory(hostname) {
  try {
    const storageData = await browserAPI.storage.local.get();
    const certKeys = Object.keys(storageData).filter(key => 
      key.startsWith(`certificate_${hostname}_`)
    );
    
    return certKeys
      .map(key => storageData[key])
      .filter(data => data && data.certificate && data.timestamp)
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 10); // Keep last 10 certificates
  } catch (error) {
    console.error('Error getting certificate history:', error);
    return [];
  }
}

// Check if hostname is a CDN
function isCDN(hostname) {
  const cdnPatterns = [
    /cloudflare/i,
    /cloudfront/i,
    /akamaized/i,
    /akamai/i,
    /fastly/i,
    /\.cdn\./i,
    /cdn\./i
  ];
  return cdnPatterns.some(pattern => pattern.test(hostname));
}

// Calculate anomaly score
function calculateAnomalyScore(securityInfo, hostname, certHistory) {
  if (!securityInfo || !securityInfo.certificates || securityInfo.certificates.length === 0) {
    return {
      score: 0,
      confidence: 0,
      severity: 'secure',
      breakdown: {},
      findings: []
    };
  }

  const cert = securityInfo.certificates[0];
  const isCDNDomain = isCDN(hostname);
  let score = 0;
  let confidence = 100;
  const breakdown = {};
  const findings = [];

  // Check expiration
  if (cert.validity && cert.validity.end) {
    const expirationDate = new Date(cert.validity.end);
    const now = new Date();
    const daysUntilExpiration = Math.floor((expirationDate - now) / (1000 * 60 * 60 * 24));
    
    if (expirationDate < now) {
      score += 30;
      breakdown.expiration = 30;
      findings.push({ type: 'expired', message: `Certificate expired ${Math.abs(daysUntilExpiration)} days ago`, points: 30 });
    } else if (daysUntilExpiration < 7) {
      score += 15;
      breakdown.expiration = 15;
      findings.push({ type: 'expiring_soon', message: `Certificate expires in ${daysUntilExpiration} days`, points: 15 });
    } else {
      breakdown.expiration = 0;
    }
  }

  // Check TLS version
  const tlsVersion = securityInfo.protocolVersion || '';
  if (tlsVersion === 'TLSv1.0' || tlsVersion === 'TLSv1.1') {
    score += 20;
    breakdown.tlsVersion = 20;
    findings.push({ type: 'weak_tls', message: `Using ${tlsVersion} (should use TLS 1.2+)`, points: 20 });
  } else {
    breakdown.tlsVersion = 0;
  }

  // Check cipher suite
  const cipherSuite = securityInfo.cipherSuite || '';
  const weakCiphers = ['RC4', '3DES', 'MD5', 'DES', 'NULL'];
  const hasWeakCipher = weakCiphers.some(cipher => cipherSuite.includes(cipher));
  if (hasWeakCipher) {
    score += 15;
    breakdown.cipher = 15;
    findings.push({ type: 'weak_cipher', message: `Weak cipher detected: ${cipherSuite}`, points: 15 });
  } else {
    breakdown.cipher = 0;
  }

  // Check certificate chain
  const chainLength = securityInfo.certificates.length;
  if (chainLength < 2) {
    score += 15;
    confidence -= 10;
    breakdown.chain = 15;
    findings.push({ type: 'incomplete_chain', message: `Incomplete certificate chain (${chainLength} certs)`, points: 15 });
  } else {
    breakdown.chain = 0;
  }

  // Check if self-signed (issuer same as subject)
  const subject = cert.subject || '';
  const issuer = cert.issuer || (securityInfo.certificates.length > 1 ? securityInfo.certificates[1].subject : '');
  if (subject === issuer && subject !== '') {
    score += 35;
    breakdown.selfSigned = 35;
    findings.push({ type: 'self_signed', message: 'Self-signed certificate detected', points: 35 });
  } else {
    breakdown.selfSigned = 0;
  }

  // Check hostname mismatch (simplified - Firefox handles this, but we can check subject)
  if (subject && !subject.includes(hostname) && !hostname.includes(subject.replace(/CN=/i, '').trim())) {
    // This is a simplified check - Firefox would reject mismatches before we see them
    // But we can flag suspicious patterns
    const subjectDomain = subject.match(/CN=([^,]+)/i);
    if (subjectDomain && !hostname.includes(subjectDomain[1]) && !subjectDomain[1].includes(hostname)) {
      score += 35;
      breakdown.hostnameMismatch = 35;
      findings.push({ type: 'hostname_mismatch', message: `Hostname mismatch: ${hostname} vs ${subjectDomain[1]}`, points: 35 });
    } else {
      breakdown.hostnameMismatch = 0;
    }
  } else {
    breakdown.hostnameMismatch = 0;
  }

  // Check certificate changes (if history available)
  if (certHistory.length > 0 && !isCDNDomain) {
    const lastCert = certHistory[0];
    const timeDiff = Date.now() - lastCert.timestamp;
    const hoursDiff = timeDiff / (1000 * 60 * 60);
    
    if (lastCert.certificate && lastCert.certificate.fingerprint !== generateFingerprint(cert)) {
      if (hoursDiff < 1) {
        score += 10;
        breakdown.certChange = 10;
        findings.push({ type: 'cert_changed', message: 'Certificate changed less than 1 hour ago', points: 10 });
      } else {
        breakdown.certChange = 0;
      }
    } else {
      breakdown.certChange = 0;
    }

    // Check issuer changes
    if (lastCert.certificate && lastCert.certificate.issuer !== issuer) {
      if (hoursDiff < 1) {
        score += 5;
        breakdown.issuerChange = 5;
        findings.push({ type: 'issuer_changed', message: 'Certificate issuer changed less than 1 hour ago', points: 5 });
      } else {
        breakdown.issuerChange = 0;
      }
    } else {
      breakdown.issuerChange = 0;
    }
  } else {
    breakdown.certChange = 0;
    breakdown.issuerChange = 0;
    if (certHistory.length === 0) {
      confidence -= 15; // No history
    }
  }

  // Check Let's Encrypt
  if (issuer.includes("Let's Encrypt") || issuer.includes('Lets Encrypt')) {
    score += 5;
    breakdown.letsEncrypt = 5;
    findings.push({ type: 'lets_encrypt', message: "Let's Encrypt certificate", points: 5, info: true });
  } else {
    breakdown.letsEncrypt = 0;
  }

  // Check validity period (if less than 1 day)
  if (cert.validity && cert.validity.start && cert.validity.end) {
    const validityDays = (new Date(cert.validity.end) - new Date(cert.validity.start)) / (1000 * 60 * 60 * 24);
    if (validityDays < 1) {
      score += 10;
      breakdown.shortValidity = 10;
      findings.push({ type: 'short_validity', message: 'Certificate validity period less than 1 day', points: 10 });
    } else {
      breakdown.shortValidity = 0;
    }
  } else {
    breakdown.shortValidity = 0;
  }

  // Check certificate age (if less than 24 hours old)
  if (cert.validity && cert.validity.start) {
    const certAge = (Date.now() - new Date(cert.validity.start)) / (1000 * 60 * 60);
    if (certAge < 24) {
      confidence -= 10;
    }
  }

  // CDN adjustment
  if (isCDNDomain) {
    confidence -= 5;
    // Skip cert change checks for CDNs (already done above)
  }

  // Stability bonus (certificate stable for >14 days)
  if (certHistory.length > 0) {
    const oldestCert = certHistory[certHistory.length - 1];
    if (oldestCert.timestamp) {
      const stabilityDays = (Date.now() - oldestCert.timestamp) / (1000 * 60 * 60 * 24);
      if (stabilityDays > 14) {
        confidence = Math.min(100, confidence + 10);
      }
    }
  }

  // Critical findings boost confidence
  const hasCritical = findings.some(f => f.points >= 30);
  if (hasCritical) {
    confidence = Math.max(95, confidence);
  }

  // Cap score at 100
  score = Math.min(100, score);

  // Determine severity
  let severity = 'secure';
  if (score >= 50) {
    severity = 'critical';
  } else if (score >= 20) {
    severity = 'warning';
  }

  // Ensure confidence is 0-100
  confidence = Math.max(0, Math.min(100, confidence));

  return {
    score,
    confidence,
    severity,
    breakdown,
    findings
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
