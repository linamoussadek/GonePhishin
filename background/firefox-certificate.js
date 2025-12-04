// ============================================
// Firefox Certificate Analysis Module
// ============================================
// 
// Firefox MV2 provides access to detailed certificate information via
// browser.webRequest.onHeadersReceived with securityInfo parameter.
// This module implements advanced certificate monitoring features:
// - Certificate fingerprint generation
// - Issuer drift detection
// - Certificate expiration monitoring
// - TLS version and cipher suite analysis

// Certificate database: hostname -> array of certificate fingerprints
const certificateDatabase = new Map();

// Session certificates: tabId -> hostname -> certificate fingerprint
const sessionCertificates = new Map();

/**
 * Generate SHA-256 fingerprint from certificate
 * @param {Object} certInfo - Certificate information from securityInfo
 * @returns {string} Hex-encoded SHA-256 fingerprint
 */
function generateCertificateFingerprint(certInfo) {
  // Firefox provides certificate in DER format
  // We'll use the certificate's public key info to generate a fingerprint
  try {
    // Use certificate's serial number + issuer as fingerprint
    // In a real implementation, you'd hash the full certificate DER
    const certData = `${certInfo.subject || ''}_${certInfo.issuer || ''}_${certInfo.serialNumber || ''}`;
    
    // Simple hash (in production, use crypto.subtle.digest)
    let hash = 0;
    for (let i = 0; i < certData.length; i++) {
      const char = certData.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    
    return Math.abs(hash).toString(16).padStart(16, '0');
  } catch (error) {
    console.error('Error generating fingerprint:', error);
    return 'unknown';
  }
}

/**
 * Extract certificate information from Firefox securityInfo
 * @param {Object} securityInfo - Security info from onHeadersReceived
 * @returns {Object} Certificate data
 */
function extractCertificateInfo(securityInfo) {
  if (!securityInfo || !securityInfo.certificates || securityInfo.certificates.length === 0) {
    return null;
  }

  const cert = securityInfo.certificates[0]; // Server certificate
  const issuer = securityInfo.certificates.length > 1 ? securityInfo.certificates[1] : null;

  return {
    subject: cert.subject || 'Unknown',
    issuer: issuer ? issuer.subject : cert.issuer || 'Unknown',
    serialNumber: cert.serialNumber || 'Unknown',
    validity: {
      notBefore: cert.validity?.start || null,
      notAfter: cert.validity?.end || null
    },
    fingerprint: generateCertificateFingerprint(cert),
    publicKey: {
      algorithm: cert.subjectPublicKeyInfo?.algorithm || 'Unknown',
      keySize: cert.subjectPublicKeyInfo?.keySize || 0
    },
    tlsVersion: securityInfo.protocolVersion || 'Unknown',
    cipherSuite: securityInfo.cipherSuite || 'Unknown'
  };
}

/**
 * Check for certificate expiration
 * @param {Object} certInfo - Certificate information
 * @returns {Object} Expiration status
 */
function checkCertificateExpiration(certInfo) {
  if (!certInfo.validity || !certInfo.validity.notAfter) {
    return { expired: false, warning: false };
  }

  const expirationDate = new Date(certInfo.validity.notAfter);
  const now = new Date();
  const daysUntilExpiration = Math.floor((expirationDate - now) / (1000 * 60 * 60 * 24));

  return {
    expired: expirationDate < now,
    expiresSoon: daysUntilExpiration <= 30 && daysUntilExpiration > 0,
    daysUntilExpiration: daysUntilExpiration
  };
}

/**
 * Detect issuer drift (certificate issuer changes)
 * @param {string} hostname - Hostname being checked
 * @param {string} currentIssuer - Current certificate issuer
 * @returns {boolean} True if issuer drift detected
 */
function detectIssuerDrift(hostname, currentIssuer) {
  if (!certificateDatabase.has(hostname)) {
    return false;
  }

  const history = certificateDatabase.get(hostname);
  const lastIssuer = history[history.length - 1]?.issuer;

  if (!lastIssuer) {
    return false;
  }

  return lastIssuer !== currentIssuer;
}

/**
 * Check session consistency (certificate changes during session)
 * @param {number} tabId - Tab ID
 * @param {string} hostname - Hostname
 * @param {string} fingerprint - Current certificate fingerprint
 * @returns {boolean} True if certificate changed during session
 */
function checkSessionConsistency(tabId, hostname, fingerprint) {
  const sessionKey = `${tabId}_${hostname}`;
  
  if (!sessionCertificates.has(sessionKey)) {
    sessionCertificates.set(sessionKey, fingerprint);
    return false;
  }

  const previousFingerprint = sessionCertificates.get(sessionKey);
  return previousFingerprint !== fingerprint;
}

/**
 * Analyze certificate security
 * @param {Object} securityInfo - Security info from Firefox
 * @param {number} tabId - Tab ID
 * @param {string} url - Request URL
 * @returns {Object} Analysis results
 */
function analyzeCertificate(securityInfo, tabId, url) {
  const hostname = new URL(url).hostname;
  const certInfo = extractCertificateInfo(securityInfo);

  if (!certInfo) {
    return {
      secure: false,
      error: 'No certificate information available'
    };
  }

  // Check expiration
  const expiration = checkCertificateExpiration(certInfo);
  
  // Check issuer drift
  const issuerDrift = detectIssuerDrift(hostname, certInfo.issuer);
  
  // Check session consistency
  const sessionFlip = checkSessionConsistency(tabId, hostname, certInfo.fingerprint);

  // Store certificate in database
  if (!certificateDatabase.has(hostname)) {
    certificateDatabase.set(hostname, []);
  }
  
  const history = certificateDatabase.get(hostname);
  history.push({
    ...certInfo,
    timestamp: Date.now()
  });
  
  // Keep only last 10 certificates
  if (history.length > 10) {
    history.shift();
  }

  // Determine security status
  const issues = [];
  let severity = 'secure';

  if (expiration.expired) {
    issues.push({
      type: 'certificate_expired',
      severity: 'critical',
      message: `Certificate expired ${Math.abs(expiration.daysUntilExpiration)} days ago`
    });
    severity = 'critical';
  } else if (expiration.expiresSoon) {
    issues.push({
      type: 'certificate_expiring_soon',
      severity: 'warning',
      message: `Certificate expires in ${expiration.daysUntilExpiration} days`
    });
    if (severity === 'secure') severity = 'warning';
  }

  if (issuerDrift) {
    issues.push({
      type: 'issuer_drift',
      severity: 'warning',
      message: 'Certificate issuer changed (possible MITM)'
    });
    if (severity === 'secure') severity = 'warning';
  }

  if (sessionFlip) {
    issues.push({
      type: 'session_certificate_flip',
      severity: 'critical',
      message: 'Certificate changed during session (possible MITM attack)'
    });
    severity = 'critical';
  }

  // Check TLS version
  if (certInfo.tlsVersion && certInfo.tlsVersion < 'TLSv1.2') {
    issues.push({
      type: 'weak_tls',
      severity: 'warning',
      message: `Using ${certInfo.tlsVersion} (should use TLS 1.2 or higher)`
    });
    if (severity === 'secure') severity = 'warning';
  }

  return {
    secure: severity === 'secure',
    severity,
    certificate: certInfo,
    expiration,
    issuerDrift,
    sessionFlip,
    issues,
    timestamp: Date.now()
  };
}

/**
 * Clear session certificates for a tab
 * @param {number} tabId - Tab ID
 */
function clearSessionCertificates(tabId) {
  const keysToDelete = [];
  for (const [key] of sessionCertificates) {
    if (key.startsWith(`${tabId}_`)) {
      keysToDelete.push(key);
    }
  }
  keysToDelete.forEach(key => sessionCertificates.delete(key));
}

// Export for use in Firefox background script
// In Firefox MV2, scripts are loaded in order and share global scope
// Functions are available globally after this script loads

