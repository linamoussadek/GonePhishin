// ============================================
// Gone Phishin' - Firefox Popup (Certificate Focus)
// ============================================

let currentTab = null;
const browserAPI = typeof browser !== 'undefined' ? browser : chrome;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🛡️ Gone Phishin\' Firefox Extension - Initializing...');
    
    try {
        await refreshCurrentTab();
        await updateCertificateInfo();
        
        // Refresh every 2 seconds
        setInterval(async () => {
            await updateCertificateInfo();
        }, 2000);
        
        console.log('✅ Extension initialized');
    } catch (error) {
        console.error('❌ Initialization error:', error);
        showError('Failed to initialize');
    }
});

// Refresh current tab reference
async function refreshCurrentTab() {
    const tabs = await browserAPI.tabs.query({ active: true, currentWindow: true });
    currentTab = tabs[0];
    console.log('📑 Current active tab:', currentTab?.id, currentTab?.url);
}

// Main update function - fetch and display certificate info
async function updateCertificateInfo() {
    if (!currentTab || !currentTab.url) {
        updateSiteInfo('No active tab', 'Inactive');
        return;
    }

    try {
        const url = new URL(currentTab.url);
        const hostname = url.hostname;
        const isHttps = url.protocol.startsWith('https:');
        
        // Update site URL
        document.getElementById('currentSiteUrl').textContent = hostname;
        
        if (!isHttps) {
            document.getElementById('certificateStatus').textContent = 'HTTP (No Certificate)';
            document.getElementById('certificateStatus').className = 'error';
            document.getElementById('certificateDetails').innerHTML = '<p class="no-cert">This site uses HTTP and does not have a certificate.</p>';
            return;
        }
        
        // Try to get certificate data from storage first
        const storageData = await browserAPI.storage.local.get();
        const certKeys = Object.keys(storageData).filter(key => 
            key.startsWith(`certificate_${hostname}_`)
        );
        
        if (certKeys.length > 0) {
            // Get most recent certificate data
            const recentCertKey = certKeys
                .map(key => ({ key, timestamp: storageData[key].timestamp || 0 }))
                .sort((a, b) => b.timestamp - a.timestamp)[0];
            
            const certData = storageData[recentCertKey.key];
            
            if (certData && certData.certificate) {
                displayCertificateInfo(certData);
                return;
            }
        }
        
        // Fallback: Try to get security info directly from background script
        try {
            const response = await browserAPI.runtime.sendMessage({
                action: 'getSecurityInfo',
                tabId: currentTab.id
            });
            
            if (response && response.success && response.securityInfo) {
                // Extract and display certificate data
                const certData = extractCertificateDataFromSecurityInfo(response.securityInfo, hostname);
                displayCertificateInfo(certData);
                return;
            }
        } catch (error) {
            console.log('Could not get security info directly:', error);
        }
        
        // Still no data - show loading state
        document.getElementById('certificateStatus').textContent = 'HTTPS (Analyzing...)';
        document.getElementById('certificateStatus').className = 'valid';
        document.getElementById('certificateDetails').innerHTML = '<p class="loading">Certificate information will appear here once the page loads. Try refreshing the page if it takes too long.</p>';
        
    } catch (error) {
        console.error('Error updating certificate info:', error);
        showError('Error loading certificate data');
    }
}

// Extract certificate data from securityInfo
function extractCertificateDataFromSecurityInfo(securityInfo, hostname) {
    if (!securityInfo || !securityInfo.certificates || securityInfo.certificates.length === 0) {
        return {
            secure: false,
            error: 'No certificate information available'
        };
    }

    const cert = securityInfo.certificates[0];
    const issuer = securityInfo.certificates.length > 1 ? securityInfo.certificates[1] : cert;

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

    const expiration = checkExpiration(certData.validity);
    
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

// Display certificate information
function displayCertificateInfo(certData) {
    if (certData.error) {
        document.getElementById('certificateStatus').textContent = `HTTPS - ${certData.error}`;
        document.getElementById('certificateStatus').className = 'error';
        document.getElementById('certificateDetails').innerHTML = `<p class="error">${certData.error}</p>`;
        return;
    }

    const cert = certData.certificate;
    const expiration = certData.expiration || {};
    const issues = certData.issues || [];
    
    // Update status
    let statusText = 'Valid';
    let statusClass = 'valid';
    
    if (certData.severity === 'critical') {
        statusText = 'Critical Issues';
        statusClass = 'critical';
    } else if (certData.severity === 'warning') {
        statusText = 'Warnings';
        statusClass = 'warning';
    }
    
    document.getElementById('certificateStatus').textContent = `HTTPS - ${statusText}`;
    document.getElementById('certificateStatus').className = statusClass;
    
    // Build certificate details HTML
    let detailsHTML = '<div class="cert-info-grid">';
    
    // Subject
    if (cert.subject) {
        detailsHTML += `
            <div class="cert-info-item">
                <span class="cert-label">Subject:</span>
                <span class="cert-value">${escapeHtml(cert.subject)}</span>
            </div>
        `;
    }
    
    // Issuer
    if (cert.issuer) {
        detailsHTML += `
            <div class="cert-info-item">
                <span class="cert-label">Issuer:</span>
                <span class="cert-value">${escapeHtml(cert.issuer)}</span>
            </div>
        `;
    }
    
    // Serial Number
    if (cert.serialNumber && cert.serialNumber !== 'Unknown') {
        detailsHTML += `
            <div class="cert-info-item">
                <span class="cert-label">Serial Number:</span>
                <span class="cert-value">${escapeHtml(cert.serialNumber)}</span>
            </div>
        `;
    }
    
    // Fingerprint
    if (cert.fingerprint) {
        detailsHTML += `
            <div class="cert-info-item">
                <span class="cert-label">Fingerprint:</span>
                <span class="cert-value cert-fingerprint">${escapeHtml(cert.fingerprint)}</span>
            </div>
        `;
    }
    
    // TLS Version
    if (cert.tlsVersion && cert.tlsVersion !== 'Unknown') {
        detailsHTML += `
            <div class="cert-info-item">
                <span class="cert-label">TLS Version:</span>
                <span class="cert-value">${escapeHtml(cert.tlsVersion)}</span>
            </div>
        `;
    }
    
    // Cipher Suite
    if (cert.cipherSuite && cert.cipherSuite !== 'Unknown') {
        detailsHTML += `
            <div class="cert-info-item">
                <span class="cert-label">Cipher Suite:</span>
                <span class="cert-value">${escapeHtml(cert.cipherSuite)}</span>
            </div>
        `;
    }
    
    // Expiration
    if (expiration.expired) {
        detailsHTML += `
            <div class="cert-info-item cert-warning">
                <span class="cert-label">⚠️ Expiration:</span>
                <span class="cert-value">Expired ${Math.abs(expiration.daysUntilExpiration)} days ago</span>
            </div>
        `;
    } else if (expiration.expiresSoon) {
        detailsHTML += `
            <div class="cert-info-item cert-warning">
                <span class="cert-label">⚠️ Expiration:</span>
                <span class="cert-value">Expires in ${expiration.daysUntilExpiration} days</span>
            </div>
        `;
    } else if (expiration.daysUntilExpiration !== undefined) {
        detailsHTML += `
            <div class="cert-info-item">
                <span class="cert-label">Expiration:</span>
                <span class="cert-value">Valid for ${expiration.daysUntilExpiration} more days</span>
            </div>
        `;
    }
    
    // Validity dates
    if (cert.validity) {
        if (cert.validity.notBefore) {
            detailsHTML += `
                <div class="cert-info-item">
                    <span class="cert-label">Valid From:</span>
                    <span class="cert-value">${new Date(cert.validity.notBefore).toLocaleDateString()}</span>
                </div>
            `;
        }
        if (cert.validity.notAfter) {
            detailsHTML += `
                <div class="cert-info-item">
                    <span class="cert-label">Valid Until:</span>
                    <span class="cert-value">${new Date(cert.validity.notAfter).toLocaleDateString()}</span>
                </div>
            `;
        }
    }
    
    // Public Key Info
    if (cert.publicKey) {
        if (cert.publicKey.algorithm && cert.publicKey.algorithm !== 'Unknown') {
            detailsHTML += `
                <div class="cert-info-item">
                    <span class="cert-label">Key Algorithm:</span>
                    <span class="cert-value">${escapeHtml(cert.publicKey.algorithm)}</span>
                </div>
            `;
        }
        if (cert.publicKey.keySize && cert.publicKey.keySize > 0) {
            detailsHTML += `
                <div class="cert-info-item">
                    <span class="cert-label">Key Size:</span>
                    <span class="cert-value">${cert.publicKey.keySize} bits</span>
                </div>
            `;
        }
    }
    
    detailsHTML += '</div>';
    
    // Display issues if any
    if (issues.length > 0) {
        detailsHTML += '<div class="cert-issues">';
        detailsHTML += '<h3 class="issues-header">⚠️ Certificate Issues:</h3>';
        issues.forEach(issue => {
            const severityClass = issue.severity === 'critical' ? 'critical' : 'warning';
            detailsHTML += `
                <div class="cert-issue ${severityClass}">
                    <span class="issue-severity">${issue.severity.toUpperCase()}</span>
                    <span class="issue-message">${escapeHtml(issue.message)}</span>
                </div>
            `;
        });
        detailsHTML += '</div>';
    }
    
    document.getElementById('certificateDetails').innerHTML = detailsHTML;
}

// Helper functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function updateSiteInfo(url, status) {
    document.getElementById('currentSiteUrl').textContent = url;
    document.getElementById('certificateStatus').textContent = status;
}

function showError(message) {
    document.getElementById('certificateStatus').textContent = `Error: ${message}`;
    document.getElementById('certificateStatus').className = 'error';
    document.getElementById('certificateDetails').innerHTML = `<p class="error">${message}</p>`;
}
