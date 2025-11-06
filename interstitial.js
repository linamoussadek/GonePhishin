// ============================================
// Gone Phishin' - Interstitial Page
// Professional Security Alert Handler
// ============================================

let evidence = null;

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚨 Interstitial page loaded');
    
    // Parse evidence from URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const evidenceParam = urlParams.get('evidence');
    
    if (evidenceParam) {
        try {
            evidence = JSON.parse(decodeURIComponent(evidenceParam));
            displayEvidence(evidence);
        } catch (error) {
            console.error('Failed to parse evidence:', error);
            displayError();
        }
    } else {
        displayError();
    }

    // Set up event listeners
    setupEventListeners();
});

// ============================================
// DISPLAY EVIDENCE
// ============================================

function displayEvidence(evidence) {
    // Basic site information
    document.getElementById('hostname').textContent = evidence.hostname || 'Unknown';
    document.getElementById('localFingerprint').textContent = 
        formatFingerprint(evidence.fingerprint) || 'Unknown';
    document.getElementById('issuer').textContent = evidence.issuer || 'Unknown';
    document.getElementById('protocol').textContent = evidence.protocol || 'Unknown';
    document.getElementById('cipher').textContent = evidence.cipher || 'Unknown';
    
    // Set timestamp
    const timestamp = new Date(evidence.timestamp).toLocaleString();
    document.getElementById('timestamp').textContent = `Detected: ${timestamp}`;
    
    // Display notary results if available
    if (evidence.notaryResults) {
        displayNotaryResults(evidence.notaryResults, evidence.consensus);
    }
    
    // Display threat analysis
    if (evidence.consensus && evidence.consensus.severity === 'critical') {
        displayThreatAnalysis(evidence);
    }
}

function formatFingerprint(fingerprint) {
    if (!fingerprint) return 'N/A';
    if (fingerprint.length > 64) {
        return fingerprint.substring(0, 32) + '...' + fingerprint.substring(fingerprint.length - 16);
    }
    return fingerprint;
}

// ============================================
// NOTARY RESULTS
// ============================================

function displayNotaryResults(notaryResults, consensus) {
    const notarySection = document.getElementById('notarySection');
    const consensusSummary = document.getElementById('consensusSummary');
    const notaryResultsDiv = document.getElementById('notaryResults');
    const consensusExplanation = document.getElementById('consensusExplanation');
    
    notarySection.style.display = 'block';
    
    // Update consensus status
    const consensusStatus = document.getElementById('consensusStatus');
    let statusClass = 'checking';
    let statusIcon = '⏳';
    let statusText = 'Analyzing consensus...';
    
    if (consensus) {
        if (consensus.severity === 'critical') {
            statusClass = 'critical';
            statusIcon = '🚨';
            statusText = 'MITM Attack Detected';
        } else if (consensus.severity === 'medium') {
            statusClass = 'warning';
            statusIcon = '⚠️';
            statusText = 'Mixed Notary Responses';
        } else if (consensus.severity === 'low') {
            statusClass = 'secure';
            statusIcon = '✅';
            statusText = 'Notaries Agree - Secure';
        }
    }
    
    consensusStatus.className = `consensus-status ${statusClass}`;
    consensusStatus.querySelector('.status-icon').textContent = statusIcon;
    consensusStatus.querySelector('.status-text').textContent = statusText;
    
    // Display individual notary results
    if (notaryResults.votes && notaryResults.votes.length > 0) {
        notaryResultsDiv.innerHTML = '';
        
        notaryResults.votes.forEach((fingerprint, index) => {
            const notaryItem = document.createElement('div');
            notaryItem.className = 'notary-item success';
            notaryItem.innerHTML = `
                <div class="notary-endpoint">Notary Server ${index + 1}</div>
                <div class="notary-fingerprint">${formatFingerprint(fingerprint)}</div>
            `;
            notaryResultsDiv.appendChild(notaryItem);
        });
    }
    
    // Display consensus explanation
    if (consensus) {
        let explanation = '';
        if (consensus.consensus === 'mitm_detected') {
            explanation = `
                <strong>🚨 Critical Threat:</strong> Notary servers report different certificate fingerprints than your browser received. 
                This strongly indicates a man-in-the-middle attack. <strong>Do not proceed</strong> unless you're certain this is a trusted proxy.
            `;
        } else if (consensus.consensus === 'mixed') {
            explanation = `
                <strong>⚠️ Warning:</strong> Notary servers show mixed responses. This could indicate network issues, 
                a proxy, or a potential attack. Proceed with caution.
            `;
        } else if (consensus.consensus === 'consistent') {
            explanation = `
                <strong>✅ Secure:</strong> All notary servers agree on the certificate fingerprint. 
                However, there may be other security concerns detected.
            `;
        } else {
            explanation = consensus.details || 'Unable to determine consensus status.';
        }
        
        consensusExplanation.innerHTML = explanation;
    }
}

// ============================================
// THREAT ANALYSIS
// ============================================

function displayThreatAnalysis(evidence) {
    const threatAnalysis = document.getElementById('threatAnalysis');
    const threatDetails = document.getElementById('threatDetails');
    
    threatAnalysis.style.display = 'block';
    
    let threats = [];
    
    // MITM detection
    if (evidence.consensus && evidence.consensus.consensus === 'mitm_detected') {
        threats.push({
            title: '🚨 Man-in-the-Middle Attack',
            description: 'Certificate fingerprints from notary servers differ from your local certificate. This indicates someone is intercepting your connection.'
        });
    }
    
    // Session flip
    if (evidence.sessionFlip) {
        threats.push({
            title: '🔄 Certificate Changed During Session',
            description: 'The certificate changed during your browsing session. This could indicate an attack or network switching.'
        });
    }
    
    // Issuer drift
    if (evidence.issuerDrift) {
        threats.push({
            title: '🏛️ Certificate Issuer Changed',
            description: 'The certificate issuer has changed from previous visits. This could indicate certificate substitution.'
        });
    }
    
    // Weak TLS
    if (evidence.weakTlsIssues && evidence.weakTlsIssues.length > 0) {
        evidence.weakTlsIssues.forEach(issue => {
            threats.push({
                title: `⚠️ ${issue.type}`,
                description: issue.message
            });
        });
    }
    
    if (threats.length > 0) {
        threatDetails.innerHTML = threats.map(threat => `
            <div class="threat-item">
                <div class="threat-title">${threat.title}</div>
                <div class="threat-description">${threat.description}</div>
            </div>
        `).join('');
    }
}

// ============================================
// EVENT LISTENERS
// ============================================

function setupEventListeners() {
    // Go Back button
    document.getElementById('goBackBtn').addEventListener('click', function() {
        window.history.back();
    });

    // Proceed Anyway button
    document.getElementById('proceedBtn').addEventListener('click', function() {
        if (confirm('⚠️ WARNING: You are about to proceed despite security warnings. This could expose your data to attackers. Are you absolutely sure?')) {
            proceedWithOverride();
        }
    });

    // Pin for 24h button
    document.getElementById('pinBtn').addEventListener('click', function() {
        pinFor24Hours();
    });
}

// ============================================
// OVERRIDE FUNCTIONS
// ============================================

function proceedWithOverride() {
    if (!evidence) {
        alert('No evidence data available');
        return;
    }
    
    try {
        // Store override in chrome.storage.local
        const overrideKey = `override_${evidence.hostname}_${Date.now()}`;
        const overrideData = {
            hostname: evidence.hostname,
            timestamp: Date.now(),
            ttl: 24 * 60 * 60 * 1000, // 24 hours
            evidence: evidence,
            userAction: 'proceed_anyway'
        };
        
        chrome.storage.local.set({
            [overrideKey]: overrideData
        }, () => {
            // Log to audit trail
            const auditKey = `override_audit_${evidence.hostname}_${Date.now()}`;
            chrome.storage.local.set({
                [auditKey]: {
                    type: 'override',
                    hostname: evidence.hostname,
                    timestamp: Date.now(),
                    userAction: 'proceed_anyway',
                    evidence: evidence
                }
            }, () => {
                // Navigate back
                window.history.back();
            });
        });
    } catch (error) {
        console.error('Failed to process override:', error);
        alert('Failed to process override. Please try again.');
    }
}

function pinFor24Hours() {
    if (!evidence) {
        alert('No evidence data available');
        return;
    }
    
    try {
        // Store pin in chrome.storage.local
        const pinKey = `pin_${evidence.hostname}`;
        const pinData = {
            hostname: evidence.hostname,
            fingerprint: evidence.fingerprint,
            timestamp: Date.now(),
            ttl: 24 * 60 * 60 * 1000, // 24 hours
            evidence: evidence,
            userAction: 'pin_24h'
        };
        
        chrome.storage.local.set({
            [pinKey]: pinData
        }, () => {
            // Log to audit trail
            const auditKey = `pin_audit_${evidence.hostname}_${Date.now()}`;
            chrome.storage.local.set({
                [auditKey]: {
                    type: 'pin',
                    hostname: evidence.hostname,
                    timestamp: Date.now(),
                    userAction: 'pin_24h',
                    evidence: evidence
                }
            }, () => {
                alert('✅ Site pinned for 24 hours. You can now proceed.');
                window.history.back();
            });
        });
    } catch (error) {
        console.error('Failed to process pin:', error);
        alert('Failed to process pin. Please try again.');
    }
}

// ============================================
// ERROR HANDLING
// ============================================

function displayError() {
    document.getElementById('hostname').textContent = 'Error loading evidence';
    document.getElementById('localFingerprint').textContent = 'N/A';
    document.getElementById('issuer').textContent = 'N/A';
    document.getElementById('protocol').textContent = 'N/A';
    document.getElementById('cipher').textContent = 'N/A';
    document.getElementById('consensus').textContent = 'Unable to load evidence';
}
