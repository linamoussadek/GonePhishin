// Interstitial page JavaScript for TLS security alerts

document.addEventListener('DOMContentLoaded', function() {
    // Parse evidence from URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const evidenceParam = urlParams.get('evidence');
    
    if (evidenceParam) {
        try {
            const evidence = JSON.parse(decodeURIComponent(evidenceParam));
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

function displayEvidence(evidence) {
    // Display basic evidence
    document.getElementById('hostname').textContent = evidence.hostname || 'Unknown';
    document.getElementById('localFingerprint').textContent = evidence.fingerprint || 'Unknown';
    document.getElementById('issuer').textContent = evidence.issuer || 'Unknown';
    document.getElementById('protocol').textContent = evidence.protocol || 'Unknown';
    document.getElementById('cipher').textContent = evidence.cipher || 'Unknown';
    document.getElementById('consensus').textContent = evidence.consensus?.message || 'Unknown';

    // Display notary results if available
    if (evidence.notaryResults && evidence.notaryResults.length > 0) {
        displayNotaryResults(evidence.notaryResults);
    }

    // Set timestamp
    const timestamp = new Date(evidence.timestamp).toLocaleString();
    document.getElementById('timestamp').textContent = `Detected: ${timestamp}`;
}

function displayNotaryResults(notaryResults) {
    const notarySection = document.getElementById('notarySection');
    const notaryResultsDiv = document.getElementById('notaryResults');
    
    notarySection.style.display = 'block';
    
    notaryResults.forEach(result => {
        const notaryItem = document.createElement('div');
        notaryItem.className = 'notary-item';
        
        notaryItem.innerHTML = `
            <div class="notary-endpoint">${result.endpoint}</div>
            <div class="notary-fingerprint">${result.fingerprint}</div>
        `;
        
        notaryResultsDiv.appendChild(notaryItem);
    });
}

function displayError() {
    document.getElementById('hostname').textContent = 'Error loading evidence';
    document.getElementById('localFingerprint').textContent = 'N/A';
    document.getElementById('issuer').textContent = 'N/A';
    document.getElementById('protocol').textContent = 'N/A';
    document.getElementById('cipher').textContent = 'N/A';
    document.getElementById('consensus').textContent = 'Unable to load evidence';
}

function setupEventListeners() {
    // Go Back button
    document.getElementById('goBackBtn').addEventListener('click', function() {
        window.history.back();
    });

    // Proceed Anyway button
    document.getElementById('proceedBtn').addEventListener('click', function() {
        proceedWithOverride();
    });

    // Pin for 24h button
    document.getElementById('pinBtn').addEventListener('click', function() {
        pinFor24Hours();
    });
}

function proceedWithOverride() {
    // Get the original URL from the evidence
    const urlParams = new URLSearchParams(window.location.search);
    const evidenceParam = urlParams.get('evidence');
    
    if (evidenceParam) {
        try {
            const evidence = JSON.parse(decodeURIComponent(evidenceParam));
            
            // Store override in chrome.storage.local
            const overrideKey = `override_${evidence.hostname}_${Date.now()}`;
            const overrideData = {
                hostname: evidence.hostname,
                timestamp: Date.now(),
                ttl: 24 * 60 * 60 * 1000, // 24 hours
                evidence: evidence
            };
            
            chrome.storage.local.set({
                [overrideKey]: overrideData
            });
            
            // Log to audit trail
            const auditKey = `override_audit_${evidence.hostname}_${Date.now()}`;
            chrome.storage.local.set({
                [auditKey]: {
                    type: 'override',
                    hostname: evidence.hostname,
                    timestamp: Date.now(),
                    userAction: 'proceed_anyway'
                }
            });
            
            // Navigate to the original URL
            // Note: In a real implementation, you'd need to get the original URL
            // from the background script or store it in the evidence
            window.close();
            
        } catch (error) {
            console.error('Failed to process override:', error);
            alert('Failed to process override. Please try again.');
        }
    }
}

function pinFor24Hours() {
    // Get the original URL from the evidence
    const urlParams = new URLSearchParams(window.location.search);
    const evidenceParam = urlParams.get('evidence');
    
    if (evidenceParam) {
        try {
            const evidence = JSON.parse(decodeURIComponent(evidenceParam));
            
            // Store pin in chrome.storage.local
            const pinKey = `pin_${evidence.hostname}`;
            const pinData = {
                hostname: evidence.hostname,
                fingerprint: evidence.fingerprint,
                timestamp: Date.now(),
                ttl: 24 * 60 * 60 * 1000, // 24 hours
                evidence: evidence
            };
            
            chrome.storage.local.set({
                [pinKey]: pinData
            });
            
            // Log to audit trail
            const auditKey = `pin_audit_${evidence.hostname}_${Date.now()}`;
            chrome.storage.local.set({
                [auditKey]: {
                    type: 'pin',
                    hostname: evidence.hostname,
                    timestamp: Date.now(),
                    userAction: 'pin_24h'
                }
            });
            
            // Navigate to the original URL
            window.close();
            
        } catch (error) {
            console.error('Failed to process pin:', error);
            alert('Failed to process pin. Please try again.');
        }
    }
}
