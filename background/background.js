// background.js (MV3 service worker, ES module)

const EXTENSION_ORIGIN = chrome.runtime.getURL("").replace(/\/$/, "");

// --- HTTPS enforcement and mixed content blocking ---

// Note: In Chrome MV3, webRequestBlocking is no longer available for regular extensions.
// The CSP injection is now handled via declarativeNetRequest rules in rules/https_rules.json
// which upgrades HTTP requests and blocks mixed content at the network level.
// This is actually more efficient than header modification.

// --- Track and notify users of HTTPS upgrades ---

// Store upgrade counts per tab
const tabUpgradeCounts = new Map(); // tabId -> count
let totalUpgrades = 0;

// Listen for DNR rule matches to track HTTPS upgrades
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((details) => {
  // Only track main_frame upgrades (actual page navigations)
  if (details.request.type === "main_frame" && details.rule.ruleId === 1) {
    const tabId = details.request.tabId;
    
    // Increment counters
    totalUpgrades++;
    const count = (tabUpgradeCounts.get(tabId) || 0) + 1;
    tabUpgradeCounts.set(tabId, count);
    
    // Update badge to show upgrade happened
    chrome.action.setBadgeText({ text: "🔒", tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#4CAF50", tabId: tabId });
    
    // Show a subtle notification
    const url = new URL(details.request.url);
    chrome.action.setTitle({ 
      title: `✅ Upgraded to HTTPS: ${url.hostname}`,
      tabId: tabId 
    });
    
    // Store upgrade info for popup
    chrome.storage.local.set({ 
      totalUpgrades: totalUpgrades,
      lastUpgrade: { url: details.request.url, timestamp: Date.now() }
    });
  }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabUpgradeCounts.delete(tabId);
});

// Reset badge when navigating to a new page
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) { // Main frame only
    // Only reset if it's not an upgrade (will be set again if it is)
    setTimeout(() => {
      chrome.action.getBadgeText({ tabId: details.tabId }).then(text => {
        if (text === "🔒") {
          // Keep it for 3 seconds, then clear
          setTimeout(() => {
            chrome.action.setBadgeText({ text: "", tabId: details.tabId });
          }, 3000);
        }
      });
    }, 100);
  }
});

// --- HTTPS→HTTP downgrade detection ---
//
// NOTE: In Chrome MV3, blocking webRequest listeners are only available for
// enterprise force-installed extensions. For regular extensions, we cannot
// use blocking listeners to prevent downgrades.
//
// The DNR rules in rules/https_rules.json will handle HTTPS upgrades automatically.
// For a production extension, you would need to use declarativeNetRequest's
// redirect rules or accept that downgrade blocking requires enterprise deployment.
//
// TEMPORARILY DISABLED: The blocking webRequest code has been removed because
// it requires webRequestBlocking permission which is not available for regular extensions.

// For reference, the downgrade detection would require enterprise force-install policy.
// In a production environment, you could:
// 1. Use declarativeNetRequest redirect rules (limited capability)
// 2. Deploy via ExtensionInstallForcelist for enterprise use
// 3. Use non-blocking listeners to log/warn about downgrades (but not prevent them)

// --- Original phishing protection functionality ---

/* -------------------- start of urlscan code -------------------- */
// working urlscan code. still needs tweaking but basic functionality is there

async function submitScanToBackend(url) {
  try {
    const resp = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/urlscan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    // Check content type before parsing
    const contentType = resp.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      const bodyText = await resp.text();
      const sanitizedBody = bodyText.substring(0, 200).replace(/[<>]/g, '');
      console.error(`Backend returned HTML instead of JSON (${resp.status}): ${sanitizedBody}`);
      return { success: false, message: "Backend returned HTML error page (status " + resp.status + ") — scan aborted" };
    }

    if (!resp.ok) {
      const errText = await resp.text();
      const sanitizedBody = errText.substring(0, 200).replace(/[<>]/g, '');
      console.error(`Backend returned error: ${resp.status} - ${sanitizedBody}`);
      return { success: false, message: `Backend error: ${resp.status}` };
    }

    const data = await resp.json();
    console.log(data);

    if (!data.uuid) {
      console.error("No UUID returned; likely blocked by URLScan");
      return { success: false, message: "We couldn’t verify this URL." };
    }

    return { 
      success: true, 
      message: "Scan submitted successfully", 
      data: {uuid: data.uuid} 
    };

  } catch (error) {
    console.error("Fetch failed:", error.message);
    return { success: false, message: "Network or server error contacting backend." };
  }
};

async function pollScanResult(uuid) {
  let attempts = 0;
  const maxAttempts = 50; // arbitrary
  const pollInterval = 2000;

  while (attempts < maxAttempts) {

    try {
      const resp = await fetch(`https://premonitory-distortional-jayme.ngrok-free.dev/api/urlscan/${uuid}`, {
          method: "GET",
          headers: new Headers({
            "ngrok-skip-browser-warning": "69420",
          })
      });

      // error in response
      if (!resp.ok) {
        console.warn(`Polling failed (status ${resp.status})`);
        throw new Error(`Polling failed with ${resp.status}`);
      }

      //console.log("response: ", resp);
     // const data = await resp.json();

      let data;
      try {
        data = await resp.json();
      } catch (err) {
        console.error("Invalid JSON in polling response:", err.message);
        await new Promise((r) => setTimeout(r, pollInterval));
        attempts++;
        continue;
      }

      // still need to wait for result
      if (data.status === 'pending') {
        console.log(`Result not ready yet (attempt ${attempts + 1})...`);
        await new Promise((r) => setTimeout(r, pollInterval));
        attempts++;
        continue;
      }

      console.log("Scan complete:", data);
      return {success: true, message: "Scan complete", data};

    } catch (err) {
      console.error(`Polling error (attempt ${attempts + 1}):`, err.message);
      // still try again
      await new Promise((r) => setTimeout(r, pollInterval));
      attempts++;
    };
  }
  console.warn('Timed out waiting for scan result');
  return { success: false, message: "Scan timed out before completion" };
};

// unsuccessful scan returns {success: false, message: <msg>}
// successful scan returns {success: true, message: "Scan successful", data: {isMalicious: <boolean>} }
async function urlScan(url) {
  const submission = await submitScanToBackend(url);
  
  if (!submission.success) {
    console.warn("Problem submitting scan:", submission.message);
    return { success: false, message: submission.message };
  }

  // wait before polling
  await new Promise((r) => setTimeout(r, 10000));

  // get polling result
  const poll = await pollScanResult(submission.data.uuid);
  console.log("polling result", poll);
  if (!poll.success) {
    console.warn(poll.message);
    return { success: false, message: poll.message };
  }
  
  const result = poll.data;
  const hasVerdicts = result.verdicts?.overall?.hasVerdicts
  if (!hasVerdicts) {
    console.log("Unable to verify URL (no verdict)")
    return {  // either return an error or return null
      success: false, 
      message: "We couldn’t verify this URL." 
    };
  }

  console.log("malicious:", result.verdicts.overall.malicious);
  return { success: true, message: "Scan successful", data: { isMalicious: result.verdicts.overall.malicious } };
};

// atm it's only working when you open a new tab or if you're on an existing tab and go to a new website
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  const url = changeInfo.url;
  if (!url || ['chrome://', 'about://'].some(p => url.startsWith(p))) return;
  if (!tab.active) return; // revisit
  console.log(url);
  await urlScan(url);
});

/* -------------------- end of urlscan code -------------------- */

// --- TLS & Certificate Verification + Multi-Vantage Notary Checks ---

// Certificate tracking storage
const certificateDatabase = new Map(); // hostname -> { issuer, fingerprint, firstSeen, lastSeen, sessionCount }
const sessionCertificates = new Map(); // tabId -> { hostname, certificate, timestamp }
const weakTlsAlerts = new Map(); // hostname -> { protocol, cipher, timestamp }

// Notary configuration - Development endpoints with fallbacks
const NOTARY_ENDPOINTS = [
  'http://localhost:9001/observe',
  'http://127.0.0.1:9001/observe',
  'http://localhost:9001/observe?force=sha256:consensus_fingerprint'
];

// Configuration constants
const NOTARY_TIMEOUT = 3000; // 3 seconds
const NOTARY_CACHE_TTL = 10 * 60 * 1000; // 10 minutes
const NOTARY_RATE_LIMIT = 5 * 1000; // 5 seconds per origin (reduced for testing)

// Simulation flag to avoid accidental session flips during local testing.
// Set this in chrome.storage.local or environment during dev.
const SIMULATION_KEY = 'simulate_tls_mode';

// Helper to check simulation mode for an origin
async function isSimulationModeForOrigin(origin) {
  const obj = await chrome.storage.local.get([SIMULATION_KEY]);
  const v = obj[SIMULATION_KEY];
  // v can be boolean true to disable session checks globally in dev, or an array/object per origin.
  return !!v;
}

// TLS security policies
const TLS_POLICIES = {
  minVersion: 'TLSv1.2',
  minRsaKeySize: 2048,
  forbiddenCiphers: ['RC4', '3DES'],
  forbiddenSignatures: ['sha1']
};

// Certificate issuer drift detection
function detectIssuerDrift(hostname, newCertificate) {
  const stored = certificateDatabase.get(hostname);
  if (!stored) {
    // First visit - record as trusted (TOFU)
    certificateDatabase.set(hostname, {
      issuer: newCertificate.issuer,
      fingerprint: newCertificate.fingerprint,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      sessionCount: 1
    });
    return false;
  }

  // Check for issuer drift
  if (stored.issuer !== newCertificate.issuer) {
    console.warn(`🚨 ISSUER DRIFT DETECTED for ${hostname}:`, {
      previous: stored.issuer,
      current: newCertificate.issuer,
      timestamp: new Date().toISOString()
    });
    
    // Store the drift event
    chrome.storage.local.set({
      [`issuerDrift_${hostname}_${Date.now()}`]: {
        hostname,
        previousIssuer: stored.issuer,
        newIssuer: newCertificate.issuer,
        timestamp: Date.now()
      }
    });
    
    return true;
  }

  // Update last seen
  stored.lastSeen = Date.now();
  stored.sessionCount++;
  return false;
}

// Session consistency check with simulation mode handling
async function checkSessionConsistency(tabId, hostname, newFingerprint) {
  // Skip session checks in simulation mode
  if (await isSimulationModeForOrigin(hostname)) {
    console.log(`🧪 SIMULATION MODE: skipping session checks for origin ${hostname}`);
    return false;
  }
  
  const sessionKey = `${tabId}_${hostname}`;
  const stored = sessionCertificates.get(sessionKey);
  
  if (!stored) {
    // First navigation in this session
    sessionCertificates.set(sessionKey, {
      hostname,
      fingerprint: newFingerprint,
      timestamp: Date.now()
    });
    return false;
  }

  // Check for session flip
  if (stored.fingerprint !== newFingerprint) {
    console.warn(`🚨 SESSION FLIP DETECTED for ${hostname} in tab ${tabId}:`, {
      previous: stored.fingerprint,
      current: newFingerprint,
      timestamp: new Date().toISOString()
    });
    
    return true;
  }

  return false;
}

// Weak TLS detection
function detectWeakTls(securityInfo) {
  const issues = [];
  
  // Check TLS version
  if (securityInfo.protocolVersion && securityInfo.protocolVersion < 'TLSv1.2') {
    issues.push({
      type: 'weak_protocol',
      severity: securityInfo.protocolVersion < 'TLSv1.0' ? 'critical' : 'warning',
      message: `Weak TLS version: ${securityInfo.protocolVersion}`,
      protocol: securityInfo.protocolVersion
    });
  }

  // Check cipher suite
  if (securityInfo.cipherSuite) {
    const weakCiphers = TLS_POLICIES.forbiddenCiphers.filter(cipher => 
      securityInfo.cipherSuite.includes(cipher)
    );
    if (weakCiphers.length > 0) {
      issues.push({
        type: 'weak_cipher',
        severity: 'warning',
        message: `Weak cipher detected: ${weakCiphers.join(', ')}`,
        cipher: securityInfo.cipherSuite
      });
    }
  }

  return issues;
}

// Generate certificate fingerprint
function generateFingerprint(certificate) {
  // Use SHA-256 of the DER-encoded certificate
  return crypto.subtle.digest('SHA-256', certificate.raw).then(hash => {
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  });
}

// Rate limiting storage
const notaryRateLimit = new Map(); // hostname -> lastQueryTime

// Clear rate limit for testing
function clearRateLimit(hostname = null) {
  if (hostname) {
    notaryRateLimit.delete(hostname);
    console.log(`🧹 Cleared rate limit for ${hostname}`);
  } else {
    notaryRateLimit.clear();
    console.log('🧹 Cleared all rate limits');
  }
}

// BACKGROUND: robust notary query + cache + rate-limit
const NOTARY_TIMEOUT_MS = 3000;
const NOTARY_TTL_MS = 10 * 60 * 1000; // 10 minutes
const NOTARY_RATE_LIMIT_MS = 30 * 1000; // 30s
// Default dev notaries (local stub). In production, change these.
const DEFAULT_NOTARIES = [
  'http://localhost:8080/observe',
  'http://127.0.0.1:8080/observe',
  'http://localhost:8080/observe?force=sha256:consensus_fingerprint'
];

// Helper: safe console log (sanitizes long bodies)
function shortSnippet(s, n = 200) {
  if (!s) return '';
  return ('' + s).slice(0, n).replace(/\s+/g, ' ');
}

// Rate-limit helper: return true if allowed to query (and update timestamp)
async function canQueryNotaries(host) {
  const key = `notary_rate_${host}`;
  const now = Date.now();
  const obj = await chrome.storage.local.get([key]);
  const last = obj[key];
  if (last && (now - last) < NOTARY_RATE_LIMIT_MS) {
    return false;
  }
  const update = {};
  update[key] = now;
  await chrome.storage.local.set(update);
  return true;
}

// Cache helpers
async function getCachedNotary(host) {
  const key = `notary_cache_${host}`;
  const obj = await chrome.storage.local.get([key]);
  const entry = obj[key];
  if (!entry) return null;
  if ((Date.now() - entry.ts) > NOTARY_TTL_MS) {
    // stale
    await chrome.storage.local.remove([key]);
    return null;
  }
  return entry;
}

async function setCachedNotary(host, aggregate) {
  const key = `notary_cache_${host}`;
  const entry = { ...aggregate, ts: Date.now() };
  const kv = {};
  kv[key] = entry;
  await chrome.storage.local.set(kv);
}

// The robust query function using chrome.scripting.executeScript
async function queryNotaries(host, notaryUrls = DEFAULT_NOTARIES, { bypassCache = false } = {}) {
  // Try cached result
  if (!bypassCache) {
    const cached = await getCachedNotary(host);
    if (cached) {
      console.debug('💾 Using cached notary results for:', host);
      return cached;
    }
  }

  // Rate limit
  const allowed = await canQueryNotaries(host);
  if (!allowed && !bypassCache) {
    return { total: 0, successful: 0, failed: 0, votes: [], errors: ['rate_limited'] };
  }

  console.log('🌐 Querying notary services for hostname:', host);
  console.log('📡 Notary endpoints:', notaryUrls);

  // Use content script to make notary requests (bypasses service worker CORS restrictions)
  const results = await Promise.all(notaryUrls.map(async (baseUrl) => {
    const url = baseUrl + (baseUrl.includes('?') ? '&' : '?') + 'host=' + encodeURIComponent(host);
    console.log('🔍 Querying notary via content script:', url);
    
    try {
      // Get the active tab to inject content script
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!activeTab || !activeTab.id) {
        throw new Error('No active tab available');
      }

      // Inject content script to make the request
      const response = await chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        func: async (notaryUrl) => {
          try {
            const response = await fetch(notaryUrl, {
              method: 'GET',
              headers: {
                'Accept': 'application/json',
                'User-Agent': 'GonePhishin-Extension/1.0'
              }
            });
            
            if (!response.ok) {
              throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            return { success: true, data };
          } catch (error) {
            return { success: false, error: error.message };
          }
        },
        args: [url]
      });

      const result = response[0]?.result;
      if (!result || !result.success) {
        return { url, ok: false, reason: 'network_or_cors', message: result?.error || 'Unknown error' };
      }

      const data = result.data;
      if (!data || !data.fingerprint_sha256) {
        return { url, ok: false, reason: 'missing_field', message: 'Missing fingerprint_sha256' };
      }

      console.log('✅ Notary response from', url, ':', data);
      return { url, ok: true, fingerprint: data.fingerprint_sha256, ts: data.ts || new Date().toISOString() };

    } catch (err) {
      console.log('❌ Notary query failed for', url, ':', err.message);
      return { url, ok: false, reason: 'network_or_cors', message: err.message };
    }
  }));

  // Aggregate
  const votes = results.filter(r => r.ok).map(r => r.fingerprint);
  const successful = results.filter(r => r.ok).length;
  const failed = results.length - successful;
  const errors = results.filter(r => !r.ok).map(r => {
    return `${r.url}: ${r.reason} ${r.message ? '(' + r.message + ')' : ''}`;
  });

  const aggregate = { total: results.length, successful, failed, votes, errors };

  // Cache successful or error aggregate to avoid hammering
  await setCachedNotary(host, aggregate);
  console.log('📊 Notary query results:', aggregate);
  return aggregate;
}

// Consensus evaluation with structured results
function evaluateConsensus(localFingerprint, notaryResults) {
  if (!notaryResults || notaryResults.successful === 0) {
    return { 
      consensus: 'no_data', 
      severity: 'medium', 
      message: 'Notary servers unreachable — unable to corroborate certificate',
      details: notaryResults?.errors || ['No notary responses']
    };
  }

  const votes = notaryResults.votes || [];
  const localMatches = votes.filter(fp => fp === localFingerprint).length;
  const majority = Math.floor(votes.length / 2) + 1;

  if (localMatches >= majority) {
    return { 
      consensus: 'consistent', 
      severity: 'low', 
      message: 'Notaries agree with local view',
      details: `${localMatches}/${votes.length} notaries agree`
    };
  } else if (localMatches === 0) {
    return { 
      consensus: 'mitm_detected', 
      severity: 'critical', 
      message: 'Potential MITM detected - notaries disagree',
      details: `Local: ${localFingerprint.substring(0, 16)}... vs Notaries: ${votes.map(v => v.substring(0, 16) + '...').join(', ')}`
    };
  } else {
    return { 
      consensus: 'mixed', 
      severity: 'medium', 
      message: 'Mixed notary responses',
      details: `${localMatches}/${votes.length} notaries agree`
    };
  }
}

// Show interstitial page
async function showInterstitial(tabId, evidence) {
  const interstitialUrl = chrome.runtime.getURL('interstitial.html') + 
    '?evidence=' + encodeURIComponent(JSON.stringify(evidence));
  
  await chrome.tabs.update(tabId, { url: interstitialUrl });
}

// Update badge based on TLS status
function updateBadge(tabId, status) {
  const badgeConfig = {
    'secure': { text: '✓', color: '#4CAF50' },
    'warning': { text: '⚠', color: '#FF9800' },
    'critical': { text: '🚨', color: '#F44336' }
  };

  const config = badgeConfig[status] || badgeConfig['warning'];
  chrome.action.setBadgeText({ text: config.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
}

// Main TLS verification handler
async function verifyTlsSecurity(details) {
  console.log('🔍 TLS Verification triggered:', {
    url: details.url,
    type: details.type,
    tabId: details.tabId,
    requestId: details.requestId
  });

  if (details.type !== 'main_frame' || !details.url.startsWith('https://')) {
    console.log('⏭️ Skipping non-main-frame or non-HTTPS request');
    return;
  }

  try {
    const hostname = new URL(details.url).hostname;
    console.log('🌐 Processing TLS verification for:', hostname);
    
    // Since getSecurityInfo is not available in MV3 service workers,
    // we'll simulate the TLS verification process for testing
    console.log('🔐 Simulating TLS verification (MV3 limitation)');
    
    // Generate a mock fingerprint for testing
    const mockFingerprint = `sha256:${crypto.getRandomValues(new Uint8Array(32))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')}`;
    
    console.log('🔑 Generated mock fingerprint:', mockFingerprint);
    
    // Mock certificate info
    const mockCertInfo = {
      subject: `CN=${hostname}`,
      issuer: 'CN=DigiCert SHA2 Extended Validation Server CA',
      validFrom: new Date().toISOString(),
      validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    };
    
    console.log('📜 Mock certificate info:', mockCertInfo);
    
    // Check session consistency
    const sessionFlip = await checkSessionConsistency(details.tabId, hostname, mockFingerprint);
    console.log('🔄 Session consistency check:', { sessionFlip });
    
    // Check issuer drift
    const issuerDrift = detectIssuerDrift(hostname, {
      issuer: mockCertInfo.issuer,
      fingerprint: mockFingerprint
    });
    console.log('🏛️ Issuer drift check:', { issuerDrift });

    // Mock TLS info
    const mockTlsInfo = {
      protocolVersion: 'TLSv1.3',
      cipherSuite: 'TLS_AES_256_GCM_SHA384'
    };

    // Check for weak TLS
    const weakTlsIssues = detectWeakTls(mockTlsInfo);
    console.log('⚠️ Weak TLS issues:', weakTlsIssues);

    // Determine severity
    let severity = 'secure';
    let evidence = {
      hostname,
      fingerprint: mockFingerprint,
      issuer: mockCertInfo.issuer,
      protocol: mockTlsInfo.protocolVersion,
      cipher: mockTlsInfo.cipherSuite,
      timestamp: Date.now()
    };

    if (sessionFlip || issuerDrift) {
      console.log('🚨 High severity detected - querying notaries');
      // Query notaries for consensus
      const notaryResults = await queryNotaries(hostname);
      const consensus = evaluateConsensus(mockFingerprint, notaryResults);
      
      console.log('🌐 Notary results:', notaryResults);
      console.log('🤝 Consensus evaluation:', consensus);
      
      evidence.notaryResults = notaryResults;
      evidence.consensus = consensus;

      if (consensus.severity === 'critical') {
        severity = 'critical';
        console.log('🚨 CRITICAL: Showing interstitial');
        await showInterstitial(details.tabId, evidence);
      } else {
        severity = 'warning';
        console.log('⚠️ WARNING: Notary consensus issue');
      }
    } else if (weakTlsIssues.length > 0) {
      const criticalIssues = weakTlsIssues.filter(issue => issue.severity === 'critical');
      severity = criticalIssues.length > 0 ? 'critical' : 'warning';
      evidence.weakTlsIssues = weakTlsIssues;
      console.log('⚠️ Weak TLS detected:', severity);
    } else {
      console.log('✅ Secure connection detected');
      
      // Always query notaries for consensus verification
      console.log('🌐 Querying notaries for consensus verification');
      const notaryResults = await queryNotaries(hostname);
      const consensus = evaluateConsensus(mockFingerprint, notaryResults);
      
      console.log('🌐 Notary results:', notaryResults);
      console.log('🤝 Consensus evaluation:', consensus);
      
      evidence.notaryResults = notaryResults;
      evidence.consensus = consensus;
      
      // Update severity based on notary consensus
      if (consensus.severity === 'critical') {
        severity = 'critical';
        console.log('🚨 CRITICAL: Notary disagreement detected');
        await showInterstitial(details.tabId, evidence);
      } else if (consensus.severity === 'medium') {
        severity = 'warning';
        console.log('⚠️ WARNING: Notary consensus issue');
      } else {
        console.log('✅ Notary consensus: secure');
      }
    }

    // Update badge
    updateBadge(details.tabId, severity);
    console.log('🏷️ Badge updated:', severity);

    // Store audit log
    const auditKey = `audit_${hostname}_${Date.now()}`;
    const auditData = {
      ...evidence,
      severity,
      tabId: details.tabId
    };
    
    console.log('📝 Storing audit log:', auditKey, auditData);
    chrome.storage.local.set({
      [auditKey]: auditData
    });

    // Also store a simple test entry for popup display
    chrome.storage.local.set({
      [`test_${hostname}`]: {
        hostname,
        severity,
        timestamp: Date.now(),
        protocol: mockTlsInfo.protocolVersion,
        issuer: mockCertInfo.issuer
      }
    });

  } catch (error) {
    console.error('❌ TLS verification failed:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack,
      url: details.url,
      requestId: details.requestId
    });
  }
}

// Listen for completed requests to verify TLS
chrome.webRequest.onCompleted.addListener(verifyTlsSecurity, {
  urls: ['<all_urls>']
});

// Also listen for navigation events
chrome.webNavigation.onCompleted.addListener((details) => {
  console.log('🧭 Navigation completed:', {
    url: details.url,
    tabId: details.tabId,
    frameId: details.frameId
  });
  
  if (details.frameId === 0 && details.url.startsWith('https://')) {
    console.log('🌐 Main frame HTTPS navigation detected, triggering TLS check');
    // Trigger a manual TLS check for this navigation
    setTimeout(() => {
      verifyTlsSecurity({
        url: details.url,
        type: 'main_frame',
        tabId: details.tabId,
        requestId: `nav_${Date.now()}`
      });
    }, 1000);
  }
});

// Clean up session data when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  // Remove session certificates for this tab
  for (const [key, value] of sessionCertificates.entries()) {
    if (key.startsWith(`${tabId}_`)) {
      sessionCertificates.delete(key);
    }
  }
});

// Test function for manual testing
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'testTls') {
    console.log('🧪 Manual TLS test triggered');
    
    // Get the current active tab instead of using sender.tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (activeTab) {
        verifyTlsSecurity({
          url: request.url || activeTab.url || 'https://github.com',
          type: 'main_frame',
          tabId: activeTab.id,
          requestId: `test_${Date.now()}`
        });
      } else {
        console.log('❌ No active tab found for TLS test');
      }
    });
    
    sendResponse({ success: true });
  } else if (request.action === 'clearRateLimit') {
    console.log('🧹 Clearing rate limits for testing');
    clearRateLimit(request.hostname);
    sendResponse({ success: true });
  } else if (request.action === 'retryNotary') {
    console.log('🔄 Retrying notary check for:', request.hostname);
    // Clear cache and retry
    const cacheKey = `notary_cache_${request.hostname}`;
    chrome.storage.local.remove([cacheKey]);
    clearRateLimit(request.hostname);
    
    // Trigger notary query
    queryNotaries(request.hostname, DEFAULT_NOTARIES, { bypassCache: true }).then((results) => {
      console.log('🔄 Retry notary results:', results);
      sendResponse({ success: true, results });
    }).catch((error) => {
      console.error('🔄 Retry notary error:', error);
      sendResponse({ success: false, error: error.message });
    });
  }
});