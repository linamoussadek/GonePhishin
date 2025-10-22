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
// working urlscan code. still needs tweaking and better error handling, but basic functionality is there

async function submitScanToBackend(url) {
  try {
    const resp = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/urlscan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await resp.json();
    console.log(data);
    return data.uuid;

  } catch (error) {
    console.error("Fetch failed:", error.message);
  }
  
};

// add error handling
async function pollScanResult(uuid) {
  let attempts = 0;
  const maxAttempts = 50; // arbitrary

  while (attempts < maxAttempts) {
    const resp = await fetch(`https://premonitory-distortional-jayme.ngrok-free.dev/api/urlscan/${uuid}`,
      {
        method: "GET",
        headers: new Headers({
          "ngrok-skip-browser-warning": "69420",
        })
      }
    );
    const data = await resp.json();

    if (data.status !== 'pending') {
      //console.log('Scan complete:', data);
      return data;
    }
    console.log(`Result not ready yet (attempt ${attempts + 1})...`);
    await new Promise((r) => setTimeout(r, 2000)); // 2 second intervals
    attempts++;
  }
  console.warn('Timed out waiting for scan result');
  return null;
};

async function urlScan(url) {
  const uuid = await submitScanToBackend(url);
  await new Promise((r) => setTimeout(r, 10000)); // recommended to wait 10 seconds to poll
  const result = await pollScanResult(uuid);
  
  console.log("final urlscan result", result);
  const hasVerdicts = result.verdicts.overall.hasVerdicts
  console.log("hasverdicts: ", hasVerdicts);
  if (!hasVerdicts) {
    console.log("Unable to verify URL (no verdict)")
    return; // no verdict
  }
  console.log("malicious:", result.verdicts.overall.malicious);
  return result.verdicts.overall.malicious
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