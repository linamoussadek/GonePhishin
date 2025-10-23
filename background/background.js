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

    if (!resp.ok) {
      const errText = await resp.text();
      console.error(`Backend returned error: ${resp.status} - ${errText}`);
      return { success: false, message: "Cannot scan this URL." };
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