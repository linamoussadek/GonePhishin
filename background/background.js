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

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function pollUrlScanResult(uuid) {
    try {
        responseStatus = 404;
        content = null;
        verdict = null;
        while(responseStatus === 404) {
            const reqUrl = "https://urlscan.io/api/v1/result/" + uuid + "/?API-Key=<api-key-here>" // replace with api key
            const rawResponse = await fetch(reqUrl, {
                method: 'GET',
            });
            content = await rawResponse.json();
            responseStatus = content.status;
            if (responseStatus === 404) { // see if you can improve
                await sleep(10000);
            }
        }
        if (content) {
            // if malicious = true you might want to look further into the content data
            console.log("content: ", content);
            verdict = content.verdicts.overall.malicious; 
            console.log("verdict: ", verdict);
        }

        // need to handle failed case

        return verdict;

    } catch {
        console.error("Error retrieving URL scan result:", error);
        return null;
    }

}

async function urlScan(urlToScan) {
    try {
        const rawResponse = await fetch('https://urlscan.io/api/v1/scan', {
        method: 'POST',
        headers: {
            'API-Key': 'api-key-here', // replace with api key
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url: urlToScan,
            visibility: "public",
        })
        });

        if (!rawResponse.ok) {
        throw new Error(`HTTP error! status: ${rawResponse.status}`);
        }

        const content = await rawResponse.json();
        console.log("Scan request response:", content);

        // poll for scan result using the urlscan request uuid
        // the scan takes at least 30 seconds to finish
        const uuid = content.uuid;
        console.log("response uuid: ", uuid);
        await sleep(30000); // this may have side effects
        const result = await pollUrlScanResult(uuid);
        console.log("Scan verdict", result);

        return result;

  } catch (error) {
        console.error("Error scanning URL:", error);
        return null;
  }
}

// atm it's only working when you open a new tab or if you're on an existing tab and go to a new website
// if the extension is enabled after already navigating to the website, then we'd need a popup 
// TEMPORARILY DISABLED FOR TESTING HTTPS FEATURES
// chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
//     const url = changeInfo.url;
//     if (!url || ['chrome://', 'about://'].some(p => url.startsWith(p))) return;
//     if (!tab.active) return; // revisit
//     console.log(url);
//     await urlScan(url);
// })


// should we have a list of safe sites? to avoid unnecessary requests
// maybe allow user to whitelist websites or we could have a list of preapproved common sites and look there first