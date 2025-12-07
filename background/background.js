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
    try {
      const url = new URL(details.request.url);
      const hostname = url.hostname.toLowerCase();
      
      // Skip localhost domains (testing environments)
      if (hostname === 'localhost' || 
          hostname === '127.0.0.1' || 
          hostname === '[::1]' ||
          hostname.startsWith('localhost:') ||
          hostname.startsWith('127.0.0.1:')) {
        return; // Don't track or upgrade localhost
      }
      
    const tabId = details.request.tabId;

    // Increment counters
    totalUpgrades++;
    const count = (tabUpgradeCounts.get(tabId) || 0) + 1;
    tabUpgradeCounts.set(tabId, count);

    // Update badge to show upgrade happened
    chrome.action.setBadgeText({ text: "🔒", tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#4CAF50", tabId: tabId });

    // Show a subtle notification
    chrome.action.setTitle({
        title: `✅ Upgraded to HTTPS: ${hostname}`,
      tabId: tabId
    });

    // Store upgrade info for popup
    chrome.storage.local.set({
      totalUpgrades: totalUpgrades,
      lastUpgrade: { url: details.request.url, timestamp: Date.now() }
    });
    } catch (e) {
      // Invalid URL, skip
      console.log('Skipping upgrade tracking for invalid URL:', details.request.url);
    }
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
      data: { uuid: data.uuid }
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
      return { success: true, message: "Scan complete", data };

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
  try {


    const hostname = new URL(url).hostname;
    console.log("THIS IS THE URLSCAN HOSTNAME", hostname);

    // get whitelist
    const { whitelist = [] } = await chrome.storage.local.get("whitelist");
    let isWhitelisted = false;
    if (!(whitelist.length === 0)) { // whitelist isn't empty
      
      if (hostname.startsWith("www.")) {
        let hostnameNoWWW = hostname.slice(4);
        isWhitelisted = whitelist.some(entry =>
          entry.includes(hostnameNoWWW)
        );
      } else {
        isWhitelisted = whitelist.some(entry =>
          entry.includes(hostname)
        );
      }

    }

    if (isWhitelisted) {
      console.log("URLSCAN: url is whitelisted")
      // skip scan
      const whitelistResult =  {
        success: true,
        message: "URL domain is in whitelist",
        whitelisted: true,
        data: {
          isMalicious: false
        }
      }

      storeUrlScanResult(url, whitelistResult);

      chrome.runtime.sendMessage({
        type: "URL_SCAN_RESULT",
        url,
        result: whitelistResult
      })

      return whitelistResult;
    };


    let urlScanResult = await getUrlScanResult(hostname);
    if (urlScanResult !== null) {
      console.log("we already checked this URL", urlScanResult);
      chrome.runtime.sendMessage({
        type: "URL_SCAN_RESULT",
        url,
        result: urlScanResult.result
      });

      const scanResult = {
        success: true,
        message: "Scan results found in storage",
        data: {
          isMalicious: urlScanResult.result.data.isMalicious,
          verdicts: urlScanResult.result.data.verdicts,
          timestamp: urlScanResult.result.data.timestamp
        }
      }

      return scanResult
    } else {
      // actually perform scan

      //const hostname = new URL(sender.tab.url).hostname;
      const submission = await submitScanToBackend(url);

      if (!submission.success) {
        console.warn("Problem submitting scan:", submission.message);
        // Store unavailable status
        const unavailableResult = { 
          success: false, 
          unavailable: true,
          message: submission.message || "URLScan backend unavailable"
        };
        storeUrlScanResult(url, unavailableResult);
        
        // Send message about unavailability
        console.log("SENDING URLSCANRESULT MESSAGE (1)");
        chrome.runtime.sendMessage({
          type: "URL_SCAN_RESULT",
          url,
          result: unavailableResult
        });
        
        return unavailableResult;
      }

      // wait before polling
      await new Promise((r) => setTimeout(r, 10000));

      // get polling result
      const poll = await pollScanResult(submission.data.uuid);
      console.log("polling result", poll);
      
      if (!poll.success) {
        console.warn(poll.message);
        // Store unavailable status
        const unavailableResult = { 
          success: false, 
          unavailable: true,
          message: poll.message || "URLScan polling failed"
        };

        storeUrlScanResult(url, unavailableResult);
        
        console.log("SENDING URLSCANRESULT MESSAGE (2)");
        chrome.runtime.sendMessage({
          type: "URL_SCAN_RESULT",
          url,
          result: unavailableResult
        });
        
        return unavailableResult;
      }

      const result = poll.data;
      const hasVerdicts = result.verdicts?.overall?.hasVerdicts;
      
      if (!hasVerdicts) {
        console.log("Unable to verify URL (no verdict)");
        const noVerdictResult = { 
          success: false,
          unavailable: false,
          message: "We couldn't verify this URL."
        };
        storeUrlScanResult(url, noVerdictResult);
        
        console.log("SENDING URLSCANRESULT MESSAGE (3)");
        chrome.runtime.sendMessage({
          type: "URL_SCAN_RESULT",
          url,
          result: noVerdictResult
        });
        
        return noVerdictResult;
      }

      console.log("malicious:", result.verdicts.overall.malicious);
      
      const scanResult = { 
        success: true, 
        message: "Scan successful", 
        data: { 
          isMalicious: result.verdicts.overall.malicious, // change this line to true to sim malicious
          verdicts: result.verdicts,
          timestamp: Date.now()
        } 
      };
      
      // Store URLScan result
      storeUrlScanResult(url, scanResult);

      // Send result to popup
      console.log("SENDING URLSCANRESULT MESSAGE (4)");
      chrome.runtime.sendMessage({
        type: "URL_SCAN_RESULT",
        url,
        result: scanResult
      });
        
      return scanResult;
    }
  } catch (error) {
    console.error("URLScan error:", error);
    const errorResult = { 
      success: false, 
      unavailable: true,
      message: error.message || "URLScan service error"
    };
    storeUrlScanResult(url, errorResult);
    
    console.log("SENDING URLSCANRESULT MESSAGE (5)");
    chrome.runtime.sendMessage({
      type: "URL_SCAN_RESULT",
      url,
      result: errorResult
    });
    
    return errorResult;
  }
};

// Store URLScan result for later use in heuristics
function storeUrlScanResult(url, result) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const urlScanKey = `urlscan_${hostname}`;
    
    chrome.storage.local.set({
      [urlScanKey]: {
        url,
        hostname,
        result,
        timestamp: Date.now()
      }
    });
    
    console.log('💾 Stored URLScan result for', hostname, result);
  } catch (error) {
    console.error('Error storing URLScan result:', error);
  }
}

// Handle URLScan result messages
function handleUrlScanResult(url, result) {
  console.log('📡 URLScan result received:', url, result);
  
  // Store the result
  storeUrlScanResult(url, result);
  
  // If malicious, we should trigger a re-analysis or update threat level
  if (result.success && result.data?.isMalicious) {
    console.log('🚨 URLScan detected malicious URL:', url);
    // The heuristics engine will pick this up on next analysis
  } else if (!result.success) {
    // Backend unavailable or error
    console.log('⚠️ URLScan unavailable or error:', result.message);
    // Store as unavailable so UI can show it
    storeUrlScanResult(url, {
      success: false,
      unavailable: true,
      message: result.message || 'URLScan service unavailable'
    });
  }
} 


// Trigger URLScan when navigating to a new URL (only for active tab)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  const url = changeInfo.url;
  // Skip chrome://, about://, chrome-extension:// URLs
  if (!url || ['chrome://', 'about://', 'chrome-extension://'].some(p => url.startsWith(p))) return;
  // Only scan active tabs
  if (!tab.active) return;
  
  // Only scan on URL change (not on status changes)
  if (!changeInfo.url) return;
  
  console.log('🔍 Triggering URLScan for:', url);
  
  // Run URLScan in background (don't await - let it run async)
  urlScan(url).then(result => {
    if (result.success) {
      console.log('✅ URLScan completed:', result.data?.isMalicious ? 'MALICIOUS' : 'SAFE');
    } else {
      console.log('⚠️ URLScan unavailable:', result.message);
    }
  }).catch(error => {
    console.error('❌ URLScan error:', error);
  });
});

/* -------------------- end of urlscan code -------------------- *
/* -------------------- start of user actions code -------------------- */

// this function will generate the JWT
async function login() { 
  try {
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/auth/google', {
      method: 'GET',
      headers: {
        'ngrok-skip-browser-warning': '69420'
      }
    });

    console.log("🍇 this is the raw res", res);

    if (!res.ok) {
      const text = await res.text();
      console.error("🍇 Backend returned error:", res.status, text);
      return { error: true, status: res.status, text};
    }

    if (!("url" in res)) {
      console.error("🍇 Response has no 'url' attribute:", res);
    } 

    const data = { loginUrl: res.url };
    console.log("🍇 this is the url data", data);

   // const data = await res.json();
  //  console.log("🍇 In login function - response:", data);
    return data;

  } catch (err) {
    console.error("🍇 (login) Fetch failed:", err);
    return { error: true, message: err.message };
  }
};

async function getToken() {
  const { token } = await chrome.storage.local.get("token");
  return token || null;
}


// functions below require JWT
async function getUserInfo() { 
  try {
    const token = await getToken();
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/user/info', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'ngrok-skip-browser-warning': '69420'
      }
    });

    if (!res.ok) {
      const text = await res.text();
      console.error("🧃Backend returned error:", res.status, text);
      return { error: true, status: res.status, text };
    }

    const data = await res.json();
    console.log("🧃In getUserWhitelist function - response: ", data);
    return data;

  } catch (err) {
    console.error("🧃Fetch failed:", err);
    return { error: true, message: err.message };
  }

};

async function getUserWhitelist() {
  try {
    const token = await getToken();
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/user/whitelist', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'ngrok-skip-browser-warning': '69420'
      }
    });

    if (!res.ok) {
      const text = await res.text();
      console.error("🍊Backend returned error:", res.status, text);
      return { error: true, status: res.status, text };
    }

    const data = await res.json();
    console.log("🍊In getUserWhitelist function - response: ", data);

    // store
    const urlsOnly = data.whitelistedUrls.map(item => item.url);
    chrome.storage.local.set({whitelist: urlsOnly})
    console.log("🍊In getUserWhitelist function - stored whitelist: ", urlsOnly)


    return data
  } catch (err) {
    console.error("🍊Fetch failed:", err);
    return { error: true, message: err.message };
  }

};

// Valarie
async function addUrlToUserWhitelist(urlToAdd) { 
  try {
    console.log("🦴 in addUrlToUserWhitelist, urlToAdd =", urlToAdd);

    if (!urlToAdd) {
      console.error("🦴 addUrlToUserWhitelist called without a URL");
      return { error: true, message: "No URL provided" };
    }

    const token = await getToken();
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/user/whitelist/add', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'ngrok-skip-browser-warning': '69420',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url: urlToAdd,
      })
    });

    console.log("🦴 addUrlToUserWhitelist response object:", res);

    if (!res.ok) {
      const text = await res.text();
      console.error("🦴 addUrlToUserWhitelist error:", res.status, text);
      return { error: true, status: res.status, text };
    }

    const data = await res.json();
    console.log("🦴 addUrlToUserWhitelist success:", data);

    // bandaid soln to update storage
    getUserWhitelist();

    return { success: true, data };

  } catch (err) {
    console.log("🦴 addUrlToUserWhitelist fetch failed:", err);
    return { error: true, message: err.message };
  }
}


async function removeUrlFromUserWhitelist(urlToDelete) {
  try {
    console.log("🍟 in RemoveUrlFromUserWhitelist", typeof(urlToDelete));
    const token = await getToken();
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/user/whitelist/delete', {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
        'ngrok-skip-browser-warning': '69420',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        "url": urlToDelete,
      })
    });

    console.log("🍟 in RemoveUrlFromUserWhitelist here is my res: ", res);

    if (!res.ok) {
      const text = await res.text();
      console.error("🍟 in RemoveUrlFromUserWhitelist returned error:", res.status, text);
      //sendResponse({ error: true, status: res.status, text });
      return { error: true, status: res.status, text };
    }

    const data = await res.json();
    console.log("🍟 in RemoveUrlFromUserWhitelist function - response: ", data);

    // bandaid soln to update storage
    getUserWhitelist();

    // in storage, clear "urlscan_hostname"
    const allItems = await chrome.storage.local.get(null);
    const allKeys = Object.keys(allItems);

    const match = allKeys.find(key => 
      key.includes("urlscan_") &&
      key.includes(urlToDelete)
    );

    if (match) {
      await chrome.storage.local.remove(match);
      console.log("Removed:", match);
    }

    return { success: true, data };

  } catch (err) {
    console.error("🍟  RemoveUrlFromUserWhitelist Fetch failed:", err);
    return { error: true, message: err.message };
  }
};

/*async function getUserWhitelist() {
  try {
    const token = await getToken();
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/user/whitelist', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'ngrok-skip-browser-warning': '69420'
      }
    });

    if (!res.ok) {
      const text = await res.text();
      console.error("🍊Backend returned error:", res.status, text);
      return { error: true, status: res.status, text };
    }

    const data = await res.json();
    console.log("🍊In getUserWhitelist function - response: ", data);
    return data
  } catch (err) {
    console.error("🍊Fetch failed:", err);
    return { error: true, message: err.message };
  }

};*/

async function updateLastVisitedBlacklistedAt() { // backend will automatically update the date to today - need to fix timezone tho
  try {
    console.log("🥨 in updateLastVisitedBlacklistedAt");
    const token = await getToken();
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/user/stats/update-visited-blacklist', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'ngrok-skip-browser-warning': '69420',
      },
    });

    console.log("🥨 in updateLastVisitedBlacklistedAt here is my res: ", res);

    if (!res.ok) {
      const text = await res.text();
      console.error("🥨 in updateLastVisitedBlacklistedAt returned error:", res.status, text);
      return {error: true, status: res.status, text};
    }

  } catch (err) {
    console.log("🥨 in updateLastVisitedBlacklistedAt fetch failed:", err);
    return {error: true, message: err.message};
  }

};

async function getLastVisitedBlacklistedAt() { 
  try {
  const token = await getToken();
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/user/stats/last-visited-blacklist', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'ngrok-skip-browser-warning': '69420'
      }
    });

    if (!res.ok) {
      const text = await res.text();
      console.error("🍖 Backend returned error:", res.status, text);
      return { error: true, status: res.status, text };
    }

    const data = await res.json();
    console.log("🍖 In getLastVisitedBlacklistedAt function - response: ", data);
    return data
  } catch (err) {
    console.error("🍖 getLastVisitedBlacklistedAt Fetch failed:", err);
    return { error: true, message: err.message };
  }

};

async function getAccountCreationDate() { 
   try {
  const token = await getToken();
    const res = await fetch('https://premonitory-distortional-jayme.ngrok-free.dev/api/user/stats/account-creation-date', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'ngrok-skip-browser-warning': '69420'
      }
    });

    if (!res.ok) {
      const text = await res.text();
      console.error("🍧 Backend returned error:", res.status, text);
      return { error: true, status: res.status, text };
    }

    const data = await res.json();
    console.log("🍧 In getAccountCreationDate function - response: ", data);
    return data
  } catch (err) {
    console.error("🍧 getAccountCreationDate Fetch failed:", err);
    return { error: true, message: err.message };
  }

};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      let data;
      let whitelistResp;
      switch (msg.type) {
        case "LOGIN":
          //token = msg.token;
          console.log("🍇In switch - before calling login");
          data = await login();
          console.log("🍇In switch - after login call - data received: ", data);
          if (!data.loginUrl) {
            // do something
            sendResponse({ success: false, data})
          } else {
            console.log("🍇In switch - we have a loginUrl attribute");
          }
          sendResponse({ success: true, data });
          break;

        case "OAUTH_COMPLETE":
          console.log("⛰️ Token received from login:", msg.token);
          chrome.storage.local.set({token: msg.token});

          whitelistResp = await getUserWhitelist(); // now whitelist is in local storage
          console.log("⛰️ Whitelist received upon login:", whitelistResp);

          sendResponse({success: true});
          break;

        case "GET_USER_INFO":
          // need token
          data = await getUserInfo();
          console.log("🧃In switch - user info received: ", data);
          sendResponse({success: true, data});
          break;

        case "ADD_WHITELIST": {
          // URL comes from popup.js
          const url = msg.url;
          console.log("this is the msg.url", msg.url);
          const result = await addUrlToUserWhitelist(url);
          sendResponse(result);
          break;
        }

        case "REMOVE_WHITELIST":
          // need token
          const url = msg.url;
          sendResponse(await removeUrlFromUserWhitelist(url));
          break;

        case "GET_WHITELIST":
          // need token
          data = await getUserWhitelist();
          console.log("🍊In switch - data received: ", data);
          sendResponse({success: !data.error, data});
          break;

        case "UPDATE_LAST_VISITED_BLACKLIST":
          // need token
          sendResponse(await updateLastVisitedBlacklistedAt());
          break;

        case "GET_LAST_VISITED_BLACKLIST":
          data = await getLastVisitedBlacklistedAt(); // would need to pass token
          console.log("🍖 In switch - data received: ", data);
          sendResponse({success: true, data});
          break;

        case "GET_ACCOUNT_CREATION_DATE":
          data = await getAccountCreationDate(); // would need to pass token
          console.log("🍧 In switch - data received: ", data);
          sendResponse({success: true, data});
          break;

        default:
          sendResponse({ error: "Unknown request type" });
      }
    } catch (err) {
      console.error("Background error:", err);
      sendResponse({ error: true, message: err.message });
    }
  })();
  return true; // keep channel open
});


/* -------------------- end of user actions code -------------------- */

// --- Connection Security Check (Chrome MV3 Limited) ---
// NOTE: Chrome MV3 cannot access certificate details. This only checks HTTPS protocol.
// Full certificate verification is available in Firefox MV2 version only.

// Detect browser type
const IS_FIREFOX = typeof browser !== 'undefined';

// Simple HTTPS connection check (Chrome MV3 compatible)
async function checkConnectionSecurity(details) {
  if (details.type !== 'main_frame' || !details.url.startsWith('https://')) {
    return;
  }

  try {
    const hostname = new URL(details.url).hostname;
    
    // In Chrome MV3, we can only verify that HTTPS is being used
    // Browser already validates certificates - we just log the connection
    const securityData = {
      hostname,
      protocol: 'HTTPS',
      secure: true, // Browser validates certificate
      timestamp: Date.now(),
      note: 'Chrome MV3: Certificate validation handled by browser'
    };

    // Store simple connection log
    chrome.storage.local.set({
      [`connection_${hostname}_${Date.now()}`]: securityData
    });

    // Update badge to show secure connection
    updateBadge(details.tabId, 'secure');
    
  } catch (error) {
    console.error('❌ Connection check failed:', error);
  }
}


// Update badge based on security status
function updateBadge(tabId, status) {
  const badgeConfig = {
    'secure': { text: '✓', color: '#4CAF50' },
    'warning': { text: '⚠', color: '#FF9800' },
    'critical': { text: '🚨', color: '#F44336' }
  };

  const config = badgeConfig[status] || badgeConfig['secure'];
  chrome.action.setBadgeText({ text: config.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
}

// Listen for HTTPS connections (Chrome MV3 - limited to protocol check only)
chrome.webRequest.onCompleted.addListener(checkConnectionSecurity, {
  urls: ['<all_urls>']
});

// Also listen for navigation events
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId === 0 && details.url.startsWith('https://')) {
    checkConnectionSecurity({
      url: details.url,
      type: 'main_frame',
      tabId: details.tabId,
      requestId: `nav_${Date.now()}`
    });
  }
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
  if (request.action === 'heuristicsResults') {
    console.log('🔍 Heuristics results received:', request.data);
    handleHeuristicsResults(request.data, sender);
    sendResponse({ success: true });
  } else if (request.action === 'checkActiveTab') {
    // Check if sender's tab is the active tab
    const senderTabId = sender.tab?.id;
    // If activeTabId not set yet, assume it's active (fallback)
    const isActive = activeTabId === null || senderTabId === activeTabId;
    sendResponse({ isActive });
  } else if (request.action === 'getTabId') {
    // Return the sender's tab ID
    sendResponse({ tabId: sender.tab?.id });
  } else if (request.action === 'getUrlScanResult') {
    // Get URLScan result for a hostname
    const hostname = request.hostname;
    const storageData = await chrome.storage.local.get();
    const urlScanKey = `urlscan_${hostname}`;
    const urlScanResult = storageData[urlScanKey];
    sendResponse({ urlScanResult });
  }
  return true; // Keep channel open for async responses
});

// Handle URLScan results
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'URL_SCAN_RESULT') {
    handleUrlScanResult(message.url, message.result);
    sendResponse({ success: true });
  }
  return true;
});

// --- Heuristics Integration ---

// Track active tab
let activeTabId = null;

// Update active tab when user switches tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const oldTabId = activeTabId;
  activeTabId = activeInfo.tabId;
  console.log('📑 Active tab changed from', oldTabId, 'to:', activeTabId);
  
  // Clear badge on old tab
  if (oldTabId) {
    chrome.action.setBadgeText({ text: '', tabId: oldTabId });
  }
});

// Also track when tab is updated (navigation)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.active) {
    activeTabId = tabId;
    console.log('📑 Active tab updated:', tabId);
  }
});

// Get current active tab on startup
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0]) {
    activeTabId = tabs[0].id;
    console.log('📑 Initial active tab:', activeTabId);
  }
});

// ============================================
// Unified Mathematical Scoring System
// ============================================
// Feature weights (must sum to 1.0)
const FEATURE_WEIGHTS = {
  URLSCAN: 0.60,       // 60% - Most reliable signal when available
  HEURISTICS: 0.25,    // 25% - Pattern-based analysis
  HTTPS_ENFORCEMENT: 0.15,  // 15% - Important but binary
  CONNECTION_SECURITY: 0.00  // 0% - Removed from scoring (handled by browser)
};

const MAX_SCORES = {
  HEURISTICS: 200,  // Reduced max from heuristics (pattern-based analysis)
  // Max breakdown: Form submissions (80-130), Link patterns (100-155), Network requests (60)
  URLSCAN: 100,
  HTTPS_ENFORCEMENT: 20,
  CONNECTION_SECURITY: 10  // Not used in scoring
};

function normalizeScore(score, maxScore) {
  if (maxScore === 0) return 0;
  const clampedScore = Math.max(0, Math.min(score, maxScore));
  return (clampedScore / maxScore) * 100;
}

function calculateHttpsEnforcementScore(wasUpgraded, isHTTPS) {
  let score = 0, confidence = 100;
  if (!isHTTPS) {
    score = 20;
    confidence = 50;
  } else if (wasUpgraded) {
    score = 0;
    confidence = 100;
  } else {
    score = 0;
    confidence = 100;
  }
  return {
    score: normalizeScore(score, MAX_SCORES.HTTPS_ENFORCEMENT),
    confidence
  };
}

function calculateConnectionSecurityScore(isHTTPS, isValidCertificate) {
  let score = 0, confidence = 100;
  if (!isHTTPS) {
    score = 10;
    confidence = 0;
  } else if (!isValidCertificate) {
    score = 10;
    confidence = 0;
  } else {
    score = 0;
    confidence = 100;
  }
  return {
    score: normalizeScore(score, MAX_SCORES.CONNECTION_SECURITY),
    confidence
  };
}

function calculateUrlScanScore(urlScanResult) {
  if (!urlScanResult || urlScanResult.unavailable) {
    return { score: 0, confidence: 0, available: false };
  }
  if (urlScanResult.result?.success && urlScanResult.result?.data) {
    const isMalicious = urlScanResult.result.data.isMalicious;
    if (isMalicious) {
      return {
        score: normalizeScore(100, MAX_SCORES.URLSCAN),
        confidence: 100,
        available: true
      };
    } else {
      return { score: 0, confidence: 80, available: true };
    }
  }
  return { score: 0, confidence: 0, available: false };
}

function calculateHeuristicsScore(anomalyScore, confidenceScore) {
  return {
    score: normalizeScore(anomalyScore, MAX_SCORES.HEURISTICS),
    confidence: Math.max(0, Math.min(100, confidenceScore))
  };
}

function calculateFinalScores(featureScores) {
  const { heuristics, urlScan, httpsEnforcement, connectionSecurity } = featureScores;
  let weightedThreatScore = 0, totalWeight = 0;
  
  // URLScan (only if available) - Most reliable signal (60%)
  if (urlScan.available) {
    weightedThreatScore += FEATURE_WEIGHTS.URLSCAN * urlScan.score;
    totalWeight += FEATURE_WEIGHTS.URLSCAN;
  }
  
  // Heuristics (always available) - Pattern-based analysis (25%)
  weightedThreatScore += FEATURE_WEIGHTS.HEURISTICS * heuristics.score;
  totalWeight += FEATURE_WEIGHTS.HEURISTICS;
  
  // HTTPS Enforcement (always available) - Binary check (15%)
  weightedThreatScore += FEATURE_WEIGHTS.HTTPS_ENFORCEMENT * httpsEnforcement.score;
  totalWeight += FEATURE_WEIGHTS.HTTPS_ENFORCEMENT;
  
  // Connection Security (not used in scoring - handled by browser)
  // weightedThreatScore += FEATURE_WEIGHTS.CONNECTION_SECURITY * connectionSecurity.score;
  // totalWeight += FEATURE_WEIGHTS.CONNECTION_SECURITY;
  
  const normalizedThreatScore = totalWeight > 0 ? weightedThreatScore / totalWeight : 0;
  const finalThreatScore = Math.max(0, Math.min(100, normalizedThreatScore));
  
  let weightedConfidence = 0, confidenceWeight = 0;
  
  // URLScan confidence (only if available) - Most reliable signal (60%)
  if (urlScan.available) {
    weightedConfidence += FEATURE_WEIGHTS.URLSCAN * urlScan.confidence;
    confidenceWeight += FEATURE_WEIGHTS.URLSCAN;
  }
  
  // Heuristics confidence - Pattern-based analysis (25%)
  weightedConfidence += FEATURE_WEIGHTS.HEURISTICS * heuristics.confidence;
  confidenceWeight += FEATURE_WEIGHTS.HEURISTICS;
  
  // HTTPS Enforcement confidence - Binary check (15%)
  weightedConfidence += FEATURE_WEIGHTS.HTTPS_ENFORCEMENT * httpsEnforcement.confidence;
  confidenceWeight += FEATURE_WEIGHTS.HTTPS_ENFORCEMENT;
  
  // Connection Security confidence (not used in scoring)
  // weightedConfidence += FEATURE_WEIGHTS.CONNECTION_SECURITY * connectionSecurity.confidence;
  // confidenceWeight += FEATURE_WEIGHTS.CONNECTION_SECURITY;
  
  const normalizedConfidence = confidenceWeight > 0 ? weightedConfidence / confidenceWeight : 0;
  const finalConfidenceScore = Math.max(0, Math.min(100, normalizedConfidence));
  
    return {
    threatScore: Math.round(finalThreatScore * 100) / 100,
    confidenceScore: Math.round(finalConfidenceScore * 100) / 100,
    breakdown: {
      urlScan: {
        score: Math.round(urlScan.score * 100) / 100,
        confidence: Math.round(urlScan.confidence * 100) / 100,
        weight: FEATURE_WEIGHTS.URLSCAN,
        available: urlScan.available
      },
      heuristics: {
        score: Math.round(heuristics.score * 100) / 100,
        confidence: Math.round(heuristics.confidence * 100) / 100,
        weight: FEATURE_WEIGHTS.HEURISTICS
      },
      httpsEnforcement: {
        score: Math.round(httpsEnforcement.score * 100) / 100,
        confidence: Math.round(httpsEnforcement.confidence * 100) / 100,
        weight: FEATURE_WEIGHTS.HTTPS_ENFORCEMENT
      },
      connectionSecurity: {
        score: Math.round(connectionSecurity.score * 100) / 100,
        confidence: Math.round(connectionSecurity.confidence * 100) / 100,
        weight: FEATURE_WEIGHTS.CONNECTION_SECURITY
      }
    }
  };
}

function determineSeverity(threatScore, confidenceScore) {
  const adjustedScore = threatScore * (confidenceScore / 100);
  if (adjustedScore >= 80 || (threatScore >= 90 && confidenceScore >= 60)) {
    return 'critical';
  }
  if (adjustedScore >= 40 || (threatScore >= 50 && confidenceScore >= 40)) {
    return 'warning';
  }
  return 'secure';
}

function calculateUnifiedScores(data) {
  const {
    heuristicsAnomalyScore = 0,
    heuristicsConfidenceScore = 0,
    urlScanResult = null,
    httpsUpgraded = false,
    isHTTPS = true,
    isValidCertificate = true
  } = data;
  
  const heuristics = calculateHeuristicsScore(heuristicsAnomalyScore, heuristicsConfidenceScore);
  console.log("this is the urlscanresult stuff", urlScanResult);
  const urlScan = calculateUrlScanScore(urlScanResult); // here
  const httpsEnforcement = calculateHttpsEnforcementScore(httpsUpgraded, isHTTPS);
  const connectionSecurity = calculateConnectionSecurityScore(isHTTPS, isValidCertificate);
  
  const finalScores = calculateFinalScores({
    heuristics,
    urlScan,
    httpsEnforcement,
    connectionSecurity
  });
  
  const severity = determineSeverity(finalScores.threatScore, finalScores.confidenceScore);
  
      return {
    ...finalScores,
    severity,
    rawScores: {
      heuristicsAnomalyScore,
      heuristicsConfidenceScore
    }
  };
}

// Handle heuristics results from content script
async function handleHeuristicsResults(results, sender) {
  const tabId = sender.tab?.id;
  if (!tabId) {
    console.log('No tab ID for heuristics results');
    return;
  }

  // If activeTabId not set yet, set it to this tab (initialization)
  if (activeTabId === null) {
    activeTabId = tabId;
    console.log('📑 Setting initial active tab from heuristics:', tabId);
  }

  // Only process heuristics for the active tab
  if (tabId !== activeTabId) {
    console.log(`⏭️ Skipping heuristics for inactive tab ${tabId} (active: ${activeTabId})`);
    return;
  }

  // Get URLScan result for this hostname
  const hostname = new URL(sender.tab.url).hostname;
  const url = new URL(sender.tab.url)
  let urlScanResult = await getUrlScanResult(hostname);
  if (urlScanResult === null) {
    console.log("Getting urlscan result before calculating score")
    await urlScan(url);
    urlScanResult = await getUrlScanResult(hostname);
  }

  console.log("this is the urlscanresult from storage", urlScanResult);
  
  // Get HTTPS upgrade status for this tab
  const httpsUpgraded = tabUpgradeCounts.has(tabId) && tabUpgradeCounts.get(tabId) > 0;
  const isHTTPS = sender.tab.url.startsWith('https://');
  
  // Check connection security (assume valid certificate if HTTPS)
  // In Chrome MV3, we can't verify certificate details, so we assume valid if HTTPS
  const isValidCertificate = isHTTPS; // Simplified for Chrome MV3
  
  // Calculate unified scores using mathematical scoring system
  const unifiedScores = calculateUnifiedScores({
    heuristicsAnomalyScore: results.anomalyScore || 0,
    heuristicsConfidenceScore: results.confidenceScore || 0,
    urlScanResult: urlScanResult || null,
    httpsUpgraded,
    isHTTPS,
    isValidCertificate
  });
  
  console.log('📊 Unified scoring results:', {
    threatScore: unifiedScores.threatScore,
    confidenceScore: unifiedScores.confidenceScore,
    severity: unifiedScores.severity,
    breakdown: unifiedScores.breakdown
  });

  // Store unified results with tabId in key for easy filtering
  const storageKey = `heuristics_${tabId}_${hostname}_${Date.now()}`;

  chrome.storage.local.set({
    [storageKey]: {
      // Keep original heuristics data for reference
      anomalyScore: results.anomalyScore || 0,
      confidenceScore: results.confidenceScore || 0,
      detectedIssues: results.detectedIssues || [],
      externalLinks: results.externalLinks || [],
      externalPosts: results.externalPosts || [],
      
      // Unified scores (normalized 0-100)
      threatScore: unifiedScores.threatScore,
      confidenceScore: unifiedScores.confidenceScore,
      severity: unifiedScores.severity,
      
      // Score breakdown for transparency
      scoreBreakdown: unifiedScores.breakdown,
      
      // Metadata
      hostname,
      tabId,
      timestamp: Date.now(),
      
      // Feature status
      urlScan: urlScanResult ? {
        whitelisted: urlScanResult.result?.whitelisted || false,
        available: !urlScanResult.unavailable,
        malicious: urlScanResult.result?.data?.isMalicious || false,
        unavailable: urlScanResult.unavailable || false,
        message: urlScanResult.result?.message || urlScanResult.message
      } : null,
      httpsUpgraded,
      isHTTPS,
      isValidCertificate
    }
  });

  // Clean up old entries for this tab (keep only most recent)
  cleanupOldTabEntries(tabId);

  // Update badge based on unified severity (use threatScore for badge)
  updateBadgeFromHeuristics(tabId, {
    severity: unifiedScores.severity,
    anomalyScore: unifiedScores.threatScore // Use unified threat score for badge
  });

  // Log critical threats
  if (unifiedScores.severity === 'critical') {
    console.log('🚨 CRITICAL threat detected!', {
      threatScore: unifiedScores.threatScore,
      confidenceScore: unifiedScores.confidenceScore,
      issues: results.detectedIssues?.length || 0
    });
  }
}

// Get URLScan result for a hostname in storage
async function getUrlScanResult(hostname) {
  try {
    const storageData = await chrome.storage.local.get();
    const urlScanKey = `urlscan_${hostname}`;
    return storageData[urlScanKey] || null;
  } catch (error) {
    console.error('Error getting URLScan result:', error);
    return null;
  }
}

// Integrate URLScan results into heuristics scoring
function integrateUrlScanResults(results, urlScanResult) {
  if (!urlScanResult || urlScanResult.unavailable) {
    // URLScan unavailable - add informational issue but don't penalize score
    results.detectedIssues.push({
      type: 'urlscan_unavailable',
      severity: 'info',
      message: 'URLScan.io service unavailable - backend may not be running',
      score: 0
    });
    return;
  }

  if (urlScanResult.result?.success && urlScanResult.result?.data) {
    const isMalicious = urlScanResult.result.data.isMalicious;
    
    if (isMalicious) {
      // URLScan marked as malicious - add significant points
      results.anomalyScore += 100;
      results.confidenceScore = Math.min(100, results.confidenceScore + 30); // Increase confidence
      
      results.detectedIssues.push({
        type: 'urlscan_malicious',
        severity: 'critical',
        message: 'URLScan.io flagged this URL as malicious',
        score: 100
      });
      
      console.log('🚨 URLScan marked URL as malicious - added 100 points');
    } else {
      // URLScan marked as safe - increase confidence but don't reduce score
      results.confidenceScore = Math.min(100, results.confidenceScore + 10);
      
      results.detectedIssues.push({
        type: 'urlscan_safe',
        severity: 'info',
        message: 'URLScan.io verified this URL as safe',
        score: 0
      });
    }
    
    // Recalculate severity with new score (using same logic as heuristics engine)
    const adjustedScore = results.anomalyScore * (results.confidenceScore / 100);
    if (adjustedScore >= 80 || (results.anomalyScore >= 100 && results.confidenceScore >= 60)) {
      results.severity = 'critical';
    } else if (adjustedScore >= 40 || (results.anomalyScore >= 50 && results.confidenceScore >= 40)) {
      results.severity = 'warning';
    } else if (results.anomalyScore >= 20) {
      results.severity = 'warning';
    } else {
      results.severity = 'secure';
    }
  }
}

// Clean up old heuristics entries for a tab (keep only most recent)
async function cleanupOldTabEntries(tabId) {
  const storageData = await chrome.storage.local.get();
  const tabKeys = Object.keys(storageData).filter(key => 
    key.startsWith(`heuristics_${tabId}_`)
  );
  
  if (tabKeys.length > 5) {
    // Keep only 5 most recent entries
    const sortedKeys = tabKeys
      .map(key => ({ key, timestamp: storageData[key].timestamp || 0 }))
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(5);
    
    const keysToDelete = tabKeys.filter(key => 
      !sortedKeys.some(sk => sk.key === key)
    );
    
    chrome.storage.local.remove(keysToDelete);
  }
}

// Update badge based on heuristics results (only for active tab)
function updateBadgeFromHeuristics(tabId, results) {
  // Only update badge for the active tab
  if (tabId !== activeTabId) {
    return;
  }
  
  const badgeMap = {
    'critical': { text: '🚨', color: '#F44336' },
    'high': { text: '⚠️', color: '#FF9800' },
    'warning': { text: '⚠', color: '#FF9800' },
    'secure': { text: '', color: '#4CAF50' }
  };

  const config = badgeMap[results.severity] || badgeMap['secure'];
  chrome.action.setBadgeText({ text: config.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
  
  // Clear badges on inactive tabs
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      if (tab.id !== activeTabId) {
        chrome.action.setBadgeText({ text: '', tabId: tab.id });
      }
    });
  });
}

// DISABLED: No full-screen warnings - all warnings shown in popup only
// function showHeuristicsWarning(tabId, results) {
//   // Removed - warnings are now shown only in extension popup
// }
