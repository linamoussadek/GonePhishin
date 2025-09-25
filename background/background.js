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
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    const url = changeInfo.url;
    if (!url || ['chrome://', 'about://'].some(p => url.startsWith(p))) return;
    if (!tab.active) return; // revisit
    console.log(url);
    await urlScan(url);
})


// should we have a list of safe sites? to avoid unnecessary requests
// maybe allow user to whitelist websites or we could have a list of preapproved common sites and look there first