import { runRuleEngine } from "../layers/layer_1/ruleEngine.js";  
import { analyzeWithLLM } from "../layers/layer_2/03_llmAnalyzer.js";

console.log("Phishing detector background running");

// Tabs allowed to bypass scan once
const temporaryAllowTabs = new Set();

// Tabs currently being scanned (prevents loop)
const scanningTabs = new Set();

//extraction of domain from webpage
function getDomain(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return null;
    }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; //only scans the main page . (main page has 0 frameId)

    const tabId = details.tabId;
    const url = details.url;

    if (!url.startsWith("http")) return;

    // Ignore extension pages
    if (url.startsWith("chrome-extension://")) return;

    // Ignore internal extension page
    // If we don't ignore these, it will scan its own pages and cause infinite loops..
    if (url.includes("loading.html") || url.includes("block.html")) return; 

    // Continue Once bypass(used by "Continue Anyway" button)
    if (temporaryAllowTabs.has(tabId)) {
        temporaryAllowTabs.delete(tabId);
        return;
    }

    // Prevent scanning loop
    if (scanningTabs.has(tabId)) {
        scanningTabs.delete(tabId);
        return;
    }

    const domain = getDomain(url);
    if (!domain) return;

    
     //  redirect to loading page
    scanningTabs.add(tabId);

    chrome.tabs.update(tabId, {
        url:
            chrome.runtime.getURL("ui/loading.html") +
            "?url=" +
            encodeURIComponent(url),
    });
});


chrome.runtime.onMessage.addListener((message, sender) => {

    const tabId = sender.tab?.id;
    if (!tabId) return;

    // SCAN FLOW
    if (message.action === "scanNow") {

        const url = message.url;
        const domain = getDomain(url);
        if (!domain) return;

        runRuleEngine(url, domain).then(async (result) => {

                // Clearly phishing → block immediately
                if (result.status === "phishing") {
                    chrome.tabs.update(tabId, {
                        url:
                            chrome.runtime.getURL("ui/block.html") +
                            "?url=" +
                            encodeURIComponent(url),
                    });
                    return;
                }

                // Clearly safe → allow
                if (result.status === "safe") {
                    chrome.tabs.update(tabId, {
                        url: url,
                    });
                    return;
                }

                // Suspicious → send to LLM (Layer 2)
                const llmResult = await analyzeWithLLM(url);

                if (llmResult.isPhishing && llmResult.confidence > 70) {
                    chrome.tabs.update(tabId, {
                        url:
                            chrome.runtime.getURL("ui/block.html") +
                            "?url=" +
                            encodeURIComponent(url),
                    });
                } else {
                    chrome.tabs.update(tabId, {
                        url: url,
                    });
                }

            });

        return;
    }

    // Continue once
    if (message.action === "continueOnce") {
        temporaryAllowTabs.add(tabId);

        chrome.tabs.update(tabId, {
            url: message.url,
        });
    }

    //  Add to whitelist
    if (message.action === "addWhitelist") {
        const domain = getDomain(message.url);

        chrome.storage.local.get(["websiteToIgnore"], (data) => {
            let list = data.websiteToIgnore || [];

            if (!list.includes(domain)) {
                list.push(domain);
            }

            chrome.storage.local.set({ websiteToIgnore: list }, () => {
                chrome.tabs.update(tabId, {
                    url: message.url,
                });
            });
        });
    }
 
    //  Go back
    if (message.action === "goBack") {
        chrome.tabs.remove(tabId);
    }

});