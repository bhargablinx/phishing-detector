import { runRuleEngine }      from "../layers/layer_1/ruleEngine.js";
import { analyzeWithLLM }     from "../layers/layer_2/03_llmAnalyzer.js";
import { preloadPhishingFeed } from "../services/blacklistFeeds.js";

console.log("[PhishSentinel] Service worker started.");

// STARTUP: PRE-LOAD PHISHING FEED


/**
 *  feed pre-loader immediately on startup.
 *
 * This runs in the background — it does NOT block navigation events.
 * If a navigation arrives before the feed is ready, the lookup in
 * isFeedBlacklisted() will await the same preload promise (fallback path).
 *
 * On subsequent startups within the 6-hour TTL window, this loads
 * from chrome.storage.local instantly (no network request).
 */
preloadPhishingFeed().catch(err => {
  console.error("[PhishSentinel] Feed pre-load failed:", err);
});

// ─────────────────────────────────────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────────────────────────────────────

// Tabs allowed to bypass scan once (used by "Continue Anyway" button)
const temporaryAllowTabs = new Set();

// Tabs currently being scanned (prevents redirect loop)
const scanningTabs = new Set();

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Extracts the hostname from a URL string.
 * Returns null if the URL is malformed.
 *
 * @param {string} url
 * @returns {string | null}
 */
function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// NAVIGATION INTERCEPTION
// ─────────────────────────────────────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {

  // Only intercept main frame navigations (frameId 0)
  if (details.frameId !== 0) return;

  const tabId = details.tabId;
  const url   = details.url;

  // Only scan HTTP/HTTPS pages
  if (!url.startsWith("http")) return;

  // Never scan our own extension pages (avoids infinite redirect loops)
  if (url.startsWith("chrome-extension://")) return;
  if (url.includes("loading.html") || url.includes("block.html")) return;

  // "Continue Anyway" bypass — user chose to proceed past the warning
  if (temporaryAllowTabs.has(tabId)) {
    temporaryAllowTabs.delete(tabId);
    return;
  }

  // Scan-in-progress guard — prevents re-intercepting our own redirect
  if (scanningTabs.has(tabId)) {
    scanningTabs.delete(tabId);
    return;
  }

  const domain = getDomain(url);
  if (!domain) return;

  // Mark tab as scanning and redirect to loading page
  scanningTabs.add(tabId);
  chrome.tabs.update(tabId, {
    url: chrome.runtime.getURL("ui/loading.html") + "?url=" + encodeURIComponent(url),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGE HANDLER
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender) => {

  const tabId = sender.tab?.id;
  if (!tabId) return;

  // ── SCAN FLOW ─────────────────────────────────────────────────────────────
  if (message.action === "scanNow") {

    const url    = message.url;
    const domain = getDomain(url);
    if (!domain) return;

    runRuleEngine(url, domain).then(async (result) => {

      // Clearly phishing → redirect to block page
      if (result.status === "phishing") {
        chrome.tabs.update(tabId, {
          url: chrome.runtime.getURL("ui/block.html") + "?url=" + encodeURIComponent(url),
        });
        return;
      }

      // Clearly safe → allow navigation
      if (result.status === "safe") {
        chrome.tabs.update(tabId, { url });
        return;
      }

      // Suspicious → escalate to LLM (Layer 2)
      const llmResult = await analyzeWithLLM(url);

      if (llmResult.isPhishing && llmResult.confidence > 70) {
        chrome.tabs.update(tabId, {
          url: chrome.runtime.getURL("ui/block.html") + "?url=" + encodeURIComponent(url),
        });
      } else {
        chrome.tabs.update(tabId, { url });
      }

    });

    return;
  }

  // ── CONTINUE ONCE ─────────────────────────────────────────────────────────
  if (message.action === "continueOnce") {
    temporaryAllowTabs.add(tabId);
    chrome.tabs.update(tabId, { url: message.url });
  }

  // ── ADD TO WHITELIST ──────────────────────────────────────────────────────
  if (message.action === "addWhitelist") {
    const domain = getDomain(message.url);

    chrome.storage.local.get(["websiteToIgnore"], (data) => {
      let list = data.websiteToIgnore || [];

      if (!list.includes(domain)) {
        list.push(domain);
      }

      chrome.storage.local.set({ websiteToIgnore: list }, () => {
        chrome.tabs.update(tabId, { url: message.url });
      });
    });
  }

  // ── GO BACK ───────────────────────────────────────────────────────────────
  if (message.action === "goBack") {
    chrome.tabs.remove(tabId);
  }

});