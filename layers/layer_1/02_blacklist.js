/**
 * 02_blacklist.js
 * Layer 1 — blacklist check. Runs after whitelist, before URL/domain heuristics.
 *
 * Two checks:
 *  1. Local blacklist (LLM-confirmed domains) → Bloom Filter, O(k)
 *  2. External feed (OpenPhish + Phishing.Database) → Set.has(), O(1)
 *
 * Bloom Filter false positives (~0.1%) are safe — they propagate as "phishing"
 * and get verified by the next layer. No legitimate site is silently blocked.
 */

import { BloomFilter }       from "../../utils/bloomFilter.js";
import { isFeedBlacklisted } from "../../services/blacklistFeeds.js";

// Bloom Filter sized for 700K items @ 0.1% FPR: ~1.2 MB
const localBloomFilter = new BloomFilter(10_000_000, 10);
let filterInitialized  = false;

/** Loads the local blacklist from storage and populates the Bloom Filter. */
async function initializeBloomFilter() {
  const { blacklist = [] } = await chrome.storage.local.get(["blacklist"]);
  localBloomFilter.clear();
  localBloomFilter.addAll(blacklist);
  filterInitialized = true;
  console.log(`[Sentinel] Bloom Filter ready — ${blacklist.length} domains, FPR: ${(localBloomFilter.falsePositiveRate * 100).toFixed(4)}%`);
}

/**
 * Rebuilds the filter whenever a new domain is added to the local blacklist.
 * Ensures newly confirmed phishing domains are detectable immediately.
 */
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.blacklist) {
    console.log("[Sentinel] Blacklist updated — rebuilding Bloom Filter...");
    initializeBloomFilter();
  }
});

/**
 * Returns true if the domain is (probably) blacklisted.
 * @param {string} domain - Hostname to check, e.g. "evil.com"
 * @param {string} url    - Full URL (passed through for consistency)
 */
export async function isBlacklisted(domain, url) {
  // Step 1 — Local Bloom Filter
  if (!filterInitialized) await initializeBloomFilter();
  if (localBloomFilter.has(domain)) {
    console.log(`[Sentinel] Bloom Filter hit: ${domain}`);
    return true;
  }

  // Step 2 — External feed Set
  if (await isFeedBlacklisted(domain)) {
    console.log(`[Sentinel] Feed Set hit: ${domain}`);
    return true;
  }

  return false;
}

/**
 * Adds a confirmed phishing domain to chrome.storage and the live Bloom Filter.
 * @param {string} domain
 */
export async function addToLocalBlacklist(domain) {
  const { blacklist = [] } = await chrome.storage.local.get(["blacklist"]);
  if (!blacklist.includes(domain)) {
    blacklist.push(domain);
    await chrome.storage.local.set({ blacklist });
    localBloomFilter.add(domain); // Immediate effect without waiting for storage event
    console.log(`[Sentinel] Added to local blacklist: ${domain}`);
  }
}

