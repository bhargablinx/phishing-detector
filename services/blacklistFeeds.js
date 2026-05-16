/**
 * blacklistFeeds.js
 * Manages the external phishing feed as an in-memory Set for O(1) lookups.
 *
 * Key design decisions:
 *  - URLs normalized to hostnames before storage → exact-match with Set.has()
 *  - Feed cached in chrome.storage.local (TTL 6h) → survives service worker restarts
 *  - Pre-loaded on startup → zero network latency during URL checks
 */

const FEED_SOURCES = [
  "https://openphish.com/feed.txt",
  "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
];

const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const STORAGE_KEY  = "phishingFeedCache";

/** In-memory Set of hostnames. Null until preloadPhishingFeed() completes. */
let feedSet = null;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Extracts hostname from a raw URL.
 * "http://evil.com/path?x=1" → "evil.com"
 * Returns null for malformed URLs (filtered out before storage).
 */
function normalizeToHostname(rawUrl) {
  try {
    const urlStr = rawUrl.startsWith("http") ? rawUrl : `http://${rawUrl}`;
    return new URL(urlStr).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Fetches one feed source. Returns lines as string array. Empty array on error. */
async function fetchFeedSource(sourceUrl) {
  try {
    const text = await (await fetch(sourceUrl)).text();
    return text.split("\n").map(l => l.trim()).filter(Boolean);
  } catch (err) {
    console.error(`[Sentinel] Feed fetch failed: ${sourceUrl}`, err);
    return [];
  }
}

/** Normalizes raw lines and deduplicates into a Set. */
function buildFeedSet(rawLines) {
  return new Set(rawLines.map(normalizeToHostname).filter(Boolean));
}

/** Persists feed to chrome.storage.local with a timestamp. */
async function persistFeedToStorage(set) {
  try {
    const payload = { [STORAGE_KEY]: { hostnames: [...set], fetchedAt: Date.now() } };
    const sizeMB  = (JSON.stringify(payload).length / 1024 / 1024).toFixed(2);
    console.log(`[Sentinel] Persisting feed — ${set.size} domains, ${sizeMB} MB`);
    await chrome.storage.local.set(payload);
  } catch (err) {
    // Feed still works from memory this session; just won't persist across restarts.
    console.warn("[Sentinel] Storage persist failed:", err.message);
  }
}

/** Loads feed from storage if it exists and is within TTL. Returns null if stale/missing. */
async function loadFeedFromStorage() {
  try {
    const cache = (await chrome.storage.local.get([STORAGE_KEY]))[STORAGE_KEY];
    if (!cache?.hostnames || !cache?.fetchedAt) return null;
    if (Date.now() - cache.fetchedAt > CACHE_TTL_MS) {
      console.log("[Sentinel] Feed cache expired — will re-fetch.");
      return null;
    }
    console.log(`[Sentinel] Feed loaded from cache — ${cache.hostnames.length} domains`);
    return new Set(cache.hostnames);
  } catch {
    return null;
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Called by background.js on service worker startup.
 * Loads from storage cache if fresh, otherwise fetches all sources in parallel.
 * After this resolves, all lookups hit the in-memory Set with zero latency.
 */
export async function preloadPhishingFeed() {
  console.log("[Sentinel] Pre-loading phishing feed...");
  const cached = await loadFeedFromStorage();
  if (cached) { feedSet = cached; return; }

  const lines = (await Promise.all(FEED_SOURCES.map(fetchFeedSource))).flat();
  feedSet     = buildFeedSet(lines);
  console.log(`[Sentinel] Feed built — ${feedSet.size} unique domains`);
  await persistFeedToStorage(feedSet);
}

/**
 * O(1) lookup — called by 02_blacklist.js on every navigation.
 * Falls back to triggering preload if the Set is not yet initialized.
 */
export async function isFeedBlacklisted(hostname) {
  if (!feedSet) await preloadPhishingFeed();
  return feedSet.has(hostname);
}

/** Bypasses TTL and forces a fresh feed fetch. */
export async function refreshPhishingFeed() {
  console.log("[Sentinel] Force-refreshing feed...");
  const lines = (await Promise.all(FEED_SOURCES.map(fetchFeedSource))).flat();
  feedSet     = buildFeedSet(lines);
  await persistFeedToStorage(feedSet);
}
