/*
Blacklist Rule

Purpose:
Immediately block domains that are already known to be phishing.

Sources:
1. Domains added after LLM detection
2. Domains added from threat feed APIs
3. Manual developer additions

This list is stored in chrome.storage so it persists.
*/
import { getAllPhishingFeeds } from "../../services/blacklistFeeds.js";

export async function isBlacklisted(domain, url) {

    /* 1. Local blacklist */
    const data = await chrome.storage.local.get(["blacklist"]);
    const blacklist = data.blacklist || [];

    if (blacklist.includes(domain)) {
        return true;
    }

    /* 2. External feed */
    const feed = await getAllPhishingFeeds();

    // safer match
    const isMatch = feed.some(phishUrl => {
        return url === phishUrl || url.startsWith(phishUrl);
    });

    if (isMatch) {
        return true;
    }

    return false;
}


