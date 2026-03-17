/*
URL Rules

Purpose:
Detect suspicious patterns inside the URL string itself.

These checks are cheap and fast.

We detect:
- phishing keywords
- very long URLs
- '@' redirection trick
*/
import suspiciousKeywords from "../../config/suspiciousKeywords.js";

export function checkUrlRules(url) {

    const lower = url.toLowerCase();

    // strong signal → block
    if (url.includes("@")) {
        return { block: true };
    }

    // count keyword matches (cheap + fast)
    let matches = 0;
    for (const k of suspiciousKeywords) {
        if (lower.includes(k)) matches++;
        if (matches >= 2) return { suspicious: true }; // early exit
    }

    //  mild signals
    if (url.length > 300 || (url.match(/&/g)?.length || 0) > 5) {
        return { suspicious: true };
    }

    return {};
}