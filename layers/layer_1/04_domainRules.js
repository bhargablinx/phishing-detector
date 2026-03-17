/*
Domain Rules

Purpose:
Analyze domain structure for phishing indicators.

Checks include:
- suspicious TLDs
- punycode domains (homograph attacks)
- too many subdomains
- IP address domains
*/
import badTlds from "../../config/badTlds.js";

export function checkDomainRules(domain) {

    const parts = domain.split(".");
    const tld = parts.pop();

    //  stronger signals first
    if (domain.includes("xn--")) return { suspicious: true };

    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(domain);
    if (isIP) return { suspicious: true };

    //  weaker signals combined
    if (badTlds.includes(tld) && parts.length > 2) {
        return { suspicious: true };
    }

    return {};
}