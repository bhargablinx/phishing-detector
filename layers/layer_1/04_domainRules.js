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

    let suspicious = false;

    const parts = domain.split(".");
    const tld = parts[parts.length - 1];

    // suspicious TLD
    if (badTlds.includes(tld)) {
        suspicious = true;
    }


    /* Punycode Detection
    Example:
    xn--pple-43d.com
    which visually looks like "apple.com"
    */
    if (domain.includes("xn--")) {
        suspicious = true;
    }


    // too many subdomains
    if (parts.length > 4) {
        suspicious = true;
    }
    

    // IP address domain
    const ipPattern = /^\d+\.\d+\.\d+\.\d+$/;

    if (ipPattern.test(domain)) {
        suspicious = true;
    }

    return { suspicious };
}