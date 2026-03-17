/*
Rule Engine : Controller of layer_1

Order of execution :

1. Whitelist (skip everything)
2. Blacklist (instant block)
3. URL Rules
4. Domain Rules

Final Output:
SAFE
PHISHING
SUSPICIOUS
*/
import { isWhitelisted } from "./01_whitelist.js";
import { isBlacklisted } from "./02_blacklist.js";
import { checkUrlRules } from "./03_urlRules.js";
import { checkDomainRules } from "./04_domainRules.js";

export async function runRuleEngine(url, domain) {

    // 1. Whitelist → allow immediately
    if (await isWhitelisted(domain)) {
        return { status: "safe" };
    }

    // 2. Blacklist → block immediately
    if (await isBlacklisted(domain, url)) {
        return { status: "phishing" };
    }

    // 3. URL rules (fast check)
    const urlRes = checkUrlRules(url);
    if (urlRes.block) {
        return { status: "phishing" };
    }

    // 4. Domain rules (fast check)
    const domainRes = checkDomainRules(domain);

    // 5. Only mark suspicious (no heavy merging)
    if (urlRes.suspicious || domainRes.suspicious) {
        return { status: "suspicious" };
    }

    // default
    return { status: "safe" };
}