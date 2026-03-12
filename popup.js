// Show current website
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    try {
        const url = new URL(tabs[0].url);
        document.getElementById("currentSite").textContent = url.hostname;
    } catch {
        document.getElementById("currentSite").textContent = "Unknown";
    }
});

// Load whitelist
function loadWhitelist() {
    chrome.storage.local.get(["websiteToIgnore"], (data) => {
        const list = data.websiteToIgnore || [];
        const container = document.getElementById("whitelist");

        container.innerHTML = "";

        if (list.length === 0) {
            container.innerHTML = "No whitelisted sites";
            return;
        }

        list.forEach((domain) => {
            const div = document.createElement("div");
            div.className = "site";

            const span = document.createElement("span");
            span.className = "domain";
            span.textContent = domain;

            const btn = document.createElement("button");
            btn.className = "remove-btn";

            btn.innerHTML = `
<svg viewBox="0 0 24 24" width="14" height="14">
<line x1="5" y1="12" x2="19" y2="12"
stroke="white"
stroke-width="2"
stroke-linecap="round"/>
</svg>
`;

            btn.onclick = () => {
                chrome.storage.local.get(["websiteToIgnore"], (data) => {
                    let arr = data.websiteToIgnore || [];
                    arr = arr.filter((d) => d !== domain);

                    chrome.storage.local.set(
                        { websiteToIgnore: arr },
                        loadWhitelist,
                    );
                });
            };

            btn.onclick = () => {
                chrome.storage.local.get(["websiteToIgnore"], (data) => {
                    let arr = data.websiteToIgnore || [];
                    arr = arr.filter((d) => d !== domain);

                    chrome.storage.local.set(
                        { websiteToIgnore: arr },
                        loadWhitelist,
                    );
                });
            };

            div.appendChild(span);
            div.appendChild(btn);

            container.appendChild(div);
        });
    });
}

loadWhitelist();
