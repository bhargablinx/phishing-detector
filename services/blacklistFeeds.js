let cachedFeed = null;

async function fetchFeed(url) {
  try {
    const response = await fetch(url);
    const text = await response.text();
    return text.split("\n").filter(Boolean);
  } catch (error) {
    console.error(`Error fetching ${url}:`, error);
    return [];
  }
}

export async function getAllPhishingFeeds() {
  if (cachedFeed) return cachedFeed;

  const sources = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
  ];

  const results = await Promise.all(sources.map(fetchFeed));

  let combined = results.flat();
  combined = [...new Set(combined)];

  cachedFeed = combined;
  return combined;
}