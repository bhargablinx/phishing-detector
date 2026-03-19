export function extractMetadata(url) {
  const parsed = new URL(url);

  return {
    hostname: parsed.hostname,
    path: parsed.pathname,
    hasIP: /\d+\.\d+\.\d+\.\d+/.test(parsed.hostname),
    hasSuspiciousWords: /(login|verify|secure|account)/i.test(url),
    urlLength: url.length
  };
}