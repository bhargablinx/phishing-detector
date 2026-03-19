export function buildPrompt(url, metadata) {
  return `
        You are a cybersecurity expert.

        Analyze this URL and determine if it is a phishing site.

        URL: ${url}

        Metadata:
        ${JSON.stringify(metadata)}

        Return ONLY JSON:
        {
        "isPhishing": true/false,
        "confidence": 0-100,
        "reason": "short explanation"
        }
        `;
}