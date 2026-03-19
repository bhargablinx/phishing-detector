import { buildPrompt } from "./02_promptBuilder.js";
import { extractMetadata } from "./01_metadataExtractor.js";

const API_KEY = "AIzaSyAoCiDP8wR8ih4a_9bYWgEVo6BmX7uWkQY";

export async function analyzeWithLLM(url) {
  const metadata = extractMetadata(url);
  const prompt = buildPrompt(url, metadata);

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${API_KEY}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        contents: [
          {
            parts: [{ text: prompt }]
          }
        ]
      })
    }
  );

  const data = await response.json();

  try {
    const text = data.candidates[0].content.parts[0].text;
    return JSON.parse(text);
  } catch (err) {
    return {
      isPhishing: false,
      confidence: 0,
      reason: "LLM parse error"
    };
  }
}