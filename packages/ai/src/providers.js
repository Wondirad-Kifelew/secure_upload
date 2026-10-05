import { buildSecurityExplanationInput, SECURITY_AI_INSTRUCTIONS } from "./prompt.js";

export class AIProvider {
  async explain(_input) {
    throw new Error("AIProvider.explain() must be implemented.");
  }
}

export class LocalExplanationProvider extends AIProvider {
  async explain(input) {
    const anomalyText = input.anomaly?.isAnomalous
      ? `The ML model marked the file as anomalous (score ${Number(input.anomaly.anomalyScore).toFixed(2)}).`
      : "The ML anomaly model did not mark the file as anomalous.";

    const riskText = `The deterministic risk engine produced a score of ${input.risk?.score ?? "unknown"}/100.`;
    const reasons = (input.risk?.reasons ?? []).slice(0, 5);
    const reasonText = reasons.length
      ? `Main contributing signals: ${reasons.join("; ")}.`
      : "No major contributing signals were recorded.";
    const sandboxText = input.sandbox?.triggered
      ? `Sandbox analysis was ${input.sandbox.status}; dynamic evidence was kept separate from the ML score.`
      : "Sandbox analysis was not triggered by the current policy.";

    return {
      provider: "local",
      model: "deterministic-template",
      explanation: `${riskText} ${anomalyText} ${reasonText} ${sandboxText}`,
    };
  }
}

/**
 * OpenAI Responses API adapter.
 *
 * Uses the Node.js built-in fetch so this package has no runtime SDK
 * dependency. Only structured security evidence is sent; raw file bytes are
 * intentionally excluded from the request.
 */
export class OpenAIExplanationProvider extends AIProvider {
  constructor({
    apiKey = process.env.OPENAI_API_KEY,
    model = process.env.OPENAI_MODEL || "gpt-5.6-luna",
    endpoint = "https://api.openai.com/v1/responses",
    fetchImpl = globalThis.fetch,
  } = {}) {
    super();
    if (!apiKey) {
      throw new Error("OPENAI_API_KEY is required for OpenAIExplanationProvider.");
    }
    if (typeof fetchImpl !== "function") {
      throw new Error("A fetch implementation is required for OpenAIExplanationProvider.");
    }

    this.apiKey = apiKey;
    this.model = model;
    this.endpoint = endpoint;
    this.fetchImpl = fetchImpl;
  }

  async explain(input) {
    const response = await this.fetchImpl(this.endpoint, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: this.model,
        input: [
          {
            role: "system",
            content: [{ type: "input_text", text: SECURITY_AI_INSTRUCTIONS }],
          },
          {
            role: "user",
            content: [{
              type: "input_text",
              text: `Analyze this security evidence and produce a concise explanation:\n\n${buildSecurityExplanationInput(input)}`,
            }],
          },
        ],
        max_output_tokens: 450,
      }),
    });

    const rawText = await response.text();
    let data;
    try {
      data = JSON.parse(rawText);
    } catch {
      data = null;
    }

    if (!response.ok) {
      throw new Error(`OpenAI Responses API returned HTTP ${response.status}: ${data?.error?.message ?? rawText}`);
    }

    const explanation = data?.output_text?.trim() || extractOutputText(data);
    return {
      provider: "openai",
      model: this.model,
      explanation: explanation || "The AI provider returned no explanation text.",
      responseId: data?.id ?? null,
    };
  }
}

function extractOutputText(data) {
  const parts = [];
  for (const item of data?.output ?? []) {
    for (const content of item?.content ?? []) {
      if (content?.type === "output_text" && typeof content.text === "string") {
        parts.push(content.text);
      }
    }
  }
  return parts.join("\n").trim();
}

export function createAIProviderFromEnv() {
  if (process.env.AI_PROVIDER === "disabled") return null;
  if (process.env.OPENAI_API_KEY) return new OpenAIExplanationProvider();
  return new LocalExplanationProvider();
}
