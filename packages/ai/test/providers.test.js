import { jest } from "@jest/globals";
import { LocalExplanationProvider, OpenAIExplanationProvider } from "../src/index.js";

describe("AI providers", () => {
  test("local provider produces an evidence-grounded explanation", async () => {
    const provider = new LocalExplanationProvider();
    const result = await provider.explain({
      anomaly: { anomalyScore: 0.8, isAnomalous: true },
      risk: { score: 72, reasons: ["Macro-related content detected"] },
      sandbox: { triggered: true, status: "completed" },
    });

    expect(result.provider).toBe("local");
    expect(result.explanation).toMatch(/72\/100/);
    expect(result.explanation).toMatch(/anomalous/i);
  });

  test("OpenAI provider calls Responses API and returns output text", async () => {
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        id: "resp_test",
        output_text: "Evidence summary",
      }),
    });

    const provider = new OpenAIExplanationProvider({
      apiKey: "test-key",
      model: "test-model",
      endpoint: "https://example.test/v1/responses",
      fetchImpl: fetchMock,
    });

    const result = await provider.explain({
      filename: "sample.pdf",
      features: { entropy: 6.8 },
      findings: [],
      anomaly: { anomalyScore: 0.2, isAnomalous: false },
      risk: { score: 15, reasons: [] },
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe("https://example.test/v1/responses");
    expect(options.headers.Authorization).toBe("Bearer test-key");
    expect(JSON.parse(options.body).model).toBe("test-model");
    expect(result.provider).toBe("openai");
    expect(result.explanation).toBe("Evidence summary");
  });
});
