import { IsolationForest } from "../src/index.js";

describe("IsolationForest", () => {
  test("scores an outlier higher than a normal point", () => {
    const normal = [
      [0, 0], [0.1, 0.1], [0.2, 0.15], [0.05, 0.2],
      [0.15, 0], [0.3, 0.1], [0.25, 0.2], [0.1, 0.25],
    ];
    const detector = new IsolationForest({ nTrees: 80, sampleSize: 8, seed: 7, threshold: 0.55 }).fit(normal);
    const normalScore = detector.score([0.12, 0.12]);
    const outlierScore = detector.score([10, 10]);

    expect(outlierScore.anomalyScore).toBeGreaterThan(normalScore.anomalyScore);
    expect(outlierScore.isAnomalous).toBe(true);
  });

  test("serializes and restores a trained model", () => {
    const detector = new IsolationForest({ nTrees: 10, sampleSize: 6, seed: 1 }).fit([
      [0], [0.1], [0.2], [0.3], [0.15], [0.05],
    ]);
    const restored = IsolationForest.fromJSON(detector.toJSON());
    expect(restored.score([5]).anomalyScore).toBe(detector.score([5]).anomalyScore);
  });
});
