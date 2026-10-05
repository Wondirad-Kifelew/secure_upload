import fs from "node:fs/promises";
import path from "node:path";
import { IsolationForest } from "../packages/risk-engine/src/index.js";

const [inputPath, outputPath = "./storage/models/anomaly-model.json"] = process.argv.slice(2);
if (!inputPath) {
  console.error("Usage: node scripts/train-anomaly-model.js <training-json> [output-json]");
  process.exit(1);
}

const raw = await fs.readFile(inputPath, "utf8");
const dataset = JSON.parse(raw);
const vectors = dataset.vectors ?? dataset;
const detector = new IsolationForest({ nTrees: 128, sampleSize: Math.min(128, vectors.length), threshold: 0.65, seed: 1337 });
detector.fit(vectors);

await fs.mkdir(path.dirname(outputPath), { recursive: true });
await fs.writeFile(outputPath, JSON.stringify(detector.toJSON(), null, 2));
console.log(`Saved anomaly model to ${outputPath}`);
