import fs from "node:fs";
import { IsolationForest } from "./isolation-forest.js";

export function loadAnomalyModel(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return IsolationForest.fromJSON(JSON.parse(raw));
}

export function createAnomalyDetectorFromEnv() {
  const configuredPath = process.env.ANOMALY_MODEL_PATH;
  if (configuredPath) return loadAnomalyModel(configuredPath);
  return null;
}
