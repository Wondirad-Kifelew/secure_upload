function averagePathLength(n) {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  const harmonic = Array.from({ length: n - 1 }, (_, i) => 1 / (i + 1))
    .reduce((sum, value) => sum + value, 0);
  return 2 * harmonic - (2 * (n - 1)) / n;
}

function seededRandom(seed) {
  let state = (seed >>> 0) || 0x9e3779b9;
  return () => {
    state += 0x6d2b79f5;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function sampleWithoutReplacement(items, count, random) {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy.slice(0, count);
}

function range(data, dimension, indices) {
  let min = Infinity;
  let max = -Infinity;
  for (const index of indices) {
    const value = data[index][dimension];
    min = Math.min(min, value);
    max = Math.max(max, value);
  }
  return { min, max };
}

export class IsolationForest {
  constructor({ nTrees = 64, sampleSize = 64, threshold = 0.65, seed = 1337 } = {}) {
    this.nTrees = nTrees;
    this.sampleSize = sampleSize;
    this.threshold = threshold;
    this.seed = seed;
    this.trees = [];
    this.trainingSize = 0;
    this.featureCount = null;
    this.fitted = false;
  }

  fit(vectors) {
    if (!Array.isArray(vectors) || vectors.length < 4) {
      throw new TypeError("IsolationForest.fit requires at least 4 training vectors.");
    }

    const normalized = vectors.map((vector) => {
      if (!Array.isArray(vector) || vector.length === 0 || vector.some((value) => !Number.isFinite(value))) {
        throw new TypeError("Training vectors must be non-empty arrays of finite numbers.");
      }
      return vector.map(Number);
    });

    const featureCount = normalized[0].length;
    if (normalized.some((vector) => vector.length !== featureCount)) {
      throw new TypeError("All training vectors must have the same feature count.");
    }

    this.featureCount = featureCount;
    this.trainingSize = normalized.length;
    this.subsampleSize = Math.min(this.sampleSize, normalized.length);
    this.maxDepth = Math.ceil(Math.log2(Math.max(this.subsampleSize, 2)));
    this.trees = [];

    const random = seededRandom(this.seed);
    const allIndices = normalized.map((_, index) => index);

    for (let treeIndex = 0; treeIndex < this.nTrees; treeIndex += 1) {
      const sample = sampleWithoutReplacement(allIndices, this.subsampleSize, random);
      this.trees.push(this.#buildTree(normalized, sample, 0, random));
    }

    this.fitted = true;
    return this;
  }

  #buildTree(data, indices, depth, random) {
    if (indices.length <= 1 || depth >= this.maxDepth) {
      return { leaf: true, size: indices.length };
    }

    const candidateDimensions = [];
    for (let dimension = 0; dimension < this.featureCount; dimension += 1) {
      const { min, max } = range(data, dimension, indices);
      if (max > min) candidateDimensions.push(dimension);
    }

    if (candidateDimensions.length === 0) {
      return { leaf: true, size: indices.length };
    }

    const dimension = candidateDimensions[Math.floor(random() * candidateDimensions.length)];
    let { min, max } = range(data, dimension, indices);
    let split = min + random() * (max - min);
    let left = indices.filter((index) => data[index][dimension] < split);
    let right = indices.filter((index) => data[index][dimension] >= split);

    if (left.length === 0 || right.length === 0) {
      const values = indices.map((index) => data[index][dimension]).sort((a, b) => a - b);
      split = values[Math.floor(values.length / 2)];
      left = indices.filter((index) => data[index][dimension] < split);
      right = indices.filter((index) => data[index][dimension] >= split);
    }

    if (left.length === 0 || right.length === 0) {
      return { leaf: true, size: indices.length };
    }

    return {
      leaf: false,
      dimension,
      split,
      left: this.#buildTree(data, left, depth + 1, random),
      right: this.#buildTree(data, right, depth + 1, random),
    };
  }

  #pathLength(vector, node, depth) {
    if (node.leaf) {
      return depth + averagePathLength(node.size);
    }

    if (vector[node.dimension] < node.split) {
      return this.#pathLength(vector, node.left, depth + 1);
    }
    return this.#pathLength(vector, node.right, depth + 1);
  }

  score(vector) {
    if (!this.fitted) throw new Error("IsolationForest must be fitted before scoring.");
    if (!Array.isArray(vector) || vector.length !== this.featureCount || vector.some((value) => !Number.isFinite(value))) {
      throw new TypeError(`Expected a vector of ${this.featureCount} finite numbers.`);
    }

    const averagePath = this.trees.reduce(
      (sum, tree) => sum + this.#pathLength(vector, tree, 0),
      0
    ) / this.trees.length;

    const normalization = averagePathLength(this.subsampleSize);
    const anomalyScore = normalization === 0 ? 0.5 : Math.pow(2, -averagePath / normalization);

    return {
      anomalyScore,
      isAnomalous: anomalyScore >= this.threshold,
      threshold: this.threshold,
      averagePathLength: averagePath,
    };
  }

  predict(vector) {
    return this.score(vector);
  }

  toJSON() {
    if (!this.fitted) throw new Error("Cannot serialize an unfitted IsolationForest.");
    return {
      version: 1,
      nTrees: this.nTrees,
      sampleSize: this.sampleSize,
      threshold: this.threshold,
      seed: this.seed,
      trainingSize: this.trainingSize,
      featureCount: this.featureCount,
      trees: this.trees,
    };
  }

  static fromJSON(model) {
    if (!model || model.version !== 1 || !Array.isArray(model.trees)) {
      throw new TypeError("Invalid IsolationForest model.");
    }
    const detector = new IsolationForest(model);
    detector.trainingSize = model.trainingSize;
    detector.featureCount = model.featureCount;
    detector.subsampleSize = Math.min(model.sampleSize, model.trainingSize);
    detector.maxDepth = Math.ceil(Math.log2(Math.max(detector.subsampleSize, 2)));
    detector.trees = model.trees;
    detector.fitted = true;
    return detector;
  }
}
