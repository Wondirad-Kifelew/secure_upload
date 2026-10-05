/**
 * Root Jest config. Each package is registered as its own "project" so
 * `npm test` runs everything, but `npm run test:core` (etc.) can target
 * a single package while you're working on it.
 *
 * Each package is registered here so the full suite and focused package
 * scripts use the same test configuration.
 */
export default {
  projects: [
    {
      displayName: "core",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/core/test/**/*.test.js"]
    },
    {
      displayName: "validators",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/validators/test/**/*.test.js"]
    },
    {
      displayName: "scanners",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/scanners/test/**/*.test.js"]
    },
    {
      displayName: "cdr",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/cdr/test/**/*.test.js"]
    },
    {
      displayName: "quarantine",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/quarantine/test/**/*.test.js"]
    },
    {
      displayName: "sandbox",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/sandbox/test/**/*.test.js"]
    },
    {
      displayName: "risk-engine",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/risk-engine/test/**/*.test.js"]
    },
    {
      displayName: "ai",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/ai/test/**/*.test.js"]
    },
    {
      displayName: "service",
      testEnvironment: "node",
      transform: {},
      testMatch: ["<rootDir>/packages/service/test/**/*.test.js"]
    }
  ]
};
