/**
 * Root Jest config. Each package is registered as its own "project" so
 * `npm test` runs everything, but `npm run test:core` (etc.) can target
 * a single package while you're working on it.
 *
 * As new packages (scanners, cdr, quarantine, service) are added, add
 * a matching entry here.
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
    }
  ]
};
