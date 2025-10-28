export default {
  testEnvironment: "node",
  setupFilesAfterEnv: ["./jest.setup.js"],
  testTimeout: 30000,
  transform: {},
  extensionsToTreatAsEsm: [".js"],
  moduleNameMapping: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  testMatch: ["**/tests/**/*.test.js"],
};
