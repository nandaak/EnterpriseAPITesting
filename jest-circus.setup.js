// jest-circus.setup.js - Custom setup for jest-circus with allure
const NodeEnvironment = require("jest-environment-node").TestEnvironment;
const allure = require("jest-allure");

// Custom test environment to handle allure with jest-circus
class AllureNodeEnvironment extends NodeEnvironment {
  async setup() {
    await super.setup();
    this.global.allure = allure;

    // Setup global helper functions
    this.global.attachAllureLog = (name, content) => {
      if (typeof content === "object") {
        content = JSON.stringify(content, null, 2);
      }
      allure.createAttachment(name, () => content, "text/plain")();
    };

    this.global.attachJSON = (name, jsonData) => {
      allure.createAttachment(
        name,
        () => JSON.stringify(jsonData, null, 2),
        "application/json"
      )();
    };
  }
}

module.exports = AllureNodeEnvironment;
