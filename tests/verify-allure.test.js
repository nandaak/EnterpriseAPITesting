// tests/verify-allure.test.js - Test to verify Allure setup
describe("Allure Setup Verification", () => {
  beforeAll(() => {
    if (global.allure) {
      global.allure.addLabel("epic", "Setup Verification");
    }
  });

  test("should have allure global object", () => {
    expect(global.allure).toBeDefined();
    expect(typeof global.attachAllureLog).toBe("function");
    expect(typeof global.attachJSON).toBe("function");
    expect(typeof global.allureStep).toBe("function");
  });

  test("should attach test data to allure", async () => {
    await global.allureStep("Test data attachment", async () => {
      const testData = {
        message: "Allure setup is working!",
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || "development",
      };

      global.attachAllureLog("Verification Data", testData);
      global.attachJSON("Test Payload", testData);

      expect(true).toBe(true);
    });
  });

  test("should handle test steps correctly", async () => {
    await global.allureStep("First step", async () => {
      global.attachAllureLog("Step 1", "Executing first step");
      await new Promise((resolve) => setTimeout(resolve, 100));
    });

    await global.allureStep("Second step", async () => {
      global.attachAllureLog("Step 2", "Executing second step");
      expect(1 + 1).toBe(2);
    });
  });
});
