// tests/setup-verification.test.js - Fixed version
describe("Allure Setup Verification", () => {
  beforeAll(() => {
    if (global.allure) {
      global.allure.epic("Setup Verification");
    }
  });

  test("should have allure global object with all methods", () => {
    expect(global.allure).toBeDefined();
    expect(typeof global.attachAllureLog).toBe("function");
    expect(typeof global.attachJSON).toBe("function");
    expect(typeof global.allureStep).toBe("function");

    // Check allure methods
    expect(typeof global.allure.epic).toBe("function");
    expect(typeof global.allure.feature).toBe("function");
    expect(typeof global.allure.story).toBe("function");
    expect(typeof global.allure.severity).toBe("function");
    expect(typeof global.allure.addLabel).toBe("function");
    expect(typeof global.allure.setDescription).toBe("function");
  });

  test("should attach test data to allure", async () => {
    await global.allureStep("Test data attachment", async () => {
      const testData = {
        message: "Allure setup is working perfectly!",
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

    await global.allureStep("Third step with assertion", async () => {
      const data = { value: 42 };
      global.attachJSON("Step Data", data);
      expect(data.value).toBe(42);
    });
  });
});
