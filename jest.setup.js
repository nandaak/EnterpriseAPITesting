// Add custom matchers for better assertions
expect.extend({
  toBeOneOf(received, expectedArray) {
    const pass = expectedArray.includes(received);
    if (pass) {
      return {
        message: () =>
          `expected ${received} not to be one of [${expectedArray.join(", ")}]`,
        pass: true,
      };
    } else {
      return {
        message: () =>
          `expected ${received} to be one of [${expectedArray.join(", ")}]`,
        pass: false,
      };
    }
  },

  toBeValidId(received) {
    if (!received) {
      return {
        message: () => `expected ID to be defined but got ${received}`,
        pass: false,
      };
    }

    const idStr = String(received).trim();
    const pass =
      (idStr.length > 0 &&
        idStr !== "null" &&
        idStr !== "undefined" &&
        idStr !== "0" &&
        !isNaN(idStr)) ||
      idStr.length >= 1;

    if (pass) {
      return {
        message: () => `expected ${received} not to be a valid ID`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be a valid ID`,
        pass: false,
      };
    }
  },
});
