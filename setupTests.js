// setupTests.js - Custom Jest matchers
expect.extend({
  toBeOneOf(received, expected) {
    const pass = expected.includes(received);
    if (pass) {
      return {
        message: () =>
          `expected ${received} not to be one of [${expected.join(", ")}]`,
        pass: true,
      };
    } else {
      return {
        message: () =>
          `expected ${received} to be one of [${expected.join(", ")}]`,
        pass: false,
      };
    }
  },

  toHaveValidContent(received) {
    const hasContent =
      received &&
      (typeof received === "object"
        ? Object.keys(received).length > 0
        : typeof received === "string"
        ? received.trim().length > 0
        : received !== null && received !== undefined);

    if (hasContent) {
      return {
        message: () =>
          `expected response to have no content, but content was present`,
        pass: true,
      };
    } else {
      return {
        message: () =>
          `expected response to have valid content, but found: ${received}`,
        pass: false,
      };
    }
  },
});
