class TestDataGenerator {
  static getModuleTestData(moduleName) {
    const testDataTemplates = {
      // General Settings
      Discount_Policy: {
        getPostData: () => ({
          name: `TestDiscount-${Date.now()}`,
          nameAr: `اختبار-${Date.now()}`,
          discountPercentage: "15",
          userIds: [],
        }),
        getEditData: (originalData) => ({
          ...originalData,
          name: `UpdatedDiscount-${Date.now()}`,
          discountPercentage: "20",
        }),
      },

      Financial_Calendar: {
        getPostData: () => ({
          name: `TestCalendar-${Date.now()}`,
          code: `CAL-${Date.now()}`,
          fromDate: "2025-01-01",
          toDate: "2025-12-31",
          noOfExtraPeriods: 0,
        }),
        getEditData: (originalData) => ({
          ...originalData,
          name: `UpdatedCalendar-${Date.now()}`,
          code: `UPD-CAL-${Date.now()}`,
        }),
      },

      // Finance
      Treasury_Definition: {
        getPostData: () => ({
          name: `TestTreasury-${Date.now()}`,
          nameAr: `خزنة-اختبار-${Date.now()}`,
          currencyId: 4,
          branches: [],
          accountId: 1376,
          accountOpeningBalance: 100000,
        }),
        getEditData: (originalData) => ({
          ...originalData,
          name: `UpdatedTreasury-${Date.now()}`,
          accountOpeningBalance: 150000,
        }),
      },

      Bank_Definition: {
        getPostData: () => ({
          name: `TestBank-${Date.now()}`,
          nameAr: `بنك-اختبار-${Date.now()}`,
          bankAccounts: [
            {
              accountNumber: `ACC-${Date.now()}`,
              glAccountId: 1376,
              currencyId: 4,
              openingBalance: 50000,
            },
          ],
        }),
        getEditData: (originalData) => ({
          ...originalData,
          name: `UpdatedBank-${Date.now()}`,
          bankAccounts: originalData.bankAccounts.map((acc) => ({
            ...acc,
            openingBalance: 75000,
          })),
        }),
      },

      // Sales
      Customer_Definition: {
        getPostData: () => ({
          name: `TestCustomer-${Date.now()}`,
          nameAr: `عميل-اختبار-${Date.now()}`,
          categoryId: 1,
          contactInfo: {
            contactEmail: `test${Date.now()}@example.com`,
          },
          financialInfo: {
            paymentTermId: 1,
            currencyId: 3,
          },
        }),
        getEditData: (originalData) => ({
          ...originalData,
          name: `UpdatedCustomer-${Date.now()}`,
          contactInfo: {
            ...originalData.contactInfo,
            contactEmail: `updated${Date.now()}@example.com`,
          },
        }),
      },
      // Default template for any module
      default: {
        getPostData: () => ({
          name: `Test-${Date.now()}`,
          nameAr: `اختبار-${Date.now()}`,
          code: `TEST-${Date.now()}`,
        }),
        getEditData: (originalData) => ({
          ...originalData,
          name: `Updated-${Date.now()}`,
          code: `UPD-${Date.now()}`,
        }),
        getCommitData: (createdData) => ({
          id: createdData.id,
          status: "Posted",
        }),
        getMaliciousWrongTypes: () => ({
          name: 12345, // Should be string
          nameAr: true, // Should be string
          discountPercentage: "not_a_number", // Should be number
          quantity: "invalid", // Should be number
          date: "invalid_date", // Should be valid date
          isActive: "not_boolean", // Should be boolean
          amount: [], // Should be number
          percentage: {}, // Should be number
        }),
        getMaliciousInvalidValues: () => ({
          name: "A".repeat(1000), // Too long
          nameAr: "B".repeat(1000), // Too long
          discountPercentage: -50, // Negative value
          quantity: -100, // Negative quantity
          amount: 0, // Zero amount
          fromDate: "2025-13-45", // Invalid date
          toDate: "2020-01-01", // Past date
          nonExistentId: 999999, // Non-existent master data
          invalidEnum: "INVALID_ENUM_VALUE", // Invalid enum
          currencyId: -1, // Invalid ID
          accountId: 0, // Zero ID
        }),
        getNullRequiredFields: () => ({
          name: null,
          nameAr: null,
          code: null,
          description: null,
          amount: null,
          quantity: null,
          date: null,
        }),
      },
    };

    return testDataTemplates[moduleName] || testDataTemplates.default;
  }

  static generateMaliciousPayloads() {
    return {
      sqlInjection: {
        name: "test'; DROP TABLE users; --",
        description: "test' OR '1'='1",
      },
      xssPayload: {
        name: "<script>alert('XSS')</script>",
        description: "<img src=x onerror=alert('XSS')>",
      },
      bufferOverflow: {
        name: "A".repeat(10000),
        description: "B".repeat(10000),
      },
      pathTraversal: {
        name: "../../etc/passwd",
        filePath: ".../.../.../windows/system32/config",
      },
      commandInjection: {
        name: "test; rm -rf /",
        command: "| cat /etc/passwd",
      },
    };
  }

  static getInvalidTokens() {
    return {
      noToken: null,
      wrongToken: "Bearer invalid_token_12345",
      expiredToken:
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      malformedToken: "InvalidTokenFormat",
      emptyToken: "Bearer ",
      wrongFormat: "Basic dGVzdDp0ZXN0",
    };
  }
}

module.exports = TestDataGenerator;
