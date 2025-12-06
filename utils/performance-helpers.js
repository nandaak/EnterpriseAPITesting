// utils/performance-helpers.js
const apiClient = require("./api-client");
const logger = require("./logger");
const Constants = require("../Constants");

const { TEST_CONFIG } = Constants;

// --- 1. MALICIOUS PAYLOAD GENERATOR ---

/**
 * Generates a payload intended to stress or maliciously test an API endpoint.
 * This function cycles through different payload types/sizes to simulate varied malicious input.
 *
 * @param {string} moduleName - The name of the module being tested.
 * @param {number} requestIndex - The index of the current request (used for variance).
 * @returns {object} A payload object containing stressful or malicious data.
 */
function generateMaliciousPayload(moduleName, requestIndex) {
  const attackVectors = [
    // 0: Deeply nested object payload (DoS vector)
    () => {
      const createNestedObject = (depth) => {
        if (depth === 0) return { val: "leaf" };
        return {
          module: moduleName,
          index: requestIndex,
          next: createNestedObject(depth - 1),
        };
      };
      return createNestedObject(15); // 15 levels deep
    },
    // 1: Large array payload (Memory consumption vector)
    () => ({
      module: moduleName,
      data: Array(2000).fill("A".repeat(100)), // 200KB of data
    }),
    // 2: SQL Injection/XSS combined payload (Security stress vector)
    () => ({
      module: moduleName,
      id: `' OR '1'='1' --`,
      name: `<script>alert('XSS_ATTACK_${requestIndex}')</script>`,
    }),
    // 3: Extremely long string payload (Input validation stress)
    () => ({
      module: moduleName,
      data: "A".repeat(1024 * 5), // 5KB single string
    }),
  ];

  // Cycle through the attack vectors based on the request index
  const vectorIndex = requestIndex % attackVectors.length;
  return attackVectors[vectorIndex]();
}

// --- 2. PERFORMANCE TEST EXECUTION ---

/**
 * Executes a load test against a module's POST endpoint using malicious payloads.
 *
 * @param {object} moduleConfig - The configuration object for the module (must contain a 'Post' array).
 * @param {string} fullModuleName - The dot-separated name of the module.
 * @returns {Promise<object>} An object containing the test results, metrics, and status.
 */
async function testPerformanceUnderMaliciousLoad(moduleConfig, fullModuleName) {
  const defaultPostUrl = moduleConfig.CREATE?.[0];

  if (!defaultPostUrl) {
    return {
      status: "skipped",
      metrics: {},
      details: "No POST endpoint found to perform load test.",
    };
  }

  const maxConcurrentRequests = TEST_CONFIG.MALICIOUS_LOAD.CONCURRENCY || 10;
  const totalRequests = TEST_CONFIG.MALICIOUS_LOAD.TOTAL_REQUESTS || 100;
  const requestPromises = [];

  let successfulRequests = 0;
  let failedRequests = 0;
  const responseTimes = [];
  const startTime = Date.now();

  const executeRequest = async (i) => {
    // Generate a payload that cycles through different attack vectors
    const payload = generateMaliciousPayload(
      fullModuleName,
      i // use request index to generate varied payload
    );

    const requestStart = Date.now();
    try {
      // Using POST endpoint with malicious payload
      const response = await apiClient.post(defaultPostUrl, payload, {
        validateStatus: (status) => status < 500, // Treat 4xx errors (expected under malicious load) as non-network failures
      });

      const duration = Date.now() - requestStart;
      responseTimes.push(duration);

      if (response.status >= 200 && response.status < 400) {
        // Unexpected success under malicious load is still a functional success for this test
        successfulRequests++;
      } else if (response.status >= 400 && response.status < 500) {
        // Expected failure (e.g., 400 Bad Request, 401 Auth) under malicious load
        successfulRequests++; // Count as functional success if system handled the bad input gracefully
      } else {
        // Actual failure (e.g., 5xx Server Error)
        failedRequests++;
      }
    } catch (error) {
      const duration = Date.now() - requestStart;
      responseTimes.push(duration);
      failedRequests++;
      // logger.error(`Request ${i} failed for ${fullModuleName}: ${error.message}`);
    }
  };

  // Execute concurrent requests in batches
  for (let i = 0; i < totalRequests; i += maxConcurrentRequests) {
    const batch = [];
    for (let j = 0; j < maxConcurrentRequests && i + j < totalRequests; j++) {
      batch.push(executeRequest(i + j));
    }
    await Promise.all(batch);
  }

  const endTime = Date.now();
  const totalDuration = endTime - startTime;

  // Check for response times before calculating metrics
  if (responseTimes.length === 0) {
    return {
      status: "failed",
      metrics: { totalRequests, successfulRequests, failedRequests },
      details: "All requests failed, no response times recorded.",
    };
  }

  // Performance Metrics Calculation
  responseTimes.sort((a, b) => a - b);
  const totalResponseTime = responseTimes.reduce((a, b) => a + b, 0);

  const metrics = {
    totalRequests: totalRequests,
    successfulRequests: successfulRequests,
    failedRequests: failedRequests,
    averageResponseTime: totalResponseTime / responseTimes.length,
    throughput: totalRequests / (totalDuration / 1000), // requests per second
    p95ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.95)],
    successRate: (successfulRequests / totalRequests) * 100,
    totalDuration: totalDuration,
  };

  const overallStatus = failedRequests === totalRequests ? "failed" : "passed";

  return {
    status: overallStatus,
    metrics: metrics,
  };
}

// --- 3. EXPORTS ---

module.exports = {
  testPerformanceUnderMaliciousLoad,
  generateMaliciousPayload, // <-- FIX: Exporting the defined function
};
