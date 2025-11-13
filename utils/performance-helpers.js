/**
 * @fileoverview Test Helpers for Performance Under Malicious Load Testing.
 * This module exports functions to execute load tests using malicious payloads
 * to assess system performance and resilience.
 */

const apiClient = require("./api-client");
const logger = require("./logger");
const { HTTP_STATUS_CODES } = require("../Constants");
const { generateMaliciousPayload } = require("./security-helpers");
// Assuming security-helpers provides functions for test tokens and malicious data
const { getLowPrivilegeToken } = require("./security-helpers");

// --- Configuration ---
const CONCURRENCY_LEVEL = 10; // Number of concurrent requests
const DURATION_SECONDS = 10; // Duration of the load test
const TOTAL_REQUESTS = CONCURRENCY_LEVEL * 10 * DURATION_SECONDS; // Target request count (approx 10 req/s per user)
const REQUEST_DELAY_MS = 1000 / 10; // 100ms delay for 10 requests per second rate

/**
 * @typedef {Object} PerformanceMetrics
 * @property {number} totalRequests - Total requests sent.
 * @property {number} successfulRequests - Requests with 2xx status.
 * @property {number} failedRequests - Requests with 4xx/5xx status or network errors.
 * @property {number} errorRate - Percentage of failed requests.
 * @property {number} throughput - Requests per second (req/sec).
 * @property {number} averageResponseTime - Average response time in ms.
 * @property {number} p95ResponseTime - 95th percentile response time in ms.
 */

/**
 * Executes a load test against a module's POST endpoint using malicious payloads.
 * Assesses performance and resilience under simulated attack.
 *
 * @param {object} moduleConfig The configuration for the current module.
 * @param {string} fullModuleName The full path name of the module being tested.
 * @returns {Promise<{metrics: PerformanceMetrics, details: string}>} The performance test results.
 */
const testPerformanceUnderMaliciousLoad = async (
  moduleConfig,
  fullModuleName
) => {
  logger.debug(`[PERF-LOAD] Starting load test on ${fullModuleName}...`);

  // 1. Get Target Endpoint (POST is mandatory for this test)
  const endpoint =
    moduleConfig.Post &&
    Array.isArray(moduleConfig.Post) &&
    moduleConfig.Post[0];

  if (!endpoint || endpoint === "URL_HERE") {
    return {
      metrics: {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        errorRate: 0,
        throughput: 0,
        averageResponseTime: 0,
        p95ResponseTime: 0,
      },
      details: `Skipped: No valid POST endpoint found for ${fullModuleName}.`,
    };
  }

  // 2. Setup Test Environment
  const userToken = await getLowPrivilegeToken();
  const headers = { Authorization: `Bearer ${userToken}` };
  const responseTimes = [];
  let successfulRequests = 0;
  let failedRequests = 0;

  const startTime = Date.now();
  logger.info(
    `[PERF-LOAD] Targeting ${endpoint} with ${CONCURRENCY_LEVEL} concurrent users for ${DURATION_SECONDS}s.`
  );

  // 3. Define the Request Execution Logic
  const executeRequest = async (i) => {
    const payload = generateMaliciousPayload(
      fullModuleName,
      "performance_test"
    );
    const requestStart = Date.now();

    try {
      // Use the POST method
      const response = await apiClient.post(endpoint, payload, { headers });
      const responseTime = Date.now() - requestStart;
      responseTimes.push(responseTime);

      // A 4xx (Client Error) for a malicious payload is often a SUCCESSFUL security response.
      // For PERFORMANCE, we only count 2xx as SUCCESSFUL for throughput/RT purposes.
      if (response.status >= 200 && response.status < 300) {
        successfulRequests++;
      } else {
        failedRequests++;
      }
    } catch (error) {
      const responseTime = Date.now() - requestStart;
      responseTimes.push(responseTime);

      // If the API correctly rejects a malicious request (e.g., 400, 403)
      if (
        error.response &&
        error.response.status >= 400 &&
        error.response.status < 500
      ) {
        // Count as a failure for standard performance metric, but successful for security.
        failedRequests++;
      } else {
        // 5xx or Network errors (system failure)
        failedRequests++;
      }
    }
  };

  // 4. Run the Concurrent Load Test using promises/timeout
  const loadTestLoop = async () => {
    const totalRequests = Math.min(TOTAL_REQUESTS, 1000); // Capping max requests for a practical Jest test
    const requests = [];

    for (let i = 0; i < totalRequests; i++) {
      // Initiate concurrent requests
      requests.push(executeRequest(i));

      // Introduce a small delay to control the flow and prevent network saturation errors
      await new Promise((resolve) => setTimeout(resolve, REQUEST_DELAY_MS));
    }

    await Promise.allSettled(requests);
  };

  await loadTestLoop();
  const endTime = Date.now();
  const duration = endTime - startTime;
  const totalRequests = successfulRequests + failedRequests;

  // 5. Calculate Metrics
  const { averageResponseTime, p95ResponseTime } =
    calculatePerformanceStatistics(responseTimes);

  const metrics = {
    totalRequests,
    successfulRequests,
    failedRequests,
    errorRate: totalRequests > 0 ? (failedRequests / totalRequests) * 100 : 0,
    throughput: duration > 0 ? (totalRequests / duration) * 1000 : 0, // req/sec
    averageResponseTime,
    p95ResponseTime,
  };

  logger.debug(
    `[PERF-LOAD] Finished. Total time: ${duration}ms. Req/s: ${metrics.throughput.toFixed(
      2
    )}`
  );

  return {
    metrics,
    details: `Performance test completed. Total requests: ${
      metrics.totalRequests
    }, Success Rate: ${(
      (metrics.successfulRequests / metrics.totalRequests) *
      100
    ).toFixed(2)}%.`,
  };
};

// =========================================================================
// PERFORMANCE CALCULATION HELPERS
// =========================================================================

/**
 * Calculates average and percentile response times.
 * @param {number[]} responseTimes - Array of response times in milliseconds.
 * @returns {{averageResponseTime: number, p95ResponseTime: number}}
 */
function calculatePerformanceStatistics(responseTimes) {
  if (responseTimes.length === 0) {
    return { averageResponseTime: 0, p95ResponseTime: 0 };
  }

  // Average
  const sum = responseTimes.reduce((a, b) => a + b, 0);
  const averageResponseTime = sum / responseTimes.length;

  // P95 (95th Percentile)
  const sortedTimes = [...responseTimes].sort((a, b) => a - b);
  const p95Index = Math.floor(sortedTimes.length * 0.95);
  // Use the index, or the last element if the index is out of bounds
  const p95ResponseTime =
    sortedTimes[Math.min(p95Index, sortedTimes.length - 1)];

  return {
    averageResponseTime: parseFloat(averageResponseTime.toFixed(2)),
    p95ResponseTime: parseFloat(p95ResponseTime.toFixed(2)),
  };
}

// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
  testPerformanceUnderMaliciousLoad,
};
