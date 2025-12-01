/**
 * Failure Response Logger
 * Captures and logs failed API responses (400, 404, 500) to failure_response.json
 */

const fs = require('fs');
const path = require('path');

class FailureResponseLogger {
  constructor(outputPath = 'failure_response.json') {
    this.outputPath = outputPath;
    this.failures = this.loadExisting();
  }

  /**
   * Load existing failures if file exists
   */
  loadExisting() {
    try {
      if (fs.existsSync(this.outputPath)) {
        return JSON.parse(fs.readFileSync(this.outputPath, 'utf8'));
      }
    } catch (error) {
      console.warn(`Could not load existing failures: ${error.message}`);
    }
    return {};
  }

  /**
   * Log a failed API response
   * @param {string} method - HTTP method (GET, POST, PUT, DELETE)
   * @param {string} url - API endpoint URL
   * @param {number} statusCode - HTTP status code
   * @param {object} responseData - Response data from API
   * @param {object} requestPayload - Request payload sent (optional)
   */
  logFailure(method, url, statusCode, responseData, requestPayload = null) {
    // Only log 400, 404, and 500 errors
    if (statusCode !== 400 && statusCode !== 404 && statusCode !== 500) {
      return;
    }

    // Create key: METHOD URL
    const key = `${method} ${url}`;

    // Create failure entry
    const failureEntry = {
      method,
      url,
      statusCode,
      timestamp: new Date().toISOString(),
      response: responseData,
      requestPayload: requestPayload
    };

    // Store in failures object
    this.failures[key] = failureEntry;

    // Save immediately
    this.save();
  }

  /**
   * Save failures to file
   */
  save() {
    try {
      fs.writeFileSync(
        this.outputPath,
        JSON.stringify(this.failures, null, 2),
        'utf8'
      );
    } catch (error) {
      console.error(`Failed to save failure responses: ${error.message}`);
    }
  }

  /**
   * Get all failures
   */
  getAll() {
    return this.failures;
  }

  /**
   * Get failures by status code
   */
  getByStatus(statusCode) {
    return Object.entries(this.failures)
      .filter(([_, failure]) => failure.statusCode === statusCode)
      .reduce((acc, [key, value]) => {
        acc[key] = value;
        return acc;
      }, {});
  }

  /**
   * Get statistics
   */
  getStats() {
    const entries = Object.values(this.failures);
    return {
      total: entries.length,
      status400: entries.filter(f => f.statusCode === 400).length,
      status404: entries.filter(f => f.statusCode === 404).length,
      status500: entries.filter(f => f.statusCode === 500).length,
      uniqueUrls: new Set(entries.map(f => f.url)).size,
      uniqueMethods: new Set(entries.map(f => f.method)).size
    };
  }

  /**
   * Clear all failures
   */
  clear() {
    this.failures = {};
    this.save();
  }

  /**
   * Generate summary report
   */
  generateReport() {
    const stats = this.getStats();
    const report = {
      timestamp: new Date().toISOString(),
      statistics: stats,
      failures: this.failures
    };

    const reportPath = 'failure_response_report.json';
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');

    return {
      reportPath,
      stats
    };
  }
}

// Singleton instance
let instance = null;

/**
 * Get singleton instance
 */
function getFailureLogger() {
  if (!instance) {
    instance = new FailureResponseLogger();
  }
  return instance;
}

module.exports = {
  FailureResponseLogger,
  getFailureLogger
};
