// utils/safe-logger.js - Completely safe logger without circular dependencies
class SafeLogger {
  static info(message) {
    const timestamp = new Date().toISOString();
    console.log(`[INFO] ${timestamp} - ${message}`);
    // NO allure attachment to prevent recursion
  }

  static debug(message) {
    const timestamp = new Date().toISOString();
    console.log(`[DEBUG] ${timestamp} - ${message}`);
    // NO allure attachment to prevent recursion
  }

  static warn(message) {
    const timestamp = new Date().toISOString();
    console.warn(`[WARN] ${timestamp} - ${message}`);
    // NO allure attachment to prevent recursion
  }

  static error(message) {
    const timestamp = new Date().toISOString();
    console.error(`[ERROR] ${timestamp} - ${message}`);
    // NO allure attachment to prevent recursion
  }
}

module.exports = SafeLogger;
