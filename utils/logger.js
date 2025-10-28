// utils/logger.js - Fixed version without jest-allure dependency
class Logger {
  static info(message) {
    console.log(`[INFO] ${new Date().toISOString()} - ${message}`);
    if (global.attachAllureLog) {
      global.attachAllureLog("INFO", message);
    }
  }

  static error(message) {
    console.error(`[ERROR] ${new Date().toISOString()} - ${message}`);
    if (global.attachAllureLog) {
      global.attachAllureLog("ERROR", message);
    }
  }

  static warn(message) {
    console.warn(`[WARN] ${new Date().toISOString()} - ${message}`);
    if (global.attachAllureLog) {
      global.attachAllureLog("WARN", message);
    }
  }

  static debug(message) {
    if (process.env.DEBUG) {
      console.log(`[DEBUG] ${new Date().toISOString()} - ${message}`);
      if (global.attachAllureLog) {
        global.attachAllureLog("DEBUG", message);
      }
    }
  }

  static apiCall(method, url, status, duration) {
    const logMessage = `${method} ${url} - ${status} (${duration}ms)`;
    this.info(logMessage);

    if (global.attachAllureLog) {
      global.attachAllureLog("API Call", {
        method,
        url,
        status,
        duration: `${duration}ms`,
        timestamp: new Date().toISOString(),
      });
    }
  }
}

module.exports = Logger;
