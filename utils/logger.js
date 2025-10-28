// utils/logger.js - Fixed to avoid circular dependencies
class Logger {
  static info(message) {
    console.log(`[INFO] ${new Date().toISOString()} - ${message}`);
    // SAFE: Only call attachAllureLog if it exists AND is not the logger itself
    if (global.attachAllureLog && !message.includes("[INFO]")) {
      try {
        global.attachAllureLog("INFO", message);
      } catch (error) {
        // Safely ignore errors to prevent infinite recursion
        console.log(`[LOGGER] Safe fallback: ${message}`);
      }
    }
  }

  static debug(message) {
    console.log(`[DEBUG] ${new Date().toISOString()} - ${message}`);
    // SAFE: Only call attachAllureLog if it exists AND is not the logger itself
    if (global.attachAllureLog && !message.includes("[DEBUG]")) {
      try {
        global.attachAllureLog("DEBUG", message);
      } catch (error) {
        // Safely ignore errors to prevent infinite recursion
        console.log(`[LOGGER] Safe fallback: ${message}`);
      }
    }
  }

  static warn(message) {
    console.warn(`[WARN] ${new Date().toISOString()} - ${message}`);
    // SAFE: Only call attachAllureLog if it exists AND is not the logger itself
    if (global.attachAllureLog && !message.includes("[WARN]")) {
      try {
        global.attachAllureLog("WARN", message);
      } catch (error) {
        // Safely ignore errors to prevent infinite recursion
        console.warn(`[LOGGER] Safe fallback: ${message}`);
      }
    }
  }

  static error(message) {
    console.error(`[ERROR] ${new Date().toISOString()} - ${message}`);
    // SAFE: Only call attachAllureLog if it exists AND is not the logger itself
    if (global.attachAllureLog && !message.includes("[ERROR]")) {
      try {
        global.attachAllureLog("ERROR", message);
      } catch (error) {
        // Safely ignore errors to prevent infinite recursion
        console.error(`[LOGGER] Safe fallback: ${message}`);
      }
    }
  }

  // Safe method for allure attachment without recursion
  static safeAttach(name, content) {
    if (global.attachAllureLog && !global._isAttaching) {
      global._isAttaching = true;
      try {
        global.attachAllureLog(name, content);
      } catch (error) {
        // Ignore errors safely
      } finally {
        global._isAttaching = false;
      }
    }
  }
}

module.exports = Logger;
