// utils/logger.js - Portable Logger Utility

class Logger {
  /**
   * Centralized function to format the log message with timestamp and level.
   * @param {string} level - The log level (e.g., INFO, DEBUG, ERROR).
   * @param {string} message - The content of the log message.
   * @returns {string} The formatted log string.
   */
  static _formatMessage(level, message) {
    const timestamp = new Date().toISOString();
    return `[${level}] ${timestamp} - ${message}`;
  }

  /**
   * Logs general informational messages.
   * @param {string} message
   */
  static info(message) {
    const formattedMessage = Logger._formatMessage("INFO", `✅ ${message}`);
    console.log(formattedMessage);
  }

  /**
   * Logs detailed, internal information, typically for troubleshooting.
   * @param {string} message
   */
  static debug(message) {
    const formattedMessage = Logger._formatMessage("DEBUG", `🔍 ${message}`);
    // Use console.log for debug to ensure it's always output unless configured otherwise
    console.log(formattedMessage);
  }

  /**
   * Logs messages that indicate a potential problem or non-fatal issue.
   * @param {string} message
   */
  static warn(message) {
    const formattedMessage = Logger._formatMessage("WARN", `⚠️ ${message}`);
    console.warn(formattedMessage);
  }

  /**
   * Logs messages for expected but failed operations or standard errors.
   * @param {string} message
   */
  static error(message) {
    const formattedMessage = Logger._formatMessage("ERROR", `❌ ${message}`);
    console.error(formattedMessage);
  }

  /**
   * Logs a critical, unrecoverable error that likely requires immediate attention/exit.
   * @param {string} message
   */
  static fatal(message) {
    const formattedMessage = Logger._formatMessage("FATAL", `🔥 ${message}`);
    console.error(formattedMessage);
    // Optional: In a real system, you might trigger an email alert or process exit here.
  }
}

module.exports = Logger;
