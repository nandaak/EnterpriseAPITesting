// utils/id-type-manager.js
/**
 * Professional ID Type Management System
 * 
 * Handles different ID types intelligently:
 * - UUID/GUID (e.g., "a331f1a1-32cb-4aed-40ab-08de0c2835e1")
 * - Numeric (e.g., 123, "456")
 * - String/Alphanumeric (e.g., "ABC123", "user_001")
 * - Composite (e.g., "ORD-2024-001")
 * 
 * @version 1.0.0
 * @author Professional Enhancement
 */

const logger = require('./logger');

class IDTypeManager {
  /**
   * ID Type Constants
   */
  static ID_TYPES = {
    UUID: 'uuid',
    GUID: 'guid',
    NUMERIC: 'numeric',
    STRING: 'string',
    ALPHANUMERIC: 'alphanumeric',
    COMPOSITE: 'composite',
    UNKNOWN: 'unknown'
  };

  /**
   * ID Format Patterns
   */
  static PATTERNS = {
    // UUID v4: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    UUID_V4: /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    
    // Generic UUID/GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    UUID_GENERIC: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    
    // Numeric: 123, 456789
    NUMERIC: /^\d+$/,
    
    // Alphanumeric: ABC123, user_001
    ALPHANUMERIC: /^[a-z0-9_-]+$/i,
    
    // Composite: ORD-2024-001, INV_2024_123
    COMPOSITE: /^[a-z]+[-_]\d+[-_][a-z0-9]+$/i
  };

  /**
   * Detect ID type from value
   * 
   * @param {*} id - The ID value to analyze
   * @returns {Object} - { type, format, isValid, metadata }
   */
  static detectIDType(id) {
    if (!id) {
      return {
        type: this.ID_TYPES.UNKNOWN,
        format: null,
        isValid: false,
        metadata: { reason: 'ID is null or undefined' }
      };
    }

    const idStr = String(id).trim();

    // Check for empty or invalid values
    if (idStr.length === 0) {
      return {
        type: this.ID_TYPES.UNKNOWN,
        format: null,
        isValid: false,
        metadata: { reason: 'ID is empty string' }
      };
    }

    // Check for null UUID
    if (idStr === '00000000-0000-0000-0000-000000000000') {
      return {
        type: this.ID_TYPES.UUID,
        format: 'null-uuid',
        isValid: false,
        metadata: { reason: 'Null UUID detected' }
      };
    }

    // UUID v4 Detection
    if (this.PATTERNS.UUID_V4.test(idStr)) {
      return {
        type: this.ID_TYPES.UUID,
        format: 'uuid-v4',
        isValid: true,
        metadata: {
          length: idStr.length,
          version: 4,
          variant: this.getUUIDVariant(idStr)
        }
      };
    }

    // Generic UUID/GUID Detection
    if (this.PATTERNS.UUID_GENERIC.test(idStr)) {
      return {
        type: this.ID_TYPES.GUID,
        format: 'guid-generic',
        isValid: true,
        metadata: {
          length: idStr.length,
          version: this.getUUIDVersion(idStr),
          variant: this.getUUIDVariant(idStr)
        }
      };
    }

    // Numeric Detection
    if (this.PATTERNS.NUMERIC.test(idStr)) {
      const numValue = parseInt(idStr, 10);
      return {
        type: this.ID_TYPES.NUMERIC,
        format: 'integer',
        isValid: numValue > 0,
        metadata: {
          value: numValue,
          length: idStr.length,
          isPositive: numValue > 0
        }
      };
    }

    // Composite Detection
    if (this.PATTERNS.COMPOSITE.test(idStr)) {
      return {
        type: this.ID_TYPES.COMPOSITE,
        format: 'composite',
        isValid: true,
        metadata: {
          length: idStr.length,
          pattern: idStr.replace(/\d+/g, 'N').replace(/[a-z]+/gi, 'A')
        }
      };
    }

    // Alphanumeric Detection
    if (this.PATTERNS.ALPHANUMERIC.test(idStr)) {
      return {
        type: this.ID_TYPES.ALPHANUMERIC,
        format: 'alphanumeric',
        isValid: idStr.length >= 1,
        metadata: {
          length: idStr.length,
          hasNumbers: /\d/.test(idStr),
          hasLetters: /[a-z]/i.test(idStr)
        }
      };
    }

    // String (fallback)
    return {
      type: this.ID_TYPES.STRING,
      format: 'string',
      isValid: idStr.length >= 1,
      metadata: {
        length: idStr.length,
        containsSpecialChars: /[^a-z0-9_-]/i.test(idStr)
      }
    };
  }

  /**
   * Get UUID version from string
   */
  static getUUIDVersion(uuidStr) {
    if (!uuidStr || uuidStr.length < 15) return null;
    const versionChar = uuidStr.charAt(14);
    return parseInt(versionChar, 16);
  }

  /**
   * Get UUID variant from string
   */
  static getUUIDVariant(uuidStr) {
    if (!uuidStr || uuidStr.length < 20) return null;
    const variantChar = uuidStr.charAt(19);
    const variantBits = parseInt(variantChar, 16);
    
    if ((variantBits & 0x8) === 0) return 'NCS';
    if ((variantBits & 0xC) === 0x8) return 'RFC4122';
    if ((variantBits & 0xE) === 0xC) return 'Microsoft';
    return 'Reserved';
  }

  /**
   * Validate ID based on its detected type
   * 
   * @param {*} id - The ID to validate
   * @param {string} expectedType - Optional expected type
   * @returns {Object} - Validation result
   */
  static validateID(id, expectedType = null) {
    const detection = this.detectIDType(id);

    if (!detection.isValid) {
      return {
        valid: false,
        type: detection.type,
        reason: detection.metadata.reason || 'Invalid ID format',
        detection
      };
    }

    // If expected type is specified, verify it matches
    if (expectedType && detection.type !== expectedType) {
      return {
        valid: false,
        type: detection.type,
        reason: `Expected ${expectedType} but got ${detection.type}`,
        detection
      };
    }

    return {
      valid: true,
      type: detection.type,
      format: detection.format,
      metadata: detection.metadata,
      detection
    };
  }

  /**
   * Format ID for URL/endpoint usage
   * 
   * @param {*} id - The ID to format
   * @param {string} context - Context: 'url', 'query', 'body'
   * @returns {string} - Formatted ID
   */
  static formatIDForEndpoint(id, context = 'url') {
    if (!id) return '';

    const idStr = String(id).trim();
    const detection = this.detectIDType(idStr);

    switch (context) {
      case 'url':
        // URL path parameter - use as-is
        return idStr;

      case 'query':
        // Query parameter - may need encoding
        return encodeURIComponent(idStr);

      case 'body':
        // Body parameter - preserve type
        if (detection.type === this.ID_TYPES.NUMERIC) {
          return parseInt(idStr, 10);
        }
        return idStr;

      default:
        return idStr;
    }
  }

  /**
   * Replace <createdId> placeholder with actual ID
   * Intelligently handles different contexts
   * 
   * @param {string} template - Template string with <createdId>
   * @param {*} id - The actual ID value
   * @returns {string} - String with ID replaced
   */
  static replacePlaceholder(template, id) {
    if (!template || !id) return template;

    const idStr = String(id).trim();
    const detection = this.detectIDType(idStr);

    logger.debug(`🔄 Replacing <createdId> with ${detection.type}: ${idStr}`);

    // Replace all instances of <createdId>
    return template.replace(/<createdId>/g, idStr);
  }

  /**
   * Replace <createdId> in payload object
   * Handles nested objects and arrays
   * 
   * @param {Object} payload - Payload object
   * @param {*} id - The actual ID value
   * @returns {Object} - Payload with IDs replaced
   */
  static replaceInPayload(payload, id) {
    if (!payload || typeof payload !== 'object') return payload;
    if (!id) return payload;

    const idStr = String(id).trim();
    const detection = this.detectIDType(idStr);
    
    // Determine the appropriate ID value based on type
    let idValue = idStr;
    if (detection.type === this.ID_TYPES.NUMERIC) {
      idValue = parseInt(idStr, 10);
    }

    const processValue = (value) => {
      if (value === '<createdId>') {
        return idValue;
      }
      if (typeof value === 'string' && value.includes('<createdId>')) {
        return value.replace(/<createdId>/g, idStr);
      }
      if (Array.isArray(value)) {
        return value.map(processValue);
      }
      if (typeof value === 'object' && value !== null) {
        return this.replaceInPayload(value, id);
      }
      return value;
    };

    const result = {};
    for (const [key, value] of Object.entries(payload)) {
      result[key] = processValue(value);
    }

    return result;
  }

  /**
   * Extract ID from response with type detection
   * Enhanced version of TestHelpers.extractId
   * 
   * @param {Object} response - API response
   * @returns {Object} - { id, type, detection }
   */
  static extractIDFromResponse(response) {
    if (!response) {
      return { id: null, type: this.ID_TYPES.UNKNOWN, detection: null };
    }

    // Try multiple extraction strategies
    const strategies = [
      // Direct data string
      () => typeof response.data === 'string' ? response.data : null,
      
      // Common ID fields
      () => response.data?.id,
      () => response.data?.Id,
      () => response.data?.ID,
      () => response.data?.uuid,
      () => response.data?.guid,
      () => response.data?.resourceId,
      () => response.data?.entityId,
      
      // Nested result
      () => response.data?.result?.id,
      () => response.data?.response?.id,
      
      // Response level
      () => response.id,
      
      // Location header
      () => {
        const location = response.headers?.location;
        if (location) {
          const match = location.match(/\/([^\/]+)$/);
          return match ? match[1] : null;
        }
        return null;
      }
    ];

    for (const strategy of strategies) {
      try {
        const extractedId = strategy();
        if (extractedId) {
          const detection = this.detectIDType(extractedId);
          if (detection.isValid) {
            logger.info(`✅ Extracted ${detection.type} ID: ${extractedId}`);
            return {
              id: extractedId,
              type: detection.type,
              format: detection.format,
              detection
            };
          }
        }
      } catch (error) {
        continue;
      }
    }

    logger.error('❌ Failed to extract valid ID from response');
    return { id: null, type: this.ID_TYPES.UNKNOWN, detection: null };
  }

  /**
   * Generate test ID for specific type
   * Useful for testing
   * 
   * @param {string} type - ID type to generate
   * @returns {string} - Generated test ID
   */
  static generateTestID(type = this.ID_TYPES.UUID) {
    switch (type) {
      case this.ID_TYPES.UUID:
      case this.ID_TYPES.GUID:
        return this.generateUUID();

      case this.ID_TYPES.NUMERIC:
        return Math.floor(Math.random() * 1000000) + 1;

      case this.ID_TYPES.ALPHANUMERIC:
        return 'TEST_' + Math.random().toString(36).substring(2, 10).toUpperCase();

      case this.ID_TYPES.COMPOSITE:
        return `ORD-${new Date().getFullYear()}-${String(Math.floor(Math.random() * 1000)).padStart(3, '0')}`;

      default:
        return 'test_' + Date.now();
    }
  }

  /**
   * Generate UUID v4
   */
  static generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Compare two IDs (handles different types)
   * 
   * @param {*} id1 - First ID
   * @param {*} id2 - Second ID
   * @returns {boolean} - True if IDs match
   */
  static compareIDs(id1, id2) {
    if (!id1 || !id2) return false;

    const str1 = String(id1).trim().toLowerCase();
    const str2 = String(id2).trim().toLowerCase();

    return str1 === str2;
  }

  /**
   * Get ID type statistics from array of IDs
   * Useful for analyzing API responses
   * 
   * @param {Array} ids - Array of IDs
   * @returns {Object} - Statistics
   */
  static analyzeIDTypes(ids) {
    if (!Array.isArray(ids) || ids.length === 0) {
      return { total: 0, types: {}, formats: {} };
    }

    const stats = {
      total: ids.length,
      types: {},
      formats: {},
      valid: 0,
      invalid: 0
    };

    ids.forEach(id => {
      const detection = this.detectIDType(id);
      
      // Count by type
      stats.types[detection.type] = (stats.types[detection.type] || 0) + 1;
      
      // Count by format
      if (detection.format) {
        stats.formats[detection.format] = (stats.formats[detection.format] || 0) + 1;
      }
      
      // Count valid/invalid
      if (detection.isValid) {
        stats.valid++;
      } else {
        stats.invalid++;
      }
    });

    return stats;
  }

  /**
   * Log ID information for debugging
   * 
   * @param {*} id - ID to log
   * @param {string} context - Context description
   */
  static logIDInfo(id, context = '') {
    const detection = this.detectIDType(id);
    const prefix = context ? `[${context}]` : '';
    
    logger.info(`${prefix} ID Analysis:`);
    logger.info(`  Value: ${id}`);
    logger.info(`  Type: ${detection.type}`);
    logger.info(`  Format: ${detection.format}`);
    logger.info(`  Valid: ${detection.isValid}`);
    logger.info(`  Metadata:`, detection.metadata);
  }
}

module.exports = IDTypeManager;
