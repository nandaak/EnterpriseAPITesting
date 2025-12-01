
/**
 * Validate and enhance payloads before sending
 */
function validateAndEnhancePayload(moduleName, payload, method) {
  if (!payload || typeof payload !== 'object') {
    return {};
  }
  
  const enhanced = { ...payload };
  
  // Add common required fields if missing
  if (method === 'POST' || method === 'PUT') {
    // Ensure name fields exist
    if (!enhanced.name && !enhanced.code) {
      enhanced.name = `Test ${moduleName}`;
    }
    
    // Add Arabic name if name exists but nameAr doesn't
    if (enhanced.name && !enhanced.nameAr) {
      enhanced.nameAr = `${enhanced.name} عربي`;
    }
    
    // Ensure arrays are initialized
    Object.keys(enhanced).forEach(key => {
      if (key.toLowerCase().includes('ids') || key.toLowerCase().includes('list')) {
        if (!Array.isArray(enhanced[key])) {
          enhanced[key] = [];
        }
      }
    });
  }
  
  return enhanced;
}

module.exports = { validateAndEnhancePayload };
