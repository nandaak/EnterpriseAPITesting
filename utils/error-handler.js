
/**
 * Enhanced error handler for API tests
 */
function handleTestError(error, context) {
  const { moduleName, operation, url, payload } = context;
  
  const errorInfo = {
    module: moduleName,
    operation,
    url,
    status: error.response?.status,
    message: error.response?.data?.message || error.message,
    payload: payload
  };
  
  // Categorize error
  if (errorInfo.status === 400) {
    errorInfo.category = 'BAD_REQUEST';
    errorInfo.suggestion = 'Check payload structure and required fields';
  } else if (errorInfo.status === 404) {
    errorInfo.category = 'NOT_FOUND';
    errorInfo.suggestion = 'Verify endpoint URL';
  } else if (errorInfo.status === 500) {
    errorInfo.category = 'SERVER_ERROR';
    errorInfo.suggestion = 'Check backend logs and dependencies';
  } else {
    errorInfo.category = 'UNKNOWN';
    errorInfo.suggestion = 'Review error details';
  }
  
  return errorInfo;
}

module.exports = { handleTestError };
