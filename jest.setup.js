// jest.setup.js - Simplified setup without Allure
console.log('[JEST SETUP] Initializing Jest configuration...');

// Mock functions for compatibility (will be no-ops)
const mockFunction = (name) => {
  return (...args) => {
    console.log(`[MOCK] ${name}:`, args.length > 0 ? args[0] : '');
  };
};

// Create minimal global object for compatibility
global.allure = {
  epic: mockFunction('epic'),
  feature: mockFunction('feature'),
  story: mockFunction('story'),
  severity: mockFunction('severity'),
  suite: mockFunction('suite'),
  parentSuite: mockFunction('parentSuite'),
  subSuite: mockFunction('subSuite'),
  owner: mockFunction('owner'),
  lead: mockFunction('lead'),
  addLabel: mockFunction('addLabel'),
  addParameter: mockFunction('addParameter'),
  description: mockFunction('description'),
  addLink: mockFunction('addLink'),
  issue: mockFunction('issue'),
  tms: mockFunction('tms'),
  testId: mockFunction('testId')
};

// Mock step function
global.allureStep = async (stepName, stepFunction) => {
  console.log(`[STEP START] ${stepName}`);
  const startTime = Date.now();
  try {
    const result = await stepFunction();
    const duration = Date.now() - startTime;
    console.log(`[STEP PASS] ${stepName} (${duration}ms)`);
    return result;
  } catch (error) {
    const duration = Date.now() - startTime;
    console.log(`[STEP FAIL] ${stepName} (${duration}ms)`, error.message);
    throw error;
  }
};

// Mock attachment functions (no-ops for HTML reporter)
global.attachAllureLog = (name, content) => {
  console.log(`[ATTACH] ${name}:`, typeof content === 'string' ? content.substring(0, 100) + '...' : '[Object]');
};

global.attachJSON = (name, jsonData) => {
  const content = typeof jsonData === 'object' ? JSON.stringify(jsonData, null, 2) : jsonData;
  console.log(`[JSON ATTACH] ${name}:`, content.substring(0, 100) + '...');
};

console.log('[JEST SETUP] Configuration completed successfully');