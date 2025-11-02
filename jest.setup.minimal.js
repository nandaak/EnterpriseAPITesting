// jest.setup.minimal.js - Ultra minimal setup
console.log('[JEST SETUP] Loading minimal setup...');

// Mock Allure functions to prevent errors
const mockFunction = (name) => {
  return (...args) => {
    console.log(`[ALLURE MOCK] ${name}:`, args.length > 0 ? args[0] : '');
  };
};

// Create minimal global Allure object
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
  try {
    const result = await stepFunction();
    console.log(`[STEP PASS] ${stepName}`);
    return result;
  } catch (error) {
    console.log(`[STEP FAIL] ${stepName}: ${error.message}`);
    throw error;
  }
};

// Mock attachment functions
global.attachAllureLog = (name, content) => {
  console.log(`[ATTACH] ${name}`);
};

global.attachJSON = (name, jsonData) => {
  console.log(`[JSON ATTACH] ${name}`);
};

console.log('[JEST SETUP] Minimal setup completed');