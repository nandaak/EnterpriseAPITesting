// jest.setup.js - Complete Allure setup
console.log('[JEST SETUP] Initializing Allure configuration...');

// Initialize global Allure object
global.allure = {
  // Core methods
  addLabel: (name, value) => {
    console.log(`[ALLURE] Label: ${name}=${value}`);
  },
  addParameter: (name, value, mode = 'hidden') => {
    console.log(`[ALLURE] Parameter: ${name}=${value}, mode=${mode}`);
  },
  description: (value) => {
    console.log(`[ALLURE] Description: ${value}`);
  },
  addLink: (name, url, type = 'custom') => {
    console.log(`[ALLURE] Link: ${name}, ${url}, type=${type}`);
  },
  
  // Convenience methods
  epic: (epic) => {
    console.log(`[ALLURE] Epic: ${epic}`);
    global.allure.addLabel('epic', epic);
  },
  feature: (feature) => {
    console.log(`[ALLURE] Feature: ${feature}`);
    global.allure.addLabel('feature', feature);
  },
  story: (story) => {
    console.log(`[ALLURE] Story: ${story}`);
    global.allure.addLabel('story', story);
  },
  severity: (severity) => {
    console.log(`[ALLURE] Severity: ${severity}`);
    global.allure.addLabel('severity', severity);
  },
  suite: (suite) => {
    console.log(`[ALLURE] Suite: ${suite}`);
    global.allure.addLabel('suite', suite);
  },
  parentSuite: (parentSuite) => {
    console.log(`[ALLURE] Parent Suite: ${parentSuite}`);
    global.allure.addLabel('parentSuite', parentSuite);
  },
  subSuite: (subSuite) => {
    console.log(`[ALLURE] Sub Suite: ${subSuite}`);
    global.allure.addLabel('subSuite', subSuite);
  },
  owner: (owner) => {
    console.log(`[ALLURE] Owner: ${owner}`);
    global.allure.addLabel('owner', owner);
  },
  lead: (lead) => {
    console.log(`[ALLURE] Lead: ${lead}`);
    global.allure.addLabel('lead', lead);
  },
  
  // Issue tracking
  issue: (value) => {
    global.allure.addLink(value, `https://example.com/issue/${value}`, 'issue');
  },
  tms: (value) => {
    global.allure.addLink(value, `https://example.com/tms/${value}`, 'tms');
  },
  testId: (value) => {
    global.allure.addLabel('testId', value);
  }
};

// Safe attachment methods
global.attachAllureLog = (name, content) => {
  console.log(`[ALLURE ATTACH] ${name}:`, typeof content === 'string' ? content.substring(0, 100) + '...' : '[Object]');
};

global.attachJSON = (name, jsonData) => {
  const content = typeof jsonData === 'object' ? JSON.stringify(jsonData, null, 2) : jsonData;
  console.log(`[ALLURE JSON] ${name}:`, content.substring(0, 100) + '...');
};

// Safe step function
global.allureStep = async (stepName, stepFunction) => {
  console.log(`[ALLURE STEP START] ${stepName}`);
  const startTime = Date.now();
  try {
    const result = await stepFunction();
    const duration = Date.now() - startTime;
    console.log(`[ALLURE STEP PASS] ${stepName} (${duration}ms)`);
    return result;
  } catch (error) {
    const duration = Date.now() - startTime;
    console.log(`[ALLURE STEP FAIL] ${stepName} (${duration}ms)`, error.message);
    throw error;
  }
};

console.log('[JEST SETUP] Allure configuration completed successfully');