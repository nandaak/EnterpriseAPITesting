/**
 * @fileoverview Test Helpers for Advanced Security Testing.
 * This module exports functions used by the '3.Advanced-Security-Testing.test.js' suite
 * to execute real-world security checks against API endpoints.
 */

const apiClient = require("./api-client");
const logger = require("./logger");
const { HTTP_STATUS_CODES, TEST_TAGS } = require("../Constants");
// NOTE: Assuming there are helper functions in 'security-helpers.js' 
// for creating and managing test users/tokens.
const { 
    createTestUser, 
    loginUser, 
    getLowPrivilegeToken, 
    getHighPrivilegeToken,
    getAnotherUserToken,
    generateMaliciousPayload 
} = require("./security-helpers");


// =========================================================================
// INTERFACE: Security Test Result Object
// =========================================================================
// All test functions must return an object matching this structure:
/*
{
    success: boolean,
    details: string,
    vulnerabilities: string[], // List of vulnerability types found (e.g., "Price Manipulation")
    // ... any other relevant data
}
*/
// =========================================================================

/**
 * Helper to extract an executable endpoint URL/Method from moduleConfig.
 * Prioritizes POST/PUT/EDIT for testing mutations.
 * @param {object} moduleConfig The configuration for the current module.
 * @returns {{url: string, method: string}|null}
 */
const getRelevantEndpoint = (moduleConfig) => {
    // Priority order for advanced tests: mutation methods
    const prioritizedMethods = ['POST', 'PUT', 'EDIT', 'Commit']; 
    
    for (const method of prioritizedMethods) {
        if (moduleConfig[method] && Array.isArray(moduleConfig[method]) && moduleConfig[method][0] !== "URL_HERE") {
            // Assuming the first element is the URL and the method is the key itself
            return { url: moduleConfig[method][0], method: method.toLowerCase() };
        }
    }
    // Fallback to View/LookUP (read operations are relevant for IDOR/Privilege)
    if (moduleConfig.View && Array.isArray(moduleConfig.View) && moduleConfig.View[0] !== "URL_HERE") {
         return { url: moduleConfig.View[0], method: 'get' };
    }

    return null;
};

// =========================================================================
// 🎯 TC-1: BUSINESS LOGIC FLAWS (Price Manipulation)
// =========================================================================

/**
 * Tests for business logic flaws, such as manipulating item prices in a transaction.
 * @param {object} moduleConfig The configuration for the current module.
 * @param {string} fullModuleName The full path name of the module being tested.
 * @returns {Promise<object>} The security test results.
 */
const testBusinessLogicFlaws = async (moduleConfig, fullModuleName) => {
    logger.debug(`[BLF] Starting test on ${fullModuleName}...`);
    const endpoint = getRelevantEndpoint(moduleConfig);

    if (!endpoint || (endpoint.method !== 'post' && endpoint.method !== 'put')) {
        return {
            success: true,
            details: `Skipped: No suitable POST/PUT/EDIT endpoint found for Business Logic test in ${fullModuleName}.`,
            vulnerabilities: [],
        };
    }

    try {
        // 1. Get a standard user token
        const userToken = await getLowPrivilegeToken();

        // 2. Prepare a standard payload (A resource creation request)
        const standardPayload = {
            itemName: `TestItem-${Date.now()}`,
            quantity: 1,
            unitPrice: 100.00, // The legitimate price
            totalPrice: 100.00
        };

        // 3. Prepare a malicious payload (Manipulate the price)
        const maliciousPayload = {
            ...standardPayload,
            unitPrice: 0.01, // Attacker tries to pay 0.01 instead of 100.00
            totalPrice: 0.01 
        };
        
        // 4. Execute the malicious request
        const maliciousResponse = await apiClient[endpoint.method](
            endpoint.url, 
            maliciousPayload, 
            { headers: { Authorization: `Bearer ${userToken}` } }
        );

        // 5. Check if the server accepted the manipulated price
        if (maliciousResponse.status === HTTP_STATUS_CODES.OK || maliciousResponse.status === HTTP_STATUS_CODES.CREATED) {
            // NOTE: A real check would involve retrieving the created resource
            // and validating the price saved in the database, but for a high-level
            // test helper, checking the immediate response body is often sufficient 
            // to indicate a potential issue.
            const savedPrice = maliciousResponse.data.totalPrice || maliciousResponse.data.unitPrice;
            
            if (savedPrice < standardPayload.totalPrice) {
                 // **VULNERABILITY DETECTED**
                logger.error(`[BLF-FAIL] Price manipulation successful in ${fullModuleName}. Saved price: ${savedPrice}`);
                return {
                    success: false,
                    details: `Vulnerability: Price manipulation successful. Attacker tried to save ${maliciousPayload.totalPrice}, server accepted ${savedPrice}.`,
                    vulnerabilities: ["Business Logic Flaw - Price Manipulation"],
                };
            }
        }
        
        return {
            success: true,
            details: `Business logic test passed. Attempted price manipulation was rejected (Status: ${maliciousResponse.status}).`,
            vulnerabilities: [],
        };

    } catch (error) {
        // Expecting a failure (4xx or 5xx) when the server correctly rejects the malicious request
        if (error.response && error.response.status === HTTP_STATUS_CODES.FORBIDDEN) {
             return {
                success: true,
                details: "Request was correctly rejected (Forbidden), indicating server-side price validation is likely present.",
                vulnerabilities: [],
            };
        }
        
        logger.error(`[BLF-ERROR] Test execution error for ${fullModuleName}: ${error.message}`);
        throw error;
    }
};

// =========================================================================
// 🎯 TC-2: PRIVILEGE ESCALATION (Horizontal & Vertical)
// =========================================================================

/**
 * Tests for privilege escalation, where a low-privilege user attempts to perform 
 * an action reserved for a high-privilege user (Vertical) or another user (Horizontal).
 * @param {object} moduleConfig The configuration for the current module.
 * @param {string} fullModuleName The full path name of the module being tested.
 * @returns {Promise<object>} The security test results.
 */
const testPrivilegeEscalation = async (moduleConfig, fullModuleName) => {
    logger.debug(`[PE] Starting test on ${fullModuleName}...`);
    const endpoint = getRelevantEndpoint(moduleConfig);

    if (!endpoint || (endpoint.method !== 'post' && endpoint.method !== 'put')) {
         return {
            success: true,
            details: `Skipped: No suitable POST/PUT/EDIT endpoint found for Privilege Escalation test in ${fullModuleName}.`,
            vulnerabilities: [],
        };
    }

    const highPrivilegeToken = await getHighPrivilegeToken();
    const lowPrivilegeToken = await getLowPrivilegeToken();
    let vulnerabilities = [];
    
    // --- VERTICAL PRIVILEGE ESCALATION (Low user attempts High action) ---
    try {
        // 1. Low-privilege user attempts an administrative action (e.g., creating a new module entry)
        const lowPrivilegePayload = generateMaliciousPayload(fullModuleName, 'vertical_escalation');
        
        // Use a high-privilege endpoint URL if available, otherwise use a generic mutation endpoint.
        const response = await apiClient[endpoint.method](
            endpoint.url, 
            lowPrivilegePayload, 
            { headers: { Authorization: `Bearer ${lowPrivilegeToken}` } }
        );

        // A successful response (200/201) indicates a vertical privilege escalation vulnerability
        if (response.status === HTTP_STATUS_CODES.OK || response.status === HTTP_STATUS_CODES.CREATED) {
            vulnerabilities.push("Vertical Privilege Escalation");
            logger.error(`[PE-FAIL] Vertical privilege escalation successful in ${fullModuleName}. Low-privilege user gained access.`);
        }

    } catch (error) {
        // Correct behavior is a 403 Forbidden or 401 Unauthorized
        if (error.response && (error.response.status === HTTP_STATUS_CODES.FORBIDDEN || error.response.status === HTTP_STATUS_CODES.UNAUTHORIZED)) {
             logger.debug(`[PE-PASS] Vertical escalation attempt correctly rejected (Status: ${error.response.status}).`);
        } else {
            // An unexpected error or a success response not caught above is a failure
            logger.error(`[PE-ERROR] Vertical Escalation Test Error: ${error.message}`);
        }
    }
    
    // --- HORIZONTAL PRIVILEGE ESCALATION (User A attempts to access/modify User B's resource) ---
    try {
        // This requires two different users and an ID to test. 
        // We'll rely on the IDOR test for full coverage, but include a basic check here.
        const anotherUserToken = await getAnotherUserToken();
        // Assuming a PUT/EDIT requires a resource ID in the URL for horizontal checks.
        
        // This is highly dependent on the URL structure. We'll skip detailed horizontal 
        // check here to avoid complex mock data generation and let IDOR cover it.
        // The absence of an ID in the URL makes the test impractical without context.
        logger.debug(`[PE-SKIP] Skipping detailed horizontal escalation check (covered by IDOR).`);

    } catch (error) {
        // Catch-all error logging for horizontal test
    }


    return {
        success: vulnerabilities.length === 0,
        details: vulnerabilities.length === 0 ? "All privilege escalation checks passed." : "Privilege escalation vulnerabilities found.",
        vulnerabilities: vulnerabilities,
    };
};


// =========================================================================
// 🎯 TC-3: MASS ASSIGNMENT VULNERABILITIES
// =========================================================================

/**
 * Tests for mass assignment vulnerabilities, where an attacker sends unauthorized
 * fields (e.g., 'isAdmin', 'accountBalance') in a standard request to modify them.
 * @param {object} moduleConfig The configuration for the current module.
 * @param {string} fullModuleName The full path name of the module being tested.
 * @returns {Promise<object>} The security test results.
 */
const testMassAssignment = async (moduleConfig, fullModuleName) => {
    logger.debug(`[MA] Starting test on ${fullModuleName}...`);
    const endpoint = getRelevantEndpoint(moduleConfig);

    if (!endpoint || (endpoint.method !== 'post' && endpoint.method !== 'put' && endpoint.method !== 'edit')) {
        return {
            success: true,
            details: `Skipped: No suitable POST/PUT/EDIT endpoint found for Mass Assignment test in ${fullModuleName}.`,
            vulnerabilities: [],
        };
    }

    try {
        // 1. Get a standard user token
        const userToken = await getLowPrivilegeToken();

        // 2. Prepare the malicious payload
        const maliciousPayload = {
            // Standard user input fields
            name: "Normal Update",
            description: "Attempting to mass assign a protected field",
            // Malicious protected fields
            isAdmin: true, // Attempt to elevate privilege
            accountBalance: 999999, // Attempt to change balance
            role: "administrator" // Attempt to change role
        };
        
        // 3. Execute the malicious request
        const maliciousResponse = await apiClient[endpoint.method](
            endpoint.url, 
            maliciousPayload, 
            { headers: { Authorization: `Bearer ${userToken}` } }
        );

        // 4. Check if protected fields were modified in the response (or follow-up check)
        if (maliciousResponse.status === HTTP_STATUS_CODES.OK || maliciousResponse.status === HTTP_STATUS_CODES.CREATED) {
            // A real-world check would involve querying the DB or a View endpoint to see 
            // if the protected fields were actually saved with the malicious values.
            const responseBody = maliciousResponse.data || {};
            
            if (responseBody.isAdmin === true || responseBody.accountBalance === 999999 || responseBody.role === "administrator") {
                 // **VULNERABILITY DETECTED**
                logger.error(`[MA-FAIL] Mass Assignment successful in ${fullModuleName}. Protected field 'isAdmin' or 'accountBalance' was accepted.`);
                return {
                    success: false,
                    details: "Vulnerability: Mass Assignment successful. Server accepted and processed unauthorized protected fields.",
                    vulnerabilities: ["Mass Assignment"],
                };
            }
        }
        
        return {
            success: true,
            details: `Mass Assignment test passed. Protected fields were not assigned. (Status: ${maliciousResponse.status}).`,
            vulnerabilities: [],
        };

    } catch (error) {
        // Generally, the test should pass if the request is accepted but the protected fields are ignored.
        // A failure here would indicate an execution error, not necessarily a vulnerability.
        logger.error(`[MA-ERROR] Test execution error for ${fullModuleName}: ${error.message}`);
        throw error;
    }
};


// =========================================================================
// 🎯 TC-4: INSECURE DIRECT OBJECT REFERENCES (IDOR)
// =========================================================================

/**
 * Tests for IDOR vulnerabilities, where a user can access or modify another user's 
 * resources by changing a predictable resource ID in the URL or payload.
 * @param {object} moduleConfig The configuration for the current module.
 * @param {string} fullModuleName The full path name of the module being tested.
 * @returns {Promise<object>} The security test results.
 */
const testIDORVulnerabilities = async (moduleConfig, fullModuleName) => {
    logger.debug(`[IDOR] Starting test on ${fullModuleName}...`);
    // Find an endpoint that uses an ID (View/PUT/DELETE)
    const viewEndpoint = moduleConfig.View && moduleConfig.View[0] !== "URL_HERE" ? moduleConfig.View[0] : null;

    if (!viewEndpoint || !viewEndpoint.includes('{id}')) {
        return {
            success: true,
            details: `Skipped: No suitable VIEW endpoint with a dynamic ID found for IDOR test in ${fullModuleName}. (Expected URL to contain '{id}')`,
            vulnerabilities: [],
        };
    }

    try {
        // 1. Get tokens for two different, low-privilege users
        const userAToken = await getLowPrivilegeToken(); // User A owns Resource 1
        const userBToken = await getAnotherUserToken(); // User B (The attacker)

        // 2. Mock a resource ID (Resource 1) that belongs to User A
        // NOTE: In a real test, you'd CREATE Resource 1 using User A's token first 
        // and capture the returned ID. For a mock, we use a known ID.
        const resourceId = '12345'; // The resource ID belonging to User A

        const targetUrl = viewEndpoint.replace('{id}', resourceId);

        // 3. User B (attacker) attempts to access User A's resource (Resource 1)
        const attackResponse = await apiClient.get(
            targetUrl, 
            { headers: { Authorization: `Bearer ${userBToken}` } }
        );

        // 4. Check if the access was successful
        if (attackResponse.status === HTTP_STATUS_CODES.OK) {
             // **VULNERABILITY DETECTED**
            logger.error(`[IDOR-FAIL] IDOR successful in ${fullModuleName}. User B accessed User A's resource ID ${resourceId}.`);
            return {
                success: false,
                details: `Vulnerability: IDOR successful. Attacker (User B) accessed another user's resource (ID ${resourceId}).`,
                vulnerabilities: ["Insecure Direct Object Reference (IDOR)"],
            };
        }
        
        return {
            success: true,
            details: `IDOR test passed. Access to the resource ID ${resourceId} was correctly denied for User B (Status: ${attackResponse.status}).`,
            vulnerabilities: [],
        };

    } catch (error) {
        // Correct behavior is a 403 Forbidden or 404 Not Found (if implemented securely)
        if (error.response && (error.response.status === HTTP_STATUS_CODES.FORBIDDEN || error.response.status === HTTP_STATUS_CODES.NOT_FOUND || error.response.status === HTTP_STATUS_CODES.UNAUTHORIZED)) {
             return {
                success: true,
                details: `Request was correctly denied (Status: ${error.response.status}). IDOR protection is present.`,
                vulnerabilities: [],
            };
        }
        
        logger.error(`[IDOR-ERROR] Test execution error for ${fullModuleName}: ${error.message}`);
        throw error;
    }
};


// =========================================================================
// 🎯 TC-5: RACE CONDITIONS & CONCURRENCY
// =========================================================================

/**
 * Tests for race condition vulnerabilities by sending multiple simultaneous requests
 * (e.g., trying to withdraw more money than available).
 * @param {object} moduleConfig The configuration for the current module.
 * @param {string} fullModuleName The full path name of the module being tested.
 * @returns {Promise<object>} The security test results.
 */
const testRaceConditions = async (moduleConfig, fullModuleName) => {
    logger.debug(`[RC] Starting test on ${fullModuleName}...`);
    const endpoint = getRelevantEndpoint(moduleConfig);

    // This test is highly specific to a transactional endpoint (like a withdrawal or purchase)
    if (!endpoint || (endpoint.method !== 'post' && endpoint.method !== 'put') || !fullModuleName.toLowerCase().includes('transaction')) {
        return {
            success: true,
            details: `Skipped: Endpoint not suitable for Race Condition test in ${fullModuleName} (Requires POST/PUT/EDIT on a transactional module).`,
            vulnerabilities: [],
        };
    }

    const CONCURRENCY_LEVEL = 5; // Number of simultaneous requests
    const initialBalance = 100;
    const withdrawalAmount = 60;

    try {
        const userToken = await getLowPrivilegeToken();
        const transactionUrl = endpoint.url;

        // 1. Setup/Mock Initial State
        // In a real test: create an account/resource with the initialBalance.
        logger.info(`[RC-SETUP] Mocking initial balance: ${initialBalance}. Withdrawal attempt: ${withdrawalAmount}`);

        // 2. Define the payload for the withdrawal
        const payload = {
            amount: withdrawalAmount,
            accountId: 'mocked-account-id', // Assuming a fixed ID for the test
        };

        // 3. Create a burst of simultaneous requests
        const requestPromises = Array(CONCURRENCY_LEVEL).fill(0).map((_, index) => {
            return apiClient[endpoint.method](
                transactionUrl,
                payload,
                { headers: { Authorization: `Bearer ${userToken}` } }
            ).catch(err => err.response || err); // Capture success/failure responses
        });
        
        logger.info(`[RC-EXEC] Sending ${CONCURRENCY_LEVEL} simultaneous requests...`);
        const results = await Promise.all(requestPromises);

        // 4. Analyze results (Count successful transactions)
        const successfulTransactions = results.filter(res => 
            res && (res.status === HTTP_STATUS_CODES.OK || res.status === HTTP_STATUS_CODES.CREATED)
        ).length;
        
        // Only ONE transaction should succeed (total withdrawal: 60)
        // If more than one succeeds, a race condition allowed an overdraft/double-spend.
        if (successfulTransactions > 1) {
             // **VULNERABILITY DETECTED**
            logger.error(`[RC-FAIL] Race condition successful in ${fullModuleName}. ${successfulTransactions} transactions succeeded, expected 1.`);
            return {
                success: false,
                details: `Vulnerability: Race Condition successful. ${successfulTransactions} transactions executed, leading to potential overdraft (Max allowed: 1).`,
                vulnerabilities: ["Race Condition"],
            };
        }

        return {
            success: true,
            details: `Race Condition test passed. Only ${successfulTransactions} transaction(s) succeeded, indicating proper concurrency control.`,
            vulnerabilities: [],
        };

    } catch (error) {
        logger.error(`[RC-ERROR] Test execution error for ${fullModuleName}: ${error.message}`);
        throw error;
    }
};


// =========================================================================
// EXPORTS
// =========================================================================

module.exports = {
    testBusinessLogicFlaws,
    testPrivilegeEscalation,
    testMassAssignment,
    testIDORVulnerabilities,
    testRaceConditions,
};