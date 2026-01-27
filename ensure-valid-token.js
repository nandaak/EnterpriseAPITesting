// ensure-valid-token.js - Robust token validation and refresh
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

const TOKEN_PATH = path.join(__dirname, 'token.txt');

/**
 * Clean token from quotes and line breaks
 */
function cleanToken(token) {
  return token
    .replace(/[\r\n"']/g, '')
    .trim();
}

/**
 * Validate JWT token structure and expiration
 */
function validateToken(token) {
  if (!token) {
    return { valid: false, reason: 'Token is empty' };
  }

  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, reason: 'Invalid JWT structure' };
    }

    // Decode payload
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(Buffer.from(base64, 'base64').toString());

    const expiresAt = new Date(payload.exp * 1000);
    const now = new Date();
    const minutesUntilExpiry = Math.round((expiresAt - now) / (1000 * 60));

    if (minutesUntilExpiry < 0) {
      return { valid: false, reason: 'Token expired', expiresAt, minutesUntilExpiry };
    }

    if (minutesUntilExpiry < 5) {
      return { valid: false, reason: 'Token expires soon', expiresAt, minutesUntilExpiry };
    }

    return { valid: true, expiresAt, minutesUntilExpiry };
  } catch (error) {
    return { valid: false, reason: `Validation error: ${error.message}` };
  }
}

/**
 * Read token from file
 */
function readToken() {
  try {
    if (!fs.existsSync(TOKEN_PATH)) {
      return null;
    }

    const rawToken = fs.readFileSync(TOKEN_PATH, 'utf8');
    return cleanToken(rawToken);
  } catch (error) {
    console.error(`❌ Error reading token: ${error.message}`);
    return null;
  }
}

/**
 * Save token to file
 */
function saveToken(token) {
  try {
    const cleanedToken = cleanToken(token);
    fs.writeFileSync(TOKEN_PATH, cleanedToken, 'utf8');
    console.log(`✅ Token saved (${cleanedToken.length} characters)`);
    return true;
  } catch (error) {
    console.error(`❌ Error saving token: ${error.message}`);
    return false;
  }
}

/**
 * Fetch new token
 */
async function fetchNewToken() {
  console.log('🔄 Fetching new token...');
  
  try {
    const { stdout, stderr } = await execAsync('node fetchToken.js');
    
    if (stderr && !stderr.includes('dotenv')) {
      console.error(`⚠️  Fetch token stderr: ${stderr}`);
    }
    
    // Read the token that was saved by fetchToken.js
    const token = readToken();
    
    if (!token) {
      throw new Error('Token file is empty after fetch');
    }
    
    // Clean and save again to ensure no quotes/newlines
    saveToken(token);
    
    console.log('✅ New token fetched and cleaned');
    return token;
  } catch (error) {
    throw new Error(`Failed to fetch token: ${error.message}`);
  }
}

/**
 * Ensure valid token exists
 */
async function ensureValidToken() {
  console.log('\n🔐 Token Validation and Refresh\n');
  console.log('='.repeat(70));
  
  // Step 1: Check if token file exists
  let token = readToken();
  
  if (!token) {
    console.log('❌ No token file found');
    console.log('🔄 Fetching new token...');
    token = await fetchNewToken();
    const validation = validateToken(token);
    
    if (!validation.valid) {
      throw new Error(`Fetched token is invalid: ${validation.reason}`);
    }
    
    console.log(`✅ New token is valid (expires in ${validation.minutesUntilExpiry} minutes)`);
    console.log('='.repeat(70) + '\n');
    return { token, refreshed: true, validation };
  }
  
  // Step 2: Validate existing token
  console.log(`📄 Token file found (${token.length} characters)`);
  const validation = validateToken(token);
  
  if (!validation.valid) {
    console.log(`❌ Token is invalid: ${validation.reason}`);
    console.log('🔄 Fetching new token...');
    token = await fetchNewToken();
    const newValidation = validateToken(token);
    
    if (!newValidation.valid) {
      throw new Error(`Fetched token is invalid: ${newValidation.reason}`);
    }
    
    console.log(`✅ New token is valid (expires in ${newValidation.minutesUntilExpiry} minutes)`);
    console.log('='.repeat(70) + '\n');
    return { token, refreshed: true, validation: newValidation };
  }
  
  // Step 3: Token is valid
  console.log(`✅ Token is valid`);
  console.log(`⏰ Expires in: ${validation.minutesUntilExpiry} minutes`);
  console.log(`📅 Expires at: ${validation.expiresAt.toLocaleString()}`);
  console.log('='.repeat(70) + '\n');
  
  return { token, refreshed: false, validation };
}

// Run if called directly
if (require.main === module) {
  ensureValidToken()
    .then(result => {
      console.log('✅ Token validation complete');
      if (result.refreshed) {
        console.log('🔄 Token was refreshed');
      } else {
        console.log('✓ Existing token is valid');
      }
      process.exit(0);
    })
    .catch(error => {
      console.error(`\n❌ Token validation failed: ${error.message}\n`);
      process.exit(1);
    });
}

module.exports = { ensureValidToken, validateToken, readToken, cleanToken };
