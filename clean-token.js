// clean-token.js - Clean token file from quotes and line breaks
const fs = require('fs');
const path = require('path');

const tokenPath = path.join(__dirname, 'token.txt');

try {
  // Read the token file
  const rawToken = fs.readFileSync(tokenPath, 'utf8');
  
  // Remove quotes, line breaks, carriage returns, and trim
  const cleanToken = rawToken
    .replace(/[\r\n"']/g, '')
    .trim();
  
  // Write back the cleaned token
  fs.writeFileSync(tokenPath, cleanToken, 'utf8');
  
  console.log('✅ Token cleaned successfully');
  console.log(`📏 Token length: ${cleanToken.length} characters`);
  console.log(`🔐 Token preview: ${cleanToken.substring(0, 30)}...`);
  
  // Verify it's a valid JWT structure
  const parts = cleanToken.split('.');
  if (parts.length === 3) {
    console.log('✅ Token has valid JWT structure (3 parts)');
  } else {
    console.warn('⚠️  Warning: Token does not have standard JWT structure');
  }
  
} catch (error) {
  console.error('❌ Error cleaning token:', error.message);
  process.exit(1);
}
