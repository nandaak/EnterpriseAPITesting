// verify-token.js - Verify token file status
const fs = require('fs');
const path = require('path');

const tokenPath = path.join(__dirname, 'token.txt');

try {
  const token = fs.readFileSync(tokenPath, 'utf8');
  
  console.log('📊 Token File Status:');
  console.log(`   Length: ${token.length} characters`);
  console.log(`   Has quotes: ${token.includes('"') ? '❌ YES' : '✅ NO'}`);
  console.log(`   Has newlines: ${token.includes('\n') ? '❌ YES' : '✅ NO'}`);
  console.log(`   Preview: ${token.substring(0, 50)}...`);
  
  // Check JWT structure
  const parts = token.split('.');
  console.log(`   JWT parts: ${parts.length} ${parts.length === 3 ? '✅' : '❌'}`);
  
} catch (error) {
  console.error('❌ Error reading token:', error.message);
  process.exit(1);
}
