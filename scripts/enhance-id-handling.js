#!/usr/bin/env node
// scripts/enhance-id-handling.js
/**
 * Enhancement script to update all ID handling in CRUD lifecycle helper
 * Replaces simple string replacement with intelligent ID type management
 * 
 * Usage: node scripts/enhance-id-handling.js
 */

const fs = require('fs');
const path = require('path');

const filePath = path.join(process.cwd(), 'utils/crud-lifecycle-helper.js');

console.log('🔧 Enhancing ID handling in CRUD lifecycle helper...\n');

try {
  let content = fs.readFileSync(filePath, 'utf8');
  let changesCount = 0;

  // Enhancement 1: Replace simple .replace("<createdId>", currentId) with IDTypeManager
  const simpleReplacePattern = /\.replace\("<createdId>", currentId\)/g;
  const matches = content.match(simpleReplacePattern);
  
  if (matches) {
    console.log(`Found ${matches.length} instances of simple ID replacement`);
    
    content = content.replace(
      /const (\w+Endpoint) = operation\.endpoint\.replace\("<createdId>", currentId\);/g,
      (match, varName) => {
        changesCount++;
        return `// Use ID Type Manager for intelligent placeholder replacement
    const ${varName} = IDTypeManager.replacePlaceholder(
      operation.endpoint,
      currentId
    );`;
      }
    );
  }

  // Enhancement 2: Add ID type logging to success messages
  content = content.replace(
    /logger\.info\(`✅ (\w+) SUCCESS - Resource (\w+): \$\{currentId\}`\);/g,
    (match, phase, action) => {
      changesCount++;
      return `logger.info(\`✅ ${phase} SUCCESS - Resource ${action}: \${currentId} (\${this.createdIdType})\`);`;
    }
  );

  // Enhancement 3: Add ID type to return objects
  content = content.replace(
    /return \{(\s+)response,(\s+)(\w+Data): this\.resourceState\.(\w+Data),/g,
    (match, space1, space2, dataVar, stateVar) => {
      changesCount++;
      return `return {${space1}response,${space2}${dataVar}: this.resourceState.${stateVar},${space2}idType: this.createdIdType,`;
    }
  );

  if (changesCount > 0) {
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`\n✅ Successfully enhanced ${changesCount} ID handling instances`);
    console.log(`📝 File updated: ${filePath}`);
  } else {
    console.log('\nℹ️  No changes needed - file already enhanced or pattern not found');
  }

} catch (error) {
  console.error(`\n❌ Error: ${error.message}`);
  process.exit(1);
}

console.log('\n✨ ID handling enhancement complete!');
