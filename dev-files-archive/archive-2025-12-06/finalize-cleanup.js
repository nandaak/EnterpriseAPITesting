const fs = require('fs');
const path = require('path');

/**
 * FINAL CLEANUP - Archive the cleanup scripts themselves
 */

console.log('\n🎯 Final Cleanup - Archiving cleanup scripts...\n');

const archivePath = path.join(__dirname, 'dev-files-archive', 'archive-2025-12-06');

// Cleanup scripts to archive
const cleanupScripts = [
  'cleanup-dev-files.js',
  'cleanup-old-docs.js',
  'finalize-cleanup.js'
];

let archived = 0;

cleanupScripts.forEach(file => {
  const sourcePath = path.join(__dirname, file);
  const destPath = path.join(archivePath, file);
  
  if (fs.existsSync(sourcePath) && file !== 'finalize-cleanup.js') {
    try {
      fs.copyFileSync(sourcePath, destPath);
      fs.unlinkSync(sourcePath);
      console.log(`✓ Archived: ${file}`);
      archived++;
    } catch (error) {
      console.log(`⚠️  Error: ${error.message}`);
    }
  }
});

// Update archive index
const indexPath = path.join(archivePath, 'ARCHIVE-INDEX.md');
if (fs.existsSync(indexPath)) {
  let index = fs.readFileSync(indexPath, 'utf8');
  index += '\n### Cleanup Scripts\n\n';
  cleanupScripts.forEach(file => {
    index += `- ${file}\n`;
  });
  fs.writeFileSync(indexPath, index, 'utf8');
  console.log('✓ Updated archive index\n');
}

console.log('═'.repeat(60));
console.log('  FINAL CLEANUP COMPLETE');
console.log('═'.repeat(60));
console.log(`\n✅ Archived ${archived} cleanup scripts`);
console.log('\n📁 Project Root is Now Clean!\n');

// Self-destruct this script
setTimeout(() => {
  try {
    const selfPath = path.join(__dirname, 'finalize-cleanup.js');
    const selfDest = path.join(archivePath, 'finalize-cleanup.js');
    fs.copyFileSync(selfPath, selfDest);
    fs.unlinkSync(selfPath);
    console.log('✓ Self-archived: finalize-cleanup.js\n');
  } catch (error) {
    console.log('Note: Please manually delete finalize-cleanup.js\n');
  }
}, 1000);
