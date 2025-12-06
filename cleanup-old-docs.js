const fs = require('fs');
const path = require('path');

/**
 * DOCUMENTATION CLEANUP SCRIPT
 * 
 * Archives old documentation files and keeps only the new unified documentation
 */

console.log('\n🧹 Starting Documentation Cleanup...\n');

// Files to KEEP (new unified documentation)
const KEEP_FILES = [
  'README.md',                                    // Main project readme
  'START-HERE.md',                                // Entry point
  'UNIFIED-PROJECT-DOCUMENTATION.md',             // Complete unified doc
  'PROJECT-DOCUMENTATION-INDEX.md',               // Complete index
  'DOCUMENTATION-UNIFICATION-SUMMARY.md',         // Unification summary
  'COMPLETE-PROJECT-DOCUMENTATION.md',            // Alternative guide
  'LICENSE',                                      // License file
  'LICENSE.md',                                   // License markdown
  '.gitignore',                                   // Git ignore
  'package.json',                                 // Package config
  'package-lock.json',                            // Package lock
  'babel.config.js',                              // Babel config
  'jest.config.js',                               // Jest config
  'jest.setup.js',                                // Jest setup
  '.env',                                         // Environment
  '.env.example',                                 // Environment example
  'token.txt',                                    // Token file
  'createdId.txt'                                 // Created ID file
];

// Files to ARCHIVE (old documentation)
const ARCHIVE_FILES = [
  // Refactoring docs
  'MASTER-REFACTORING-REPORT.md',
  'SCHEMA-TRANSFORMATION-GUIDE.md',
  'SCHEMA-REFACTORING-SUMMARY.md',
  'FINAL-REFACTORING-REPORT.md',
  'REFACTORING-COMPLETE-REPORT.md',
  'schema-fix-summary.md',
  
  // Enhancement docs
  'MASTER-ENHANCEMENT-SUMMARY.md',
  'COMPREHENSIVE-ERP-API-ENHANCEMENT-GUIDE.md',
  'PAYLOAD-ENHANCEMENT-COMPLETE.md',
  'SCHEMA-HARMONIZATION-COMPLETE.md',
  'SCHEMA-ENHANCEMENT-COMPLETE.md',
  'COMPLETE-ENHANCEMENTS-SUMMARY.md',
  'COMPLETE-SCHEMA-GENERATION-SUMMARY.md',
  'PROFESSIONAL-ENHANCEMENT-COMPLETE-SUMMARY.md',
  'FINAL-ENHANCEMENT-REPORT.md',
  
  // Testing docs
  'TEST-REFACTORING-COMPLETE.md',
  'TESTING-ENHANCEMENT-COMPLETE.md',
  'ENHANCED-TESTING-GUIDE.md',
  'TestExplanation.md',
  'CRUD-TEST-FIX-COMPLETE.md',
  'PROFESSIONAL-TEST-FIXING-COMPLETE.md',
  
  // Quick reference docs
  'QUICK-START-GUIDE.md',
  'QUICK-REFERENCE-CARD.md',
  'QUICK-ERP-API-REFERENCE.md',
  'QUICK-ENDPOINT-REFERENCE.md',
  'QUICK-FIX-REFERENCE.md',
  'QUICK-ID-ANALYZER-REFERENCE.md',
  'QUICK-START-CARD.md',
  'QUICK-START-REPORT.md',
  
  // Technical docs
  'ID-REGISTRY-SYSTEM-GUIDE.md',
  'ID-TYPE-MANAGEMENT-GUIDE.md',
  'SWAGGER-INTEGRATION-GUIDE.md',
  'AUTHENTICATION-GUIDE.md',
  'ARCHITECTURE-DIAGRAM.md',
  'ID-REGISTRY-ENHANCEMENT-SUMMARY.md',
  'ID-TYPE-ENHANCEMENT-SUMMARY.md',
  
  // Implementation docs
  'IMPLEMENTATION-CHECKLIST.md',
  'IMPLEMENTATION-SUMMARY.md',
  'DYNAMIC-ENDPOINT-GUIDE.md',
  'DYNAMIC-ENDPOINT-INDEX.md',
  'DYNAMIC-ENDPOINT-README.md',
  'CLEANUP-GUIDE.md',
  'CLEANUP-ENHANCEMENT-SUMMARY.md',
  
  // Change logs
  'CHANGES-SUMMARY.md',
  'CHANGELOG-ID-REGISTRY.md',
  'ENDPOINT-UPDATE-SUMMARY.md',
  'ENHANCEMENT-SUMMARY.md',
  'UPGRADE-COMPLETE.md',
  
  // Reports
  'REPORT-ENHANCEMENT-SUMMARY.md',
  'EXECUTIVE-SUMMARY.md',
  'DOCUMENTATION-INDEX.md',
  'DUPLICATE-FILE-FIX-SUMMARY.md',
  
  // Capture/Failure docs
  '404-CAPTURE-UPDATE-COMPLETE.md',
  'FAILURE-CAPTURE-COMPLETE.md',
  'FAILURE-RESPONSE-CAPTURE-GUIDE.md',
  
  // Schema usage
  'SCHEMA-USAGE-INFO.md'
];

// Create archive directory
const archiveDir = path.join(__dirname, 'docs-archive');
const archiveTimestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
const archivePath = path.join(archiveDir, `archive-${archiveTimestamp}`);

function createArchiveDirectory() {
  if (!fs.existsSync(archiveDir)) {
    fs.mkdirSync(archiveDir, { recursive: true });
    console.log('✓ Created archive directory: docs-archive/');
  }
  
  if (!fs.existsSync(archivePath)) {
    fs.mkdirSync(archivePath, { recursive: true });
    console.log(`✓ Created archive subdirectory: archive-${archiveTimestamp}/\n`);
  }
}

function archiveFile(filename) {
  const sourcePath = path.join(__dirname, filename);
  const destPath = path.join(archivePath, filename);
  
  if (fs.existsSync(sourcePath)) {
    try {
      // Copy to archive
      fs.copyFileSync(sourcePath, destPath);
      
      // Delete original
      fs.unlinkSync(sourcePath);
      
      console.log(`  ✓ Archived: ${filename}`);
      return true;
    } catch (error) {
      console.log(`  ⚠️  Error archiving ${filename}: ${error.message}`);
      return false;
    }
  }
  return false;
}

function generateArchiveIndex() {
  let index = '# Archived Documentation\n\n';
  index += `**Archive Date**: ${new Date().toISOString()}\n\n`;
  index += '## Archived Files\n\n';
  index += 'These files have been archived because their content has been unified into:\n';
  index += '- UNIFIED-PROJECT-DOCUMENTATION.md\n';
  index += '- PROJECT-DOCUMENTATION-INDEX.md\n';
  index += '- START-HERE.md\n\n';
  index += '## Files in This Archive\n\n';
  
  const categories = {
    'Refactoring': [],
    'Enhancements': [],
    'Testing': [],
    'Quick Reference': [],
    'Technical': [],
    'Implementation': [],
    'Change Logs': [],
    'Reports': [],
    'Other': []
  };
  
  ARCHIVE_FILES.forEach(file => {
    if (file.includes('REFACTOR')) categories['Refactoring'].push(file);
    else if (file.includes('ENHANCEMENT') || file.includes('PAYLOAD') || file.includes('SCHEMA-HARMONIZATION')) categories['Enhancements'].push(file);
    else if (file.includes('TEST')) categories['Testing'].push(file);
    else if (file.includes('QUICK')) categories['Quick Reference'].push(file);
    else if (file.includes('ID-') || file.includes('SWAGGER') || file.includes('AUTH') || file.includes('ARCHITECTURE')) categories['Technical'].push(file);
    else if (file.includes('IMPLEMENTATION') || file.includes('DYNAMIC') || file.includes('CLEANUP')) categories['Implementation'].push(file);
    else if (file.includes('CHANGE') || file.includes('UPGRADE')) categories['Change Logs'].push(file);
    else if (file.includes('REPORT') || file.includes('SUMMARY') || file.includes('EXECUTIVE')) categories['Reports'].push(file);
    else categories['Other'].push(file);
  });
  
  Object.entries(categories).forEach(([category, files]) => {
    if (files.length > 0) {
      index += `### ${category}\n\n`;
      files.forEach(file => {
        index += `- ${file}\n`;
      });
      index += '\n';
    }
  });
  
  index += '## How to Access\n\n';
  index += 'All information from these files has been consolidated into the new unified documentation.\n';
  index += 'If you need to reference the original files, they are preserved in this archive.\n';
  
  fs.writeFileSync(path.join(archivePath, 'ARCHIVE-INDEX.md'), index, 'utf8');
  console.log('\n✓ Created archive index: ARCHIVE-INDEX.md');
}

function generateCleanupReport() {
  const report = {
    timestamp: new Date().toISOString(),
    archivePath: archivePath,
    filesKept: KEEP_FILES.length,
    filesArchived: ARCHIVE_FILES.length,
    keptFiles: KEEP_FILES,
    archivedFiles: ARCHIVE_FILES,
    newDocumentation: [
      'START-HERE.md',
      'UNIFIED-PROJECT-DOCUMENTATION.md',
      'PROJECT-DOCUMENTATION-INDEX.md',
      'DOCUMENTATION-UNIFICATION-SUMMARY.md'
    ]
  };
  
  fs.writeFileSync(
    path.join(__dirname, 'cleanup-report.json'),
    JSON.stringify(report, null, 2),
    'utf8'
  );
  
  console.log('✓ Created cleanup report: cleanup-report.json\n');
}

// Main execution
try {
  console.log('📋 Files to keep: ' + KEEP_FILES.length);
  console.log('📦 Files to archive: ' + ARCHIVE_FILES.length + '\n');
  
  // Create archive directory
  createArchiveDirectory();
  
  // Archive old files
  console.log('📦 Archiving old documentation files...\n');
  let archivedCount = 0;
  
  ARCHIVE_FILES.forEach(file => {
    if (archiveFile(file)) {
      archivedCount++;
    }
  });
  
  // Generate archive index
  generateArchiveIndex();
  
  // Generate cleanup report
  generateCleanupReport();
  
  // Summary
  console.log('═'.repeat(60));
  console.log('  CLEANUP COMPLETE');
  console.log('═'.repeat(60));
  console.log(`\n✅ Successfully archived ${archivedCount} files`);
  console.log(`📁 Archive location: ${archivePath}`);
  console.log(`\n📚 Active Documentation (${KEEP_FILES.length} files):`);
  console.log('   • START-HERE.md');
  console.log('   • UNIFIED-PROJECT-DOCUMENTATION.md');
  console.log('   • PROJECT-DOCUMENTATION-INDEX.md');
  console.log('   • DOCUMENTATION-UNIFICATION-SUMMARY.md');
  console.log('   • README.md');
  console.log('   • + Configuration files\n');
  
  console.log('✨ Your documentation is now clean and organized!\n');
  
} catch (error) {
  console.error('\n❌ Error during cleanup:', error.message);
  process.exit(1);
}
