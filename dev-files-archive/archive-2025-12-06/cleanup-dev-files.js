const fs = require('fs');
const path = require('path');

/**
 * DEVELOPMENT FILES CLEANUP SCRIPT
 * 
 * Archives temporary scripts and files used during development
 * Keeps only essential files needed for testing
 */

console.log('\n🧹 Starting Development Files Cleanup...\n');

// Files to KEEP (essential for testing/config)
const KEEP_FILES = [
  // Package management
  'package.json',
  'package-lock.json',
  
  // Configuration
  'jest.config.js',
  'jest.config.failed-only.js',
  'jest.esm.config.js',
  'jest.setup.js',
  'babel.config.js',
  '.babelrc',
  
  // Setup/verification
  'setupTests.js',
  'verify-setup.js',
  
  // Token management (essential)
  'fetchToken.js',
  'check-token.js',
  'token.txt',
  
  // ID management (essential)
  'createdId.txt',
  
  // Environment
  '.env',
  '.env.example',
  
  // Git
  '.gitignore',
  
  // License
  'LICENSE',
  
  // Batch files (if used for running tests)
  'run.bat',
  'run-enhanced-tests.bat'
];

// Development/utility files to ARCHIVE
const ARCHIVE_FILES = [
  // Schema refactoring scripts
  'fix-schema-keys.js',
  'refactor-all-schemas.js',
  'refactor-all-schemas-enhanced.js',
  'refactor-test-files.js',
  'validate-schemas.js',
  'verify-refactoring.js',
  
  // Documentation scripts
  'cleanup-old-docs.js',
  'generate-unified-docs.js',
  
  // Debug scripts
  'debug-schema.js',
  'debug-token.js',
  'debug-token-issue.js',
  'debug-token-status.js',
  'fix-token-file.js',
  'test-token-directly.js',
  
  // Test analysis scripts
  'run-all-tests.js',
  'run-all-tests-with-report.js',
  'watch-failures.js',
  
  // Login/submit scripts
  'submitLogin.js',
  
  // Utility scripts
  'combine_files.cjs',
  
  // Large JSON reports (generated during development)
  'schema-refactoring-report.json',
  'schema-refactoring-final-report.json',
  'schema-key-fixes-log.json',
  'schema-validation-report.json',
  'schema-analysis-report.json',
  'complete-schema-mapping-report.json',
  
  // Test reports (generated)
  'test-refactoring-report.json',
  'test-error-analysis.json',
  'final-test-analysis.json',
  'failure_analysis.json',
  'failure_response.json',
  'failure_response_report.json',
  
  // Cleanup reports
  'cleanup-report.json',
  'refactoring-verification-report.json',
  
  // Documentation generation
  'unified-docs-summary.json',
  
  // Recommendations/analysis
  'payload-recommendations.json',
  'fix-summary.json',
  
  // Large Swagger files (can be regenerated)
  'swagger-api-docs.json',
  'swagger-parsed.json'
];

// Create archive directory
const archiveDir = path.join(__dirname, 'dev-files-archive');
const archiveTimestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0];
const archivePath = path.join(archiveDir, `archive-${archiveTimestamp}`);

function createArchiveDirectory() {
  if (!fs.existsSync(archiveDir)) {
    fs.mkdirSync(archiveDir, { recursive: true });
    console.log('✓ Created archive directory: dev-files-archive/');
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
      const stats = fs.statSync(sourcePath);
      const sizeKB = (stats.size / 1024).toFixed(2);
      
      // Copy to archive
      fs.copyFileSync(sourcePath, destPath);
      
      // Delete original
      fs.unlinkSync(sourcePath);
      
      console.log(`  ✓ Archived: ${filename} (${sizeKB} KB)`);
      return { success: true, size: stats.size };
    } catch (error) {
      console.log(`  ⚠️  Error archiving ${filename}: ${error.message}`);
      return { success: false, size: 0 };
    }
  }
  return { success: false, size: 0 };
}

function generateArchiveIndex() {
  let index = '# Archived Development Files\n\n';
  index += `**Archive Date**: ${new Date().toISOString()}\n\n`;
  index += '## Purpose\n\n';
  index += 'These files were used during project development for:\n';
  index += '- Schema refactoring and transformation\n';
  index += '- Documentation generation and unification\n';
  index += '- Testing and debugging\n';
  index += '- Analysis and reporting\n\n';
  index += 'They are no longer needed for the production testing framework.\n\n';
  index += '## Archived Files\n\n';
  
  const categories = {
    'Schema Refactoring Scripts': [],
    'Documentation Scripts': [],
    'Debug Scripts': [],
    'Test Analysis Scripts': [],
    'Utility Scripts': [],
    'JSON Reports': [],
    'Large Data Files': []
  };
  
  ARCHIVE_FILES.forEach(file => {
    if (file.includes('refactor') || file.includes('validate') || file.includes('verify')) {
      categories['Schema Refactoring Scripts'].push(file);
    } else if (file.includes('cleanup-old-docs') || file.includes('generate-unified')) {
      categories['Documentation Scripts'].push(file);
    } else if (file.includes('debug') || file.includes('test-token') || file.includes('fix-token')) {
      categories['Debug Scripts'].push(file);
    } else if (file.includes('run-all-tests') || file.includes('watch')) {
      categories['Test Analysis Scripts'].push(file);
    } else if (file.endsWith('.js') || file.endsWith('.cjs')) {
      categories['Utility Scripts'].push(file);
    } else if (file.includes('swagger')) {
      categories['Large Data Files'].push(file);
    } else if (file.endsWith('.json')) {
      categories['JSON Reports'].push(file);
    }
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
  
  index += '## How to Regenerate\n\n';
  index += 'If you need to regenerate any of these files:\n\n';
  index += '### Schema Files\n';
  index += '```bash\n';
  index += 'npm run swagger:advanced:fetch\n';
  index += 'npm run swagger:advanced:generate\n';
  index += 'npm run schema:production:ready\n';
  index += '```\n\n';
  index += '### Documentation\n';
  index += '```bash\n';
  index += 'node generate-unified-docs.js  # (if restored from archive)\n';
  index += '```\n\n';
  index += '### Reports\n';
  index += 'Reports are generated automatically when running tests.\n';
  
  fs.writeFileSync(path.join(archivePath, 'ARCHIVE-INDEX.md'), index, 'utf8');
  console.log('\n✓ Created archive index: ARCHIVE-INDEX.md');
}

function generateCleanupReport(archivedCount, totalSize) {
  const report = {
    timestamp: new Date().toISOString(),
    archivePath: archivePath,
    filesKept: KEEP_FILES.length,
    filesArchived: archivedCount,
    totalSizeArchived: `${(totalSize / 1024 / 1024).toFixed(2)} MB`,
    keptFiles: KEEP_FILES,
    archivedFiles: ARCHIVE_FILES.filter(f => {
      const sourcePath = path.join(__dirname, f);
      return !fs.existsSync(sourcePath); // Only list files that were actually archived
    }),
    purpose: 'Clean up development/utility files used during project creation',
    note: 'All essential testing and configuration files have been preserved'
  };
  
  fs.writeFileSync(
    path.join(__dirname, 'dev-cleanup-report.json'),
    JSON.stringify(report, null, 2),
    'utf8'
  );
  
  console.log('✓ Created cleanup report: dev-cleanup-report.json\n');
}

// Main execution
try {
  console.log('📋 Files to keep: ' + KEEP_FILES.length);
  console.log('📦 Files to archive: ' + ARCHIVE_FILES.length + '\n');
  
  // Create archive directory
  createArchiveDirectory();
  
  // Archive development files
  console.log('📦 Archiving development files...\n');
  let archivedCount = 0;
  let totalSize = 0;
  
  ARCHIVE_FILES.forEach(file => {
    const result = archiveFile(file);
    if (result.success) {
      archivedCount++;
      totalSize += result.size;
    }
  });
  
  // Generate archive index
  generateArchiveIndex();
  
  // Generate cleanup report
  generateCleanupReport(archivedCount, totalSize);
  
  // Summary
  console.log('═'.repeat(60));
  console.log('  CLEANUP COMPLETE');
  console.log('═'.repeat(60));
  console.log(`\n✅ Successfully archived ${archivedCount} files`);
  console.log(`💾 Total size archived: ${(totalSize / 1024 / 1024).toFixed(2)} MB`);
  console.log(`📁 Archive location: ${archivePath}`);
  console.log(`\n📚 Essential Files Kept (${KEEP_FILES.length}):`);
  console.log('   • Configuration files (Jest, Babel)');
  console.log('   • Package management (package.json)');
  console.log('   • Token management (fetchToken.js, check-token.js)');
  console.log('   • Setup/verification scripts');
  console.log('   • Environment files\n');
  
  console.log('✨ Your project root is now clean and organized!\n');
  
} catch (error) {
  console.error('\n❌ Error during cleanup:', error.message);
  process.exit(1);
}
