const fs = require('fs');
const path = require('path');

/**
 * UNIFIED DOCUMENTATION GENERATOR
 * 
 * Consolidates all project markdown files into one comprehensive document
 */

console.log('\n🚀 Generating Unified Project Documentation...\n');

// Main sections to include
const sections = {
  overview: {
    title: '📋 Project Overview',
    files: ['README.md'],
    priority: 1
  },
  refactoring: {
    title: '🔄 Schema Refactoring',
    files: [
      'MASTER-REFACTORING-REPORT.md',
      'SCHEMA-TRANSFORMATION-GUIDE.md',
      'SCHEMA-REFACTORING-SUMMARY.md'
    ],
    priority: 2
  },
  enhancements: {
    title: '⭐ Feature Enhancements',
    files: [
      'MASTER-ENHANCEMENT-SUMMARY.md',
      'COMPREHENSIVE-ERP-API-ENHANCEMENT-GUIDE.md',
      'PAYLOAD-ENHANCEMENT-COMPLETE.md',
      'SCHEMA-HARMONIZATION-COMPLETE.md'
    ],
    priority: 3
  },
  testing: {
    title: '🧪 Testing Framework',
    files: [
      'TEST-REFACTORING-COMPLETE.md',
      'TESTING-ENHANCEMENT-COMPLETE.md',
      'ENHANCED-TESTING-GUIDE.md'
    ],
    priority: 4
  },
  guides: {
    title: '📚 Quick Reference Guides',
    files: [
      'QUICK-START-GUIDE.md',
      'QUICK-REFERENCE-CARD.md',
      'QUICK-ERP-API-REFERENCE.md'
    ],
    priority: 5
  },
  technical: {
    title: '🛠️ Technical Documentation',
    files: [
      'ID-REGISTRY-SYSTEM-GUIDE.md',
      'ID-TYPE-MANAGEMENT-GUIDE.md',
      'SWAGGER-INTEGRATION-GUIDE.md',
      'AUTHENTICATION-GUIDE.md'
    ],
    priority: 6
  }
};

// Generate table of contents
function generateTOC(sections) {
  let toc = '## 📑 Table of Contents\n\n';
  
  Object.entries(sections)
    .sort((a, b) => a[1].priority - b[1].priority)
    .forEach(([key, section]) => {
      const anchor = section.title.toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-');
      toc += `${section.priority}. [${section.title}](#${anchor})\n`;
    });
  
  return toc + '\n---\n\n';
}

// Read and process file
function processFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      console.log(`⚠️  File not found: ${filePath}`);
      return null;
    }
    
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Remove title if it's the first line
    content = content.replace(/^#\s+.*\n/, '');
    
    // Adjust heading levels (increase by 1)
    content = content.replace(/^(#{1,5})\s/gm, '#$1 ');
    
    return content;
  } catch (error) {
    console.log(`❌ Error reading ${filePath}: ${error.message}`);
    return null;
  }
}

// Generate unified document
function generateUnifiedDoc() {
  let output = '';
  
  // Header
  output += '# 🚀 Complete Enterprise ERP API Testing Framework\n\n';
  output += '**Unified Documentation**\n\n';
  output += `**Version**: 3.0\n`;
  output += `**Last Updated**: ${new Date().toISOString().split('T')[0]}\n`;
  output += `**Status**: ✅ Production Ready\n\n`;
  output += '---\n\n';
  
  // Table of Contents
  output += generateTOC(sections);
  
  // Process each section
  Object.entries(sections)
    .sort((a, b) => a[1].priority - b[1].priority)
    .forEach(([key, section]) => {
      console.log(`\n📝 Processing: ${section.title}`);
      
      output += `\n\n# ${section.title}\n\n`;
      output += '---\n\n';
      
      section.files.forEach(file => {
        const filePath = path.join(__dirname, file);
        const content = processFile(filePath);
        
        if (content) {
          console.log(`   ✓ Added: ${file}`);
          output += `\n## From: ${file}\n\n`;
          output += content;
          output += '\n\n---\n\n';
        }
      });
    });
  
  // Footer
  output += '\n\n---\n\n';
  output += '## 📞 Support & Contact\n\n';
  output += 'For questions, issues, or contributions:\n\n';
  output += '- Review this comprehensive documentation\n';
  output += '- Check troubleshooting sections\n';
  output += '- Examine test reports and logs\n';
  output += '- Verify configuration and setup\n\n';
  output += '---\n\n';
  output += `**Generated**: ${new Date().toISOString()}\n`;
  output += '**Framework**: Enterprise ERP API Testing\n';
  output += '**Status**: ✅ Production Ready\n';
  
  return output;
}

// Main execution
try {
  console.log('Starting documentation generation...\n');
  
  const unifiedDoc = generateUnifiedDoc();
  
  const outputPath = path.join(__dirname, 'UNIFIED-PROJECT-DOCUMENTATION.md');
  fs.writeFileSync(outputPath, unifiedDoc, 'utf8');
  
  const stats = fs.statSync(outputPath);
  const sizeKB = (stats.size / 1024).toFixed(2);
  
  console.log('\n✅ Documentation generated successfully!');
  console.log(`📄 File: UNIFIED-PROJECT-DOCUMENTATION.md`);
  console.log(`📊 Size: ${sizeKB} KB`);
  console.log(`📝 Lines: ${unifiedDoc.split('\n').length}`);
  
  // Generate summary
  const summary = {
    generated: new Date().toISOString(),
    outputFile: 'UNIFIED-PROJECT-DOCUMENTATION.md',
    size: `${sizeKB} KB`,
    lines: unifiedDoc.split('\n').length,
    sections: Object.keys(sections).length,
    filesProcessed: Object.values(sections).reduce((sum, s) => sum + s.files.length, 0)
  };
  
  fs.writeFileSync(
    path.join(__dirname, 'unified-docs-summary.json'),
    JSON.stringify(summary, null, 2),
    'utf8'
  );
  
  console.log('\n📊 Summary saved to: unified-docs-summary.json\n');
  
} catch (error) {
  console.error('\n❌ Error generating documentation:', error.message);
  process.exit(1);
}
