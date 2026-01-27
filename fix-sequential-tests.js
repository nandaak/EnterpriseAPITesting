// fix-sequential-tests.js - Fix sequential test execution
const fs = require('fs');

let content = fs.readFileSync('tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js', 'utf8');

// Fix PHASE 4 (POST-UPDATE VIEW)
content = content.replace(
  /test\(\s*"🎯 \[PHASE 4\/6\] VIEW - Verify the updates were applied successfully",\s*async \(\) => \{\s*try \{\s*testContext\.lifecyclePhase = "VIEW_POST_UPDATE";\s*testContext\.operation = "VIEW_POST_UPDATE";\s*if \(!moduleOverallSuccess\) \{/,
  `test(
              "🎯 [PHASE 4/6] VIEW - Verify the updates were applied successfully",
              async () => {
                // Check if previous phase failed - if so, skip this test
                if (!moduleOverallSuccess || !hasValidCreateOperation || !createdResourceId) {
                  testContext.wasSkipped = true;
                  crudTestSummary.skippedTests++;
                  logger.warn(
                    \`⏸️ \${fullModuleName} - POST-UPDATE VIEW skipped: Previous phase failed or no resource ID\`
                  );
                  return;
                }

                try {
                  testContext.lifecyclePhase = "VIEW_POST_UPDATE";
                  testContext.operation = "VIEW_POST_UPDATE";

                  if (false) {`
);

// Fix PHASE 5 (DELETE)
content = content.replace(
  /test\(\s*"🎯 \[PHASE 5\/6\] DELETE - Remove the resource from the system",\s*async \(\) => \{\s*try \{\s*testContext\.lifecyclePhase = "DELETE";\s*testContext\.operation = "DELETE";\s*if \(!moduleOverallSuccess\) \{/,
  `test(
              "🎯 [PHASE 5/6] DELETE - Remove the resource from the system",
              async () => {
                // Check if previous phase failed - if so, skip this test
                if (!moduleOverallSuccess || !hasValidCreateOperation || !createdResourceId) {
                  testContext.wasSkipped = true;
                  crudTestSummary.skippedTests++;
                  logger.warn(
                    \`⏸️ \${fullModuleName} - DELETE skipped: Previous phase failed or no resource ID\`
                  );
                  return;
                }

                try {
                  testContext.lifecyclePhase = "DELETE";
                  testContext.operation = "DELETE";

                  if (false) {`
);

// Fix PHASE 6 (NEGATIVE VIEW)
content = content.replace(
  /test\(\s*"🎯 \[PHASE 6\/6\] NEGATIVE VIEW - Verify resource no longer exists \(404 Test\)",\s*async \(\) => \{\s*try \{\s*testContext\.lifecyclePhase = "NEGATIVE_VIEW";\s*testContext\.operation = "NEGATIVE_VIEW";\s*if \(!moduleOverallSuccess\) \{/,
  `test(
              "🎯 [PHASE 6/6] NEGATIVE VIEW - Verify resource no longer exists (404 Test)",
              async () => {
                // Check if previous phase failed - if so, skip this test
                if (!moduleOverallSuccess || !hasValidCreateOperation || !createdResourceId) {
                  testContext.wasSkipped = true;
                  crudTestSummary.skippedTests++;
                  logger.warn(
                    \`⏸️ \${fullModuleName} - NEGATIVE VIEW skipped: Previous phase failed or no resource ID\`
                  );
                  return;
                }

                try {
                  testContext.lifecyclePhase = "NEGATIVE_VIEW";
                  testContext.operation = "NEGATIVE_VIEW";

                  if (false) {`
);

fs.writeFileSync('tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js', content);
console.log('✅ Fixed sequential test execution for phases 4, 5, and 6');
