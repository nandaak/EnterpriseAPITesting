# Archived Development Files

**Archive Date**: 2025-12-06T14:11:55.009Z

## Purpose

These files were used during project development for:
- Schema refactoring and transformation
- Documentation generation and unification
- Testing and debugging
- Analysis and reporting

They are no longer needed for the production testing framework.

## Archived Files

### Schema Refactoring Scripts

- refactor-all-schemas.js
- refactor-all-schemas-enhanced.js
- refactor-test-files.js
- validate-schemas.js
- verify-refactoring.js
- schema-refactoring-report.json
- schema-refactoring-final-report.json
- test-refactoring-report.json
- refactoring-verification-report.json

### Documentation Scripts

- cleanup-old-docs.js
- generate-unified-docs.js

### Debug Scripts

- debug-schema.js
- debug-token.js
- debug-token-issue.js
- debug-token-status.js
- fix-token-file.js
- test-token-directly.js

### Test Analysis Scripts

- run-all-tests.js
- run-all-tests-with-report.js
- watch-failures.js

### Utility Scripts

- fix-schema-keys.js
- submitLogin.js
- combine_files.cjs

### JSON Reports

- schema-key-fixes-log.json
- schema-validation-report.json
- schema-analysis-report.json
- complete-schema-mapping-report.json
- test-error-analysis.json
- final-test-analysis.json
- failure_analysis.json
- failure_response.json
- failure_response_report.json
- cleanup-report.json
- unified-docs-summary.json
- payload-recommendations.json
- fix-summary.json

### Large Data Files

- swagger-api-docs.json
- swagger-parsed.json

## How to Regenerate

If you need to regenerate any of these files:

### Schema Files
```bash
npm run swagger:advanced:fetch
npm run swagger:advanced:generate
npm run schema:production:ready
```

### Documentation
```bash
node generate-unified-docs.js  # (if restored from archive)
```

### Reports
Reports are generated automatically when running tests.

### Cleanup Scripts

- cleanup-dev-files.js
- cleanup-old-docs.js
- finalize-cleanup.js
