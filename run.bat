@echo off
cd /d D:\MicrotecSaud\Jest-Api-testing-project

echo Running Test Suite 1: CRUD Validation
call npx jest tests/comprehensive-lifecycle/1.comprehensive-CRUD-Validation.test.js --config=jest.config.js

echo.
echo Running Test Suite 2: API Security
call npx jest tests/comprehensive-lifecycle/2.comprehensive-API-Security.test.js --config=jest.config.js

echo.
echo Running Test Suite 3: Advanced Security Testing
call npx jest tests/comprehensive-lifecycle/3.Advanced-Security-Testing.test.js --config=jest.config.js

echo.
echo Running Test Suite 4: Performance and Malicious Load
call npx jest tests/comprehensive-lifecycle/4.Performance-Malicious-Load.test.js --config=jest.config.js

echo.
echo Running Test Suite 5: API Health Checks
call npx jest tests/comprehensive-lifecycle/5.API-Health-Checks.test.js --config=jest.config.js

echo.
echo All test suites completed!
pause