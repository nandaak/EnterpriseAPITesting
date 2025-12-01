@echo off
echo ================================================================
echo    RUNNING ENHANCED CREATE TESTS
echo ================================================================
echo.
echo This will run all CREATE tests with the enhanced schemas
echo.
echo Press Ctrl+C to cancel, or
pause

echo.
echo Running tests...
echo.

npm test -- --testNamePattern="CREATE" --verbose

echo.
echo ================================================================
echo    TEST EXECUTION COMPLETE
echo ================================================================
echo.
echo Check the results:
echo   - Console output above
echo   - test-results/enhanced-crud-results.json
echo   - html-report/test-report.html
echo.
pause
