cd D:\MicrotecSaud\Jest-Api-testing-project
npx rimraf allure-results allure-report coverage
npx jest tests/setup-verification.test.js --config=jest.config.js
npm run test:allure
npm run allure:generate
npm run allure:open