// jest.config.failed-only.js
module.exports = {
  ...require("./jest.config.js"),
  reporters: [
    "default",
    [
      "jest-html-reporters",
      {
        publicPath: "./html-report",
        filename: "failed-tests-report.html",
        pageTitle: "Failed Tests Report",
        expand: false,
        hideIcon: true,
        includeFailureMsg: true,
        includeSuiteFailure: true,
        includeConsoleLog: true,
        includeStackTrace: true,
        // Focus on failures
        displaySuiteNumber: true,
        customInfos: [
          { title: "Report Type", value: "Failed Tests Only" },
          { title: "Generated", value: new Date().toISOString() },
        ],
      },
    ],
  ],
  bail: 0, // Don't bail to see all failures
  verbose: true,
};
