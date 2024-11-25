const fs = require('fs');
const path = require('path');
const { analyzeReactApp, saveReport } = require('./analyzeReact.js');

function runTests() {
    const testSuiteDir = path.join(__dirname, '../react_test_suite');
    const results = analyzeReactApp(testSuiteDir);

    const outputFile = path.join(testSuiteDir, 'react_test_results.json');
    saveReport(results, outputFile);
    console.log(`Results saved to ${outputFile}`);
}

runTests();
