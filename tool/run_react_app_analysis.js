const fs = require('fs');
const path = require('path');
const { analyzeReactApp, saveReport } = require('./analyzeReact.js');

function runAppAnalysis() {
    const appDir = path.join(__dirname, '../my-react-app/src');
    const results = analyzeReactApp(appDir);

    const outputFile = path.join(appDir, 'react_app_security_report.json');
    saveReport(results, outputFile);
    console.log(`Results saved to ${outputFile}`);
}

runAppAnalysis();
