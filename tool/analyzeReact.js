const fs = require('fs');
const path = require('path');
const babelParser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const esquery = require('esquery');

// Function to analyze a single React file
function analyzeReactFile(filePath) {
    const code = fs.readFileSync(filePath, 'utf-8');

    // Parse the file using Babel parser with JSX support
    const ast = babelParser.parse(code, {
        sourceType: 'module',
        plugins: ['jsx', 'typescript', 'classProperties'],
    });

    const taintedVars = new Set();
    const stateVars = new Map(); // Map of state variable names to their setter functions
    const results = [];

    // First, perform taint analysis using traversal
    traverse(ast, {
        // Identify useState hooks and state variables
        VariableDeclarator(path) {
            const init = path.node.init;
            if (
                init &&
                init.type === 'CallExpression' &&
                init.callee.name === 'useState'
            ) {
                const stateVar = path.node.id.elements[0].name;
                const setterVar = path.node.id.elements[1].name;
                stateVars.set(setterVar, stateVar);
            }
        },

        // Identify assignments from event.target.value (taint sources)
        AssignmentExpression(path) {
            const left = path.node.left;
            const right = path.node.right;

            if (isEventTargetValue(right)) {
                if (left.type === 'Identifier') {
                    taintedVars.add(left.name);
                } else if (left.type === 'MemberExpression') {
                    const varName = getMemberExpressionName(left);
                    if (varName) {
                        taintedVars.add(varName);
                    }
                }
            }
        },

        // Handle calls to state setter functions
        CallExpression(path) {
            const callee = path.node.callee;
            const args = path.node.arguments;

            if (callee.type === 'Identifier' && stateVars.has(callee.name)) {
                const stateVar = stateVars.get(callee.name);
                if (args.length > 0 && (isTainted(args[0], taintedVars) || isEventTargetValue(args[0]))) {
                    taintedVars.add(stateVar);
                }
            }
        },
    });

    // Then, use esquery to find potential vulnerabilities
    const queries = [
        {
            name: "DangerouslySetInnerHTML",
            query: `JSXAttribute[name.name="dangerouslySetInnerHTML"]`,
            message: "Potential XSS vulnerability: dangerouslySetInnerHTML found.",
            checkTainted: true,
        },
        {
            name: "Eval Usage",
            query: `CallExpression[callee.name="eval"]`,
            message: "Potential security risk: Usage of eval detected.",
            checkTainted: true,
        },
        {
            name: "Direct DOM Manipulation",
            query: `MemberExpression[object.name=/window|document/]`,
            message: "Potential security risk: Direct DOM manipulation detected.",
            checkTainted: false,
        },
        // Add more queries as needed
    ];

    // Run each query
    queries.forEach((check) => {
        const matches = esquery(ast, check.query);

        matches.forEach((match) => {
            let isVulnerable = true;

            if (check.checkTainted) {
                // If taint checking is required, check if tainted data is involved
                if (match.type === 'CallExpression') {
                    // For functions like eval
                    isVulnerable = match.arguments.some(arg => isTainted(arg, taintedVars));
                } else if (match.type === 'JSXAttribute' && match.value && match.value.expression) {
                    // For dangerouslySetInnerHTML
                    isVulnerable = isTainted(match.value.expression, taintedVars);
                }
            }

            if (isVulnerable) {
                const location = match.loc
                    ? `Line ${match.loc.start.line}, Column ${match.loc.start.column}`
                    : "Location unavailable";
                console.log(`${check.message} Found in ${filePath} at ${location}`);
                results.push({
                    file: filePath,
                    check: check.name,
                    message: check.message,
                    line: match.loc?.start.line || null,
                    column: match.loc?.start.column || null,
                });
            }
        });
    });

    return results;
}

// Helper functions
function isEventTargetValue(node) {
    return (
        node.type === 'MemberExpression' &&
        node.object.type === 'MemberExpression' &&
        node.object.object.type === 'Identifier' &&
        node.object.object.name === 'event' &&
        node.object.property.name === 'target' &&
        node.property.name === 'value'
    );
}

function getMemberExpressionName(node) {
    if (node.type === 'Identifier') {
        return node.name;
    } else if (node.type === 'MemberExpression') {
        return getMemberExpressionName(node.object);
    }
    return null;
}

function isTainted(node, taintedVars) {
    if (!node) return false;
    if (node.type === 'Identifier') {
        return taintedVars.has(node.name);
    } else if (node.type === 'MemberExpression') {
        return isTainted(node.object, taintedVars);
    } else if (node.type === 'CallExpression') {
        return node.arguments.some(arg => isTainted(arg, taintedVars));
    } else if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
        return isTainted(node.left, taintedVars) || isTainted(node.right, taintedVars);
    } else if (node.type === 'ConditionalExpression') {
        return isTainted(node.test, taintedVars) || isTainted(node.consequent, taintedVars) || isTainted(node.alternate, taintedVars);
    } else if (node.type === 'ObjectExpression') {
        return node.properties.some(prop => isTainted(prop.value, taintedVars));
    } else if (node.type === 'ArrayExpression') {
        return node.elements.some(el => isTainted(el, taintedVars));
    }
    return false;
}

// Function to analyze all React files in the app
function analyzeReactApp() {
    const directoryPath = path.join(__dirname, '../my-react-app/src'); // Adjust the path as needed
    const results = [];

    // Recursively read files in the directory
    function readDirRecursive(dir) {
        const files = fs.readdirSync(dir);
        files.forEach(file => {
            const filePath = path.join(dir, file);
            const stat = fs.statSync(filePath);
            if (stat.isDirectory() && file !== 'node_modules') {
                readDirRecursive(filePath);
            } else if (file.endsWith('.js') || file.endsWith('.jsx') || file.endsWith('.ts') || file.endsWith('.tsx')) {
                const fileResults = analyzeReactFile(filePath);
                results.push(...fileResults);
            }
        });
    }

    readDirRecursive(directoryPath);

    return results;
}

// Save the results to a file
function saveReport(results, outputFilePath) {
    fs.writeFileSync(outputFilePath, JSON.stringify(results, null, 2));
    console.log(`Report saved to ${outputFilePath}`);
}

// Running the analysis
const outputReport = 'react-security-report.json'; // Path to save the report
const results = analyzeReactApp();
saveReport(results, outputReport);
