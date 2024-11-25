const fs = require('fs');
const path = require('path');
const { parse } = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const esquery = require('esquery');

//list of known sanitization functions
const sanitizationFunctions = ['DOMPurify.sanitize', 'sanitizeHtml', 'escapeHtml'];

//analyze a single React file
function analyzeReactFile(filePath) {
    const code = fs.readFileSync(filePath, 'utf-8');

    //parse the file using Babel parser with JSX support
    const ast = parse(code, {
        sourceType: 'module',
        plugins: ['jsx', 'typescript', 'classProperties'],
    });

    const taintedVars = new Set();
    const stateVars = new Map(); //map of setter functions to state variable names
    const results = [];

    //first, perform taint analysis using traversal
    traverse(ast, {
        //identify useState hooks and state variables
        VariableDeclarator(path) {
            const id = path.node.id;
            const init = path.node.init;

            //handle useState
            if (
                init &&
                init.type === 'CallExpression' &&
                init.callee.name === 'useState'
            ) {
                const stateVar = id.elements[0].name;
                const setterVar = id.elements[1].name;
                stateVars.set(setterVar, stateVar);
            }

            //propagate taint through variable declarations
            else if (init && isTainted(init, taintedVars)) {
                const varName = id.name;
                taintedVars.add(varName);
            }
        },

        //propagate taint
        AssignmentExpression(path) {
            const left = path.node.left;
            const right = path.node.right;

            //If RHS is tainted, LHS becomes tainted
            if (isTainted(right, taintedVars)) {
                const varName = getAssignedVarName(left);
                if (varName) {
                    taintedVars.add(varName);
                }
            }

            //If RHS is a taint source (event.target.value)
            if (isEventTargetValue(right)) {
                const varName = getAssignedVarName(left);
                if (varName) {
                    taintedVars.add(varName);
                }
            }
        },

        //handle calls to functions
        CallExpression(path) {
            const callee = path.node.callee;
            const args = path.node.arguments;

            //handle calls to state setter functions
            if (callee.type === 'Identifier' && stateVars.has(callee.name)) {
                const stateVar = stateVars.get(callee.name);
                if (args.length > 0) {
                    if (isTainted(args[0], taintedVars) || isEventTargetValue(args[0])) {
                        taintedVars.add(stateVar);
                    } else if (isSanitizationCall(args[0])) {
                        //remove from taintedVars if sanitized
                        taintedVars.delete(stateVar);
                    }
                }
            }

            //propagate taint through function calls (simplified)
            else if (callee.type === 'Identifier') {
                const funcName = callee.name;
                //if function is known to sanitize, remove taint
                if (sanitizationFunctions.includes(funcName)) {
                    const varName = getAssignedVarName(path.parent);
                    if (varName && taintedVars.has(varName)) {
                        taintedVars.delete(varName);
                    }
                }
                //i assumed for now functions return tainted data if any argument is tainted
                else {
                    const varName = getAssignedVarName(path.parent);
                    if (varName && args.some(arg => isTainted(arg, taintedVars))) {
                        taintedVars.add(varName);
                    }
                }
            }
        },
    });

    //then, use esquery to find potential vulnerabilities
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
            query: `AssignmentExpression[left.object.name=/window|document/]`,
            message: "Potential security risk: Direct DOM manipulation detected.",
            checkTainted: true, 
        },
        {
            name: "Unsafe setTimeout",
            query: `CallExpression[callee.name="setTimeout"]`,
            message: "Potential security risk: setTimeout with string argument detected.",
            checkTainted: false,
        },
        {
            name: "Dynamic Script Injection",
            query: `AssignmentExpression[left.property.name="src"]`,
            message: "Potential security risk: Dynamic script src assignment detected.",
            checkTainted: true,
        },
        
    ];

    //run each query
    queries.forEach((check) => {
        const matches = esquery(ast, check.query);

        matches.forEach((match) => {
            let isVulnerable = true;

            if (check.checkTainted) {
                //If taint checking is required, check if tainted data is involved
                if (match.type === 'CallExpression') {
                    // For functions like eval
                    isVulnerable = match.arguments.some(arg => isTainted(arg, taintedVars));
                } else if (match.type === 'JSXAttribute' && match.value && match.value.expression) {
                    //for dangerouslySetInnerHTML
                    isVulnerable = isTainted(match.value.expression, taintedVars);
                } else if (match.type === 'AssignmentExpression') {
                    //for assignments, check if RHS is tainted
                    isVulnerable = isTainted(match.right, taintedVars);
                }
            } else {
                //for setTimeout with string argument
                if (check.name === "Unsafe setTimeout") {
                    const firstArg = match.arguments[0];
                    if (firstArg.type === 'StringLiteral' || (firstArg.type === 'Literal' && typeof firstArg.value === 'string')) {
                        isVulnerable = true;
                    } else {
                        isVulnerable = false;
                    }
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

//helper functions
function isEventTargetValue(node) {
    return (
        node.type === 'MemberExpression' &&
        node.object.type === 'MemberExpression' &&
        node.object.object.type === 'Identifier' &&
        ['event', 'e'].includes(node.object.object.name) &&
        node.object.property.name === 'target' &&
        node.property.name === 'value'
    );
}

function getAssignedVarName(node) {
    if (!node) return null;
    if (node.type === 'Identifier') {
        return node.name;
    } else if (node.type === 'MemberExpression') {
        return getMemberExpressionName(node);
    } else if (node.type === 'VariableDeclarator') {
        return node.id.name;
    }
    return null;
}

function getMemberExpressionName(node) {
    if (node.type === 'Identifier') {
        return node.name;
    } else if (node.type === 'MemberExpression') {
        return getMemberExpressionName(node.object);
    }
    return null;
}

function isSanitizationCall(node) {
    if (node.type === 'CallExpression') {
        const calleeName = getFullCalleeName(node.callee);
        return sanitizationFunctions.includes(calleeName);
    }
    return false;
}

function getFullCalleeName(callee) {
    if (callee.type === 'Identifier') {
        return callee.name;
    } else if (callee.type === 'MemberExpression') {
        return `${getFullCalleeName(callee.object)}.${callee.property.name}`;
    }
    return '';
}

function isTainted(node, taintedVars) {
    if (!node) return false;
    if (node.type === 'Identifier') {
        return taintedVars.has(node.name);
    } else if (node.type === 'MemberExpression') {
        return isTainted(node.object, taintedVars);
    } else if (node.type === 'CallExpression') {
        //if the call is to a sanitization function, return false
        if (isSanitizationCall(node)) {
            return false;
        }
        //assume function returns tainted data if any argument is tainted
        return node.arguments.some(arg => isTainted(arg, taintedVars));
    } else if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression') {
        return isTainted(node.left, taintedVars) || isTainted(node.right, taintedVars);
    } else if (node.type === 'ConditionalExpression') {
        return isTainted(node.test, taintedVars) || isTainted(node.consequent, taintedVars) || isTainted(node.alternate, taintedVars);
    } else if (node.type === 'ObjectExpression') {
        return node.properties.some(prop => isTainted(prop.value, taintedVars));
    } else if (node.type === 'ArrayExpression') {
        return node.elements.some(el => isTainted(el, taintedVars));
    } else if (node.type === 'Literal') {
        return false;
    } else if (node.type === 'TemplateLiteral') {
        return node.expressions.some(expr => isTainted(expr, taintedVars));
    }
    return false;
}

//function to analyze all React files in the app
function analyzeReactApp(directoryPath) {
    const results = [];

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

function saveReport(results, outputFilePath) {
    fs.writeFileSync(outputFilePath, JSON.stringify(results, null, 2));
    console.log(`Report saved to ${outputFilePath}`);
}

module.exports = { analyzeReactFile, analyzeReactApp, saveReport };
