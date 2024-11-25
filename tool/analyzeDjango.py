import os
import ast
import json

class TaintAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.tainted_vars = set()
        self.results = []
        self.current_function = None
        self.function_defs = {}
        self.call_graph = {}
        self.visited_functions = set()
        self.sanitization_functions = {'escape', 'clean', 'sanitize_input'}

    def analyze(self):
        with open(self.file_path, 'r') as file:
            code = file.read()
        self.tree = ast.parse(code)
        self.collect_function_defs()
        self.visit(self.tree)

    def collect_function_defs(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                self.function_defs[node.name] = node

    def visit_FunctionDef(self, node):
        self.current_function = node.name
        self.tainted_vars_in_scope = set()
        self.generic_visit(node)
        self.current_function = None

    def visit_Assign(self, node):
        #we check if the value is tainted
        value_is_tainted = self.is_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if value_is_tainted:
                    self.tainted_vars.add(var_name)
                elif var_name in self.tainted_vars:
                    self.tainted_vars.remove(var_name)
        self.generic_visit(node)

    def visit_Call(self, node):
        #check for sources of taint
        if self.is_source(node):
            tainted_var = self.get_assigned_var(node)
            if tainted_var:
                self.tainted_vars.add(tainted_var)
        #check for sinks
        elif self.is_sink(node):
            self.check_for_vulnerabilities(node)
        else:
            #function calls
            func_name = self.get_function_name(node)
            if func_name in self.sanitization_functions:
                #mark the variable as sanitized
                tainted_var = self.get_assigned_var(node)
                if tainted_var and tainted_var in self.tainted_vars:
                    self.tainted_vars.remove(tainted_var)
            elif func_name and func_name in self.function_defs:
                #visit the function definition
                if func_name not in self.visited_functions:
                    self.visited_functions.add(func_name)
                    original_tainted_vars = self.tainted_vars.copy()
                    self.visit(self.function_defs[func_name])
                    self.tainted_vars = original_tainted_vars
        self.generic_visit(node)

    def is_source(self, node):
        #check for request.GET.get('param') pattern
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'get':
            if isinstance(node.func.value, ast.Attribute) and node.func.value.attr in ('GET', 'POST', 'COOKIES', 'META', 'session'):
                if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == 'request':
                    return True
        return False

    def is_sink(self, node):
        #chec if the call is a sink (such asursor.execute, os.system)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'cursor':
                return True
            if node.func.attr in ('system', 'popen', 'spawn', 'call', 'check_output') and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                return True
            #deserialization functions like pickle.loads
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ('pickle', 'cPickle', 'yaml'):
                if node.func.attr in ('load', 'loads', 'unsafe_load'):
                    return True
        elif isinstance(node.func, ast.Name):
            if node.func.id == 'HttpResponse':
                return True
        return False

    def check_for_vulnerabilities(self, node):
        vulnerability = self.get_vulnerability_type(node)
        if vulnerability == 'SQL Injection':
            #handling SQL Injection differently
            if node.args:
                query_arg = node.args[0]
                if self.is_tainted(query_arg):
                    #query string is tainted - vulnerable
                    self.results.append({
                        "file": self.file_path,
                        "check": vulnerability,
                        "message": "Potential SQL Injection detected due to tainted query string.",
                        "line": node.lineno,
                        "column": node.col_offset,
                    })
        else:
            #other vulnerabilities, check if any arguments are tainted
            for arg in node.args:
                if self.is_tainted(arg) and not self.is_sanitized(arg):
                    self.results.append({
                        "file": self.file_path,
                        "check": vulnerability,
                        "message": f"Potential {vulnerability} detected.",
                        "line": node.lineno,
                        "column": node.col_offset,
                    })

    def is_tainted(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.BinOp):
            return self.is_tainted(node.left) or self.is_tainted(node.right)
        elif isinstance(node, ast.JoinedStr):
            #f-strings
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if self.is_tainted(value.value):
                        return True
            return False
        elif isinstance(node, ast.Call):
            func_name = self.get_function_name(node)
            if func_name in self.sanitization_functions:
                return False  #is sanitized
            elif func_name in self.function_defs:
                #simplification: asume function returns tainted data if it uses tainted data
                return True
            elif self.is_source(node):
                return True
        elif isinstance(node, ast.Attribute):
            return self.is_tainted(node.value)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.is_tainted(elt) for elt in node.elts)
        elif isinstance(node, ast.Dict):
            return any(self.is_tainted(k) or self.is_tainted(v) for k, v in zip(node.keys, node.values))
        elif isinstance(node, ast.Subscript):
            return self.is_tainted(node.value) or self.is_tainted(node.slice)
        elif isinstance(node, ast.Constant):
            return False  #constants are not tainted
        return False

    def is_sanitized(self, node):
        #check if the node represents a call to a sanitization function
        if isinstance(node, ast.Call):
            func_name = self.get_function_name(node)
            if func_name in self.sanitization_functions:
                return True
        return False

    def get_assigned_var(self, node):
        parent = getattr(node, 'parent', None)
        if isinstance(parent, ast.Assign):
            targets = parent.targets
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                return targets[0].id
        elif isinstance(parent, (ast.Call, ast.Expr)):
            grandparent = getattr(parent, 'parent', None)
            if isinstance(grandparent, ast.Assign):
                targets = grandparent.targets
                if len(targets) == 1 and isinstance(targets[0], ast.Name):
                    return targets[0].id
        return None

    def get_function_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def get_vulnerability_type(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute':
                return 'SQL Injection'
            elif node.func.attr in ('system', 'popen', 'spawn', 'call', 'check_output'):
                return 'Command Injection'
            elif isinstance(node.func.value, ast.Name) and node.func.value.id in ('pickle', 'cPickle', 'yaml'):
                if node.func.attr in ('load', 'loads', 'unsafe_load'):
                    return 'Insecure Deserialization'
        elif isinstance(node.func, ast.Name):
            if node.func.id == 'HttpResponse':
                return 'XSS'
        return 'Unknown Vulnerability'

    def generic_visit(self, node):
        #add parent references to nodes
        for child in ast.iter_child_nodes(node):
            child.parent = node
        super().generic_visit(node)

def analyze_django_file(file_path):
    analyzer = TaintAnalyzer(file_path)
    analyzer.analyze()
    return analyzer.results

def analyze_django_app(directory_path):
    results = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            if file_name.endswith('.py'):
                file_path = os.path.join(root, file_name)
                print(f"Analyzing {file_path}")
                file_results = analyze_django_file(file_path)
                results.extend(file_results)

    return results

def save_report(results, output_file):
    with open(output_file, 'w') as file:
        json.dump(results, file, indent=2)
    print(f"Report saved to {output_file}")
