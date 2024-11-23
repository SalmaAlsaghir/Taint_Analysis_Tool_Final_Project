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
        self.generic_visit(node)
        self.current_function = None

    def visit_Assign(self, node):
        # Check if the value is tainted
        value_is_tainted = self.is_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if value_is_tainted:
                    self.tainted_vars.add(target.id)
                elif target.id in self.tainted_vars:
                    self.tainted_vars.remove(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check for sources of taint
        if self.is_source(node):
            tainted_var = self.get_assigned_var(node)
            if tainted_var:
                self.tainted_vars.add(tainted_var)
        # Check for sinks
        elif self.is_sink(node):
            self.check_for_vulnerabilities(node)
        else:
            # Handle function calls
            func_name = self.get_function_name(node)
            if func_name and func_name in self.function_defs:
                # Visit the function definition
                if func_name not in self.visited_functions:
                    self.visited_functions.add(func_name)
                    original_tainted_vars = self.tainted_vars.copy()
                    self.visit(self.function_defs[func_name])
                    self.tainted_vars = original_tainted_vars
        self.generic_visit(node)

    def is_source(self, node):
        # Check if the call is a source of taint (e.g., request.GET.get)
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Attribute):
                if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == 'request':
                    if node.func.value.attr in ('GET', 'POST', 'COOKIES', 'META', 'session'):
                        return True
        return False

    def is_sink(self, node):
        # Check if the call is a sink (e.g., cursor.execute, os.system)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'cursor':
                return True
            if node.func.attr in ('system', 'popen', 'spawn', 'call', 'check_output') and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                return True
            # Check for deserialization functions like pickle.loads
            if isinstance(node.func.value, ast.Name) and node.func.value.id in ('pickle', 'cPickle', 'yaml'):
                if node.func.attr in ('load', 'loads', 'unsafe_load'):
                    return True
        elif isinstance(node.func, ast.Name):
            if node.func.id in ('HttpResponse', 'render', 'redirect', 'JsonResponse'):
                return True
        return False

    def check_for_vulnerabilities(self, node):
        # Check if any arguments are tainted
        for arg in node.args:
            if self.is_tainted(arg):
                vulnerability = self.get_vulnerability_type(node)
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
        elif isinstance(node, ast.Call):
            # Check if the result of a function call is tainted
            func_name = self.get_function_name(node)
            if func_name in self.function_defs:
                # Simplification: Assume function returns tainted data if it uses tainted data
                return True
            else:
                # If the function is a source, it may return tainted data
                if self.is_source(node):
                    return True
        elif isinstance(node, ast.Attribute):
            return self.is_tainted(node.value)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self.is_tainted(elt) for elt in node.elts)
        elif isinstance(node, ast.Dict):
            return any(self.is_tainted(k) or self.is_tainted(v) for k, v in zip(node.keys, node.values))
        elif isinstance(node, ast.Subscript):
            return self.is_tainted(node.value) or self.is_tainted(node.slice)
        return False

    def get_assigned_var(self, node):
        parent = getattr(node, 'parent', None)
        if isinstance(parent, ast.Assign):
            targets = parent.targets
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
        # Add parent references to nodes
        for child in ast.iter_child_nodes(node):
            child.parent = node
        super().generic_visit(node)

def analyze_django_file(file_path):
    analyzer = TaintAnalyzer(file_path)
    analyzer.analyze()
    return analyzer.results

def analyze_django_app():
    directory_path = '../my_django_project/vulnerabilities'  # Path to the Django app's views folder
    results = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            if file_name.endswith('.py'):
                file_path = os.path.join(root, file_name)
                file_results = analyze_django_file(file_path)
                results.extend(file_results)

    return results

def save_report(results, output_file):
    with open(output_file, 'w') as file:
        json.dump(results, file, indent=2)
    print(f"Report saved to {output_file}")

# Running the analysis
if __name__ == '__main__':
    output_report = 'django-security-report.json'
    results = analyze_django_app()
    save_report(results, output_report)
