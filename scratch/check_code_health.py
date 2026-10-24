import ast
import glob
import os
import builtins

CURRENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
builtin_names = set(dir(builtins)) | {
    "__file__", "__name__", "__doc__", "__package__", "Exception", "BaseException"
}

py_files = glob.glob(os.path.join(CURRENT_DIR, 'backend/**/*.py'), recursive=True) + \
           glob.glob(os.path.join(CURRENT_DIR, 'mcp_core/**/*.py'), recursive=True) + \
           [os.path.join(CURRENT_DIR, 'mcp_server.py')]

potential_name_errors = []

class ScopeVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.scopes = [set(builtin_names)]
        self.undefined = []

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name.split('.')[0]
            self.scopes[-1].add(name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name == '*':
                # can't statically know
                pass
            else:
                name = alias.asname or alias.name
                self.scopes[-1].add(name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.scopes[-1].add(node.name)
        # new scope
        fn_scope = set()
        for arg in node.args.args + node.args.kwonlyargs:
            fn_scope.add(arg.arg)
        if node.args.vararg:
            fn_scope.add(node.args.vararg.arg)
        if node.args.kwarg:
            fn_scope.add(node.args.kwarg.arg)
        self.scopes.append(fn_scope)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        self.scopes[-1].add(node.name)
        self.scopes.append(set())
        self.generic_visit(node)
        self.scopes.pop()

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.scopes[-1].add(node.id)
        elif isinstance(node.ctx, ast.Load):
            # Check if name is defined in any enclosing scope
            is_defined = any(node.id in s for s in self.scopes)
            if not is_defined:
                # ignore type annotations or forward references if common
                if node.id not in ["Optional", "Dict", "List", "Any", "Union", "Tuple", "Set", "Callable"]:
                    self.undefined.append((node.id, node.lineno))

for filepath in py_files:
    relpath = os.path.relpath(filepath, CURRENT_DIR)
    with open(filepath, 'r', encoding='utf-8') as f:
        code = f.read()
    try:
        tree = ast.parse(code, filename=filepath)
        v = ScopeVisitor(relpath)
        v.visit(tree)
        # filter out names defined later in module or common decorators
        true_undefined = []
        for name, line in v.undefined:
            # check if name was eventually added to global scope (forward ref in func)
            if name not in v.scopes[0]:
                true_undefined.append((name, line))
        if true_undefined:
            potential_name_errors.append((relpath, true_undefined))
    except Exception as e:
        print(f"Error checking {relpath}: {e}")

print(f"Potential undefined name candidates: {len(potential_name_errors)}")
for rel, items in potential_name_errors:
    print(f"\n{rel}:")
    for name, line in items[:5]:
        print(f"  Line {line}: {name}")
