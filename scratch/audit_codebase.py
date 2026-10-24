import os
import sys
import ast
import glob

CURRENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

py_files = glob.glob('backend/**/*.py', recursive=True) + glob.glob('mcp_core/**/*.py', recursive=True) + ['mcp_server.py', 'proxsynth_client.py']
print(f"Scanning {len(py_files)} Python files for syntax errors and import errors...")

import_errors = []
for f in py_files:
    try:
        with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
            source = fp.read()
        ast.parse(source, filename=f)
    except SyntaxError as e:
        print(f"SYNTAX ERROR in {f}: {e}")

# Try importing backend modules
for f in py_files:
    if 'scratch' in f or 'test_' in f or '__init__' in f:
        continue
    rel = os.path.relpath(f, CURRENT_DIR).replace('\\', '/').replace('.py', '')
    mod_name = rel.replace('/', '.')
    try:
        __import__(mod_name)
    except Exception as e:
        import_errors.append((mod_name, str(e)))

if import_errors:
    print(f"\nImport failures ({len(import_errors)}):")
    for m, err in import_errors:
        print(f"  - {m}: {err}")
else:
    print("\nAll modules imported without exceptions!")
