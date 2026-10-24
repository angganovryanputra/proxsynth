import os
import sys
CURRENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import re
import glob
from backend.app import app

backend_routes = set()
for r in app.routes:
    backend_routes.add(r.path)
    # also add with param placeholders converted to regex
    p = re.sub(r'\{[^}]+\}', '*', r.path)
    backend_routes.add(p)

frontend_calls = set()
for f in glob.glob('frontend/**/*.js', recursive=True) + ['frontend/index.html']:
    with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
        content = fp.read()
    for m in re.finditer(r'[\'\x60\"](/api/[^\'\x60\"\s\?]+)', content):
        frontend_calls.add(m.group(1))

print(f"Total frontend API endpoints detected: {len(frontend_calls)}")
missing = []
for ep in sorted(frontend_calls):
    # Separate path from query string if any
    raw_path = ep.split('?')[0]
    norm = re.sub(r'\$\{[^}]+\}', '*', raw_path)
    norm = re.sub(r'\$[^/]+', '*', norm)
    # If ends with * because of ${param} query string attached directly without ? or with ?
    if norm.endswith('*') and not any(r.path.endswith('*') for r in app.routes):
        base_norm = norm.rstrip('*')
    else:
        base_norm = norm

    matched = False
    for br in backend_routes:
        if br == base_norm or br == base_norm.rstrip('/'):
            matched = True
            break
        pattern = '^' + re.escape(br).replace(r'\*', r'[^/]+') + '$'
        if re.match(pattern, base_norm):
            matched = True
            break
    if not matched:
        missing.append((ep, base_norm))

if missing:
    print(f"Found {len(missing)} missing or mismatched endpoints:")
    for ep, norm in missing:
        print(f"  - {ep} (normalized: {norm})")
else:
    print("All frontend API endpoints matched with backend routes!")
