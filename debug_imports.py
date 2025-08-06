#!/home/sfdc_ops/python/bin/python
"""
Debug script to understand how Python imports work on your server
Run this from /edh/src/bin to see how the imports are resolved
"""

import sys
import os

print("=== Python Import Debug Information ===")
print()

print("1. Current working directory:")
print(f"   {os.getcwd()}")
print()

print("2. Python executable:")
print(f"   {sys.executable}")
print()

print("3. Python version:")
print(f"   {sys.version}")
print()

print("4. Python path (sys.path):")
for i, path in enumerate(sys.path):
    print(f"   [{i}] {path}")
print()

print("5. Environment variables:")
print(f"   PYTHONPATH: {os.environ.get('PYTHONPATH', 'Not set')}")
print(f"   PATH: {os.environ.get('PATH', 'Not set')}")
print()

print("6. Testing imports...")
try:
    import cyberark_edh_helper
    print(f"   ✓ cyberark_edh_helper imported successfully")
    print(f"   Location: {cyberark_edh_helper.__file__}")
except ImportError as e:
    print(f"   ✗ cyberark_edh_helper import failed: {e}")
print()

try:
    import edh_credentials_helper
    print(f"   ✓ edh_credentials_helper imported successfully")
    print(f"   Location: {edh_credentials_helper.__file__}")
except ImportError as e:
    print(f"   ✗ edh_credentials_helper import failed: {e}")
print()

try:
    import ops_helper
    print(f"   ✓ ops_helper imported successfully")
    print(f"   Location: {ops_helper.__file__}")
except ImportError as e:
    print(f"   ✗ ops_helper import failed: {e}")
print()

print("7. Checking for files in current directory:")
current_files = [f for f in os.listdir('.') if f.endswith('.py')]
helper_files = [f for f in current_files if any(helper in f for helper in ['cyberark', 'edh_credentials', 'ops_helper'])]
print(f"   Python files in current directory: {len(current_files)}")
print(f"   Helper files found: {helper_files}")
print()

print("8. Checking for files in ../util/bin:")
util_bin_path = os.path.join('..', 'util', 'bin')
if os.path.exists(util_bin_path):
    util_files = [f for f in os.listdir(util_bin_path) if f.endswith('.py')]
    helper_files_util = [f for f in util_files if any(helper in f for helper in ['cyberark', 'edh_credentials', 'ops_helper'])]
    print(f"   Python files in ../util/bin: {len(util_files)}")
    print(f"   Helper files found: {helper_files_util}")
else:
    print("   ../util/bin directory does not exist")
print()

print("9. Checking for symbolic links:")
for helper in ['cyberark_edh_helper.py', 'edh_credentials_helper.py', 'ops_helper.py']:
    if os.path.exists(helper):
        if os.path.islink(helper):
            target = os.readlink(helper)
            print(f"   {helper} -> {target} (symlink)")
        else:
            print(f"   {helper} (regular file)")
    else:
        print(f"   {helper} (not found)")
print()

print("10. Testing import with explicit path:")
try:
    sys.path.insert(0, os.path.join('..', 'util', 'bin'))
    import cyberark_edh_helper as test_import
    print(f"   ✓ Import from ../util/bin works")
    print(f"   Location: {test_import.__file__}")
except ImportError as e:
    print(f"   ✗ Import from ../util/bin failed: {e}")
print()

print("=== Debug Complete ===")