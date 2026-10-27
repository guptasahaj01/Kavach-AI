import sys
import os
import tempfile

# API tests must never append security events to the operator's application DB.
_test_store = tempfile.TemporaryDirectory(prefix="kavach-tests-")
os.environ["KAVACH_DB_PATH"] = os.path.join(_test_store.name, "audit.sqlite")

# Ensure project root is in sys.path for test discovery
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
