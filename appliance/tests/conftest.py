"""Hermetic defaults for the appliance test suite.

egress_proxy resolves the allowlist / denylist / mode files from GATEWAY_ALLOWLIST_FILE / GATEWAY_DENYLIST_FILE /
GATEWAY_MODE_FILE (falling back to ~/.ossredact/{allowlist.txt,denylist.txt,mode}) AT IMPORT. Without this file a
developer box or a self-hosted CI runner with a populated ~/.ossredact makes the suite non-deterministic: a live
allowlist entry (e.g. the operator's own username 'alex') exempts the exact value a path-narrowing test asserts
is redacted -> false FAILURES, and -- more dangerous -- a real PII value that happens to be allowlisted can mask a
genuine redaction regression as a false PASS. Point every default at empty temp files (mode = privacy) BEFORE any
test module imports egress_proxy so the redaction guarantees are runner-independent.

conftest.py is imported before the test modules in its directory, so setting os.environ here (module level) runs
ahead of egress_proxy's import-time reads. `setdefault` means an explicit env (the documented hermetic recipe, or
CI) still wins, and individual tests that need a specific mode/allowlist keep monkeypatching egress_proxy._MODE_FILE
etc. (module attributes), which overrides these env defaults for that test. Maps-dir isolation is intentionally NOT
done here: test_egress_e2e / test_entity_map already point GATEWAY_MAPS_DIR at their own temp dirs.
"""
import atexit
import os
import shutil
import tempfile

_HERMETIC_DIR = tempfile.mkdtemp(prefix='ossredact-test-hermetic-')
_ALLOW = os.path.join(_HERMETIC_DIR, 'allowlist.txt')
_DENY = os.path.join(_HERMETIC_DIR, 'denylist.txt')
_MODE = os.path.join(_HERMETIC_DIR, 'mode')
open(_ALLOW, 'w').close()          # empty allowlist -> nothing exempted from redaction
open(_DENY, 'w').close()           # empty denylist -> no extra always-redact terms
with open(_MODE, 'w') as _fh:
    _fh.write('privacy\n')         # privacy mode -> the full floor + soft labels redact (strictest default)

os.environ.setdefault('GATEWAY_ALLOWLIST_FILE', _ALLOW)
os.environ.setdefault('GATEWAY_DENYLIST_FILE', _DENY)
os.environ.setdefault('GATEWAY_MODE_FILE', _MODE)

atexit.register(lambda: shutil.rmtree(_HERMETIC_DIR, ignore_errors=True))
