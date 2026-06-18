"""Security-focused tests for appliance/entity_map.py.

The entity map stores the original values used for response rehydration. Its files must stay local-only:
directory traversal metadata should be private, the AES key must be 0600, and encrypted map blobs must be 0600.
"""
import os
import stat
import base64
import importlib.util


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _load_entity_map(tmp_path, monkeypatch):
    maps_dir = tmp_path / 'maps'
    key_file = maps_dir / '.mapkey'
    monkeypatch.setenv('GATEWAY_MAPS_DIR', str(maps_dir))
    monkeypatch.setenv('GATEWAY_MAP_KEY', str(key_file))
    spec = importlib.util.spec_from_file_location(
        'entity_map_under_test',
        os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'entity_map.py')),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, maps_dir, key_file


def test_entity_map_creates_private_dir_key_and_blob(tmp_path, monkeypatch):
    mod, maps_dir, key_file = _load_entity_map(tmp_path, monkeypatch)

    emap = mod.EntityMap('session-1', 'project-1')
    ph, new = emap.placeholder_for('value@example.test', 'email')
    assert new and ph == '<EMAIL_001>'
    emap.save()

    assert _mode(maps_dir) == 0o700
    assert _mode(key_file) == 0o600
    assert _mode(emap.path) == 0o600


def test_entity_map_tightens_existing_permissive_dir_and_key(tmp_path, monkeypatch):
    maps_dir = tmp_path / 'maps'
    maps_dir.mkdir(mode=0o755)
    key_file = maps_dir / '.mapkey'

    # Valid 32-byte AES key encoded as base64, deliberately created with an over-permissive mode.
    key_file.write_text(base64.b64encode(bytes(32)).decode('ascii'))
    os.chmod(maps_dir, 0o755)
    os.chmod(key_file, 0o644)

    mod, maps_dir, key_file = _load_entity_map(tmp_path, monkeypatch)
    mod.EntityMap('session-2', 'project-2')

    assert _mode(maps_dir) == 0o700
    assert _mode(key_file) == 0o600
