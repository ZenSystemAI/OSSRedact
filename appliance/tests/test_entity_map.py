"""Security-focused tests for appliance/entity_map.py.

The entity map stores the original values used for response rehydration. Its files must stay local-only:
directory traversal metadata should be private, the AES key must be 0600, and encrypted map blobs must be 0600.
"""
import os
import re
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


def test_handleless_sessions_do_not_collide(tmp_path, monkeypatch):
    """M10a: a flow with no session id and no system prompt must get a UNIQUE ephemeral key, never a
    shared 'nosession' map -- else one flow's placeholder rehydrates another flow's value (cross-session leak)."""
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    s1, s2 = mod.derive_session('', ''), mod.derive_session('', '')
    assert s1 != s2 and 'nosession' not in (s1, s2)
    # a stable handle is still stable (cross-turn stability preserved for real sessions)
    assert mod.derive_session('sess-x', '') == mod.derive_session('sess-x', '')
    assert mod.derive_session('', 'same system prompt') == mod.derive_session('', 'same system prompt')
    # two handle-less maps must not share storage or rehydration
    a = mod.EntityMap(mod.derive_session('', ''), 'p')
    b = mod.EntityMap(mod.derive_session('', ''), 'p')
    assert a.path != b.path
    pha, _ = a.placeholder_for('alice@a.test', 'email')
    assert pha not in b.replay()           # b cannot rehydrate a's placeholder -> no cross-session bleed


def test_tenant_isolates_shared_system_prompt(tmp_path, monkeypatch):
    """Leak-hunt finding: two HEADER-LESS clients with an IDENTICAL system prompt but DIFFERENT credentials must
    NOT share a sys- map -- else one tenant could guess the other's predictable placeholder (<EMAIL_001>) and
    rehydrate its value on the response. The per-credential `tenant` namespaces the system-prompt fallback."""
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    sysp = 'You are a helpful assistant.'
    a = mod.derive_session('', sysp, 'tenantAAAA')
    b = mod.derive_session('', sysp, 'tenantBBBB')
    assert a != b                                            # different credential -> different map
    assert mod.derive_session('', sysp, 'tenantAAAA') == a   # same credential + prompt -> stable (continuity kept)
    assert mod.derive_session('', sysp) == mod.derive_session('', sysp)  # no tenant -> prior single-domain behavior
    assert mod.derive_session('sess-x', sysp, 'tenantAAAA') == 'sess-x'  # header-session path unchanged (already unique)
    # storage isolation: tenant A's placeholder is not rehydratable from tenant B's map
    ma, mb = mod.EntityMap(a, 'p'), mod.EntityMap(b, 'p')
    assert ma.path != mb.path
    pha, _ = ma.placeholder_for('alice@a.test', 'email')
    assert pha not in mb.replay()


def test_at_capacity_new_placeholder_is_stored_and_rehydratable(tmp_path, monkeypatch):
    """M10c: past MAX_ENTITIES the prior code minted-but-didn't-store, so replay() couldn't rehydrate the
    newest placeholder. With bounded eviction the newest is always stored + the map stays bounded."""
    monkeypatch.setenv('GATEWAY_MAP_MAX', '3')
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    emap = mod.EntityMap('cap', 'p')
    phs = [emap.placeholder_for(f'val-{i}', 'person')[0] for i in range(6)]   # exceed MAX=3
    assert emap.replay().get(phs[-1]) == 'val-5'   # newest is stored + rehydratable (was the bug)
    assert len(emap.v2p) <= 3                       # bounded
    assert phs[0] not in emap.replay()              # oldest was evicted (FIFO)


def test_evicted_value_reuses_placeholder_and_stays_bounded(tmp_path, monkeypatch):
    """B1: an evicted value that re-appears must reuse its ORIGINAL placeholder (prompt-cache stability), NOT
    re-mint a new one, while v2p stays bounded and no counter number is ever reissued -- across a save/reload."""
    monkeypatch.setenv('GATEWAY_MAP_MAX', '3')
    monkeypatch.setenv('GATEWAY_MAP_TOMB_MAX', '100')   # isolate from tomb FIFO for this test
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    emap = mod.EntityMap('cap-reuse', 'p')
    phs = [emap.placeholder_for(f'val-{i}', 'email')[0] for i in range(5)]   # cap=3 -> val-0,val-1 evicted to tomb
    assert emap.counters['EMAIL'] == 5
    assert 'val-0' not in emap.v2p and phs[0] not in emap.replay()           # evicted from the active maps

    # val-0 re-appears (it is in the re-sent history): must reuse phs[0], counter must NOT advance.
    ph0_again, is_new = emap.placeholder_for('val-0', 'email')
    assert ph0_again == phs[0] and is_new is False, 'evicted value re-minted a different placeholder (cache-bust)'
    assert emap.counters['EMAIL'] == 5, 'counter advanced on a tomb reuse'
    assert len(emap.v2p) <= 3, 'reactivation pushed v2p past MAX_ENTITIES (eviction-first guard missing)'
    assert emap.replay().get(phs[0]) == 'val-0', 'reactivated value is not rehydratable'

    # Persistence round-trip: a fresh instance (next request / restart) still reuses the placeholder, and the
    # counter high-water survives so no <EMAIL_NNN> is ever reissued for a brand-new value.
    emap.save()
    reloaded = mod.EntityMap('cap-reuse', 'p')
    ph1_again, is_new1 = reloaded.placeholder_for('val-1', 'email')           # val-1 is in the persisted tomb
    assert ph1_again == phs[1] and is_new1 is False, 'placeholder not stable across reload'
    fresh_ph, fresh_new = reloaded.placeholder_for('brand-new@x.test', 'email')
    assert fresh_new and fresh_ph not in phs, 'a reissued placeholder number collided with a tombstoned one'


def test_reactivation_does_not_pollute_casefold_dedup_index(tmp_path, monkeypatch):
    """B1 guard: re-activating a CASE-SENSITIVE tombed value (person) must not write the shared casefold dedup
    index, or a later case-INSENSITIVE value with the same casefold would wrongly dedup onto the person token."""
    monkeypatch.setenv('GATEWAY_MAP_MAX', '2')
    monkeypatch.setenv('GATEWAY_MAP_TOMB_MAX', '100')
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    emap = mod.EntityMap('cf-guard', 'p')
    bob = emap.placeholder_for('Bob', 'person')[0]                            # case-sensitive -> not in v2p_cf
    emap.placeholder_for('X', 'person')
    emap.placeholder_for('Y', 'person')                                       # evicts 'Bob' (cap=2) into the tomb
    assert 'Bob' not in emap.v2p
    re_bob, _ = emap.placeholder_for('Bob', 'person')                         # reactivate from tomb
    assert re_bob == bob
    # a non-sensitive value whose casefold == 'bob' must NOT inherit Bob's PERSON placeholder.
    org_ph, org_new = emap.placeholder_for('bob', 'organization')
    assert org_new and org_ph != bob, 'case-sensitive reactivation polluted v2p_cf -> wrong-label dedup'


def test_person_case_variants_are_distinct_for_lossless_rehydrate(tmp_path, monkeypatch):
    """T13: a capitalized person must not own a lowercase path or username token."""
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    emap = mod.EntityMap('person-case', 'p')
    ph1, new1 = emap.placeholder_for('Nadia', 'person')
    ph2, new2 = emap.placeholder_for('nadia', 'person')

    assert new1 and new2
    assert ph1 == '<PERSON_001>'
    assert ph2 == '<PERSON_002>'
    assert emap.replay() == {'<PERSON_001>': 'Nadia', '<PERSON_002>': 'nadia'}


def test_concurrent_mint_same_value_yields_one_placeholder(tmp_path, monkeypatch):
    """M10b: the per-map lock must guard the mint RMW so concurrent callers on one instance can't mint
    two placeholders for the same value."""
    import threading
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    emap = mod.EntityMap('concurrent', 'p')
    results, barrier = [], threading.Barrier(20)
    def mint():
        barrier.wait()
        results.append(emap.placeholder_for('contended@x.test', 'email')[0])
    threads = [threading.Thread(target=mint) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(set(results)) == 1                   # exactly one placeholder for the one value


def test_placeholder_contract_guard_matches_python_and_ts_literals(tmp_path, monkeypatch):
    """M11 guard: keep Python entity-map placeholders in lockstep with the TS core contract."""
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    assert mod.PLACEHOLDER_CONTRACT_PATTERN == r'^<([A-Z0-9_]+)_\d{3,}>$'
    contract = re.compile(mod.PLACEHOLDER_CONTRACT_PATTERN)

    emap = mod.EntityMap('contract', 'p')
    ph, new = emap.placeholder_for('user@example.test', 'email')
    assert new and ph == '<EMAIL_001>'
    assert contract.fullmatch(ph)

    for literal in ('<EMAIL_001>', '<SENSITIVEACCOUNTID_123>', '<SENSITIVE_ACCOUNT_ID_123>', '<A1_1000>'):
        assert contract.fullmatch(literal), literal
    for literal in ('<EMAIL_01>', '<email_001>', '<PERSON_1>', '<PERSON_ABC>', '<PERSON-001>'):
        assert not contract.fullmatch(literal), literal


def test_interprocess_map_lock_preserves_concurrent_fresh_instance_writes(tmp_path, monkeypatch):
    """M10 follow-up: serialize fresh EntityMap load->mint->save cycles for one persisted map."""
    import multiprocessing
    import time
    mod, _, _ = _load_entity_map(tmp_path, monkeypatch)
    session = 'cross-instance'
    project = 'p'
    batches = [
        [('shared@example.test', 'email'), ('val-1', 'person'), ('acct-001', 'sensitive_account_id')],
        [('shared@example.test', 'email'), ('val-2', 'person'), ('acct-002', 'sensitive_account_id')],
        [('shared@example.test', 'email'), ('val-3', 'person'), ('acct-003', 'sensitive_account_id')],
        [('shared@example.test', 'email'), ('val-4', 'person'), ('acct-004', 'sensitive_account_id')],
    ]

    def worker(values, queue):
        try:
            with mod.map_file_lock(session, project):
                emap = mod.EntityMap(session, project)
                time.sleep(0.01)
                for value, label in values:
                    emap.placeholder_for(value, label)
                    time.sleep(0.002)
                emap.save()
            queue.put(None)
        except Exception as exc:
            queue.put(repr(exc))

    ctx = multiprocessing.get_context('fork')
    queue = ctx.Queue()
    procs = [ctx.Process(target=worker, args=(batch, queue)) for batch in batches]
    for proc in procs:
        proc.start()
    errors = [queue.get(timeout=5) for _ in procs]
    for proc in procs:
        proc.join(timeout=5)
    assert errors == [None] * len(procs)
    assert all(proc.exitcode == 0 for proc in procs)

    with mod.map_file_lock(session, project):
        reloaded = mod.EntityMap(session, project)
    expected_values = {value for batch in batches for value, _label in batch}
    assert set(reloaded.v2p) == expected_values
    assert len(set(reloaded.v2p.values())) == len(expected_values)
    assert reloaded.v2p['shared@example.test'] == '<EMAIL_001>'
    replay = reloaded.replay()
    assert all(replay[reloaded.v2p[value]] == value for value in expected_values)
