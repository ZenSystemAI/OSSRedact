#!/usr/bin/env python3
"""Session+project entity map for the egress proxy (SPECS §2.2).

Gives cross-turn placeholder stability: the same value -> the same placeholder this turn and next, keyed on
(session, project). Persisted encrypted at rest (AES-GCM, 256-bit key in a local 0600 file). Bidirectional
(value<->placeholder). TTL'd + size-capped. NEVER logs values or the key.
"""
import contextlib, fcntl, os, re, json, time, base64, hashlib, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAPS_DIR = os.environ.get('GATEWAY_MAPS_DIR', os.path.expanduser('~/.ossredact/maps'))
KEY_FILE = os.environ.get('GATEWAY_MAP_KEY', os.path.join(MAPS_DIR, '.mapkey'))
TTL_S = int(os.environ.get('GATEWAY_MAP_TTL_H', '24')) * 3600
MAX_ENTITIES = int(os.environ.get('GATEWAY_MAP_MAX', '5000'))
_CASE_SENSITIVE_LABEL_KEYS = {'password', 'secret', 'username', 'person', 'name', 'accesstoken', 'apikey', 'filepath'}
# Canonical placeholder contract shared with packages/redaction-core/src/placeholder.ts.
# Any change here must update the TypeScript side and both guard tests:
# <LABEL_NNN>, label [A-Z0-9_]+, 3 or more decimal digits.
PLACEHOLDER_CONTRACT_PATTERN = r'^<([A-Z0-9_]+)_\d{3,}>$'
_PH_LABEL_RE = re.compile(PLACEHOLDER_CONTRACT_PATTERN)

_LOCKS = {}
_LOCKS_GUARD = threading.Lock()


def _chmod_private(path, mode):
    try:
        os.chmod(path, mode)
    except OSError as e:
        print(f"[entity_map chmod err] {type(e).__name__}", flush=True)


def _ensure_maps_dir():
    os.makedirs(MAPS_DIR, mode=0o700, exist_ok=True)
    _chmod_private(MAPS_DIR, 0o700)


def _key_lock(path):
    with _LOCKS_GUARD:
        lk = _LOCKS.get(path)
        if lk is None:
            lk = _LOCKS[path] = threading.RLock()
        return lk


def map_path_for(session, project='default'):
    return os.path.join(MAPS_DIR, _safe_name(session, project or 'default') + '.json.enc')


@contextlib.contextmanager
def map_file_lock(session, project='default'):
    """Exclusive host-local lock for a persisted map's load->mint->save cycle.

    EntityMap.placeholder_for still keeps its per-path in-process lock for one-instance RMW safety. This
    outer guard covers fresh EntityMap instances in concurrent requests or processes that share one map file.
    """
    _ensure_maps_dir()
    path = map_path_for(session, project)
    lock_path = path + '.lock'
    lk = _key_lock(path)
    with lk:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _chmod_private(lock_path, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _load_key():
    _ensure_maps_dir()
    if os.path.exists(KEY_FILE):
        _chmod_private(KEY_FILE, 0o600)
        with open(KEY_FILE, 'rb') as f:
            return base64.b64decode(f.read())
    k = AESGCM.generate_key(bit_length=256)
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, base64.b64encode(k))
    finally:
        os.close(fd)
    return k


_AES = AESGCM(_load_key())


def _safe_name(session, project):
    return hashlib.sha256(f"{project}\x00{session}".encode()).hexdigest()[:32]


def _ephemeral_session():
    """Unique per-call session id for a flow with NO stable handle (no client session id, no system
    prompt). Prevents distinct concurrent first-turn flows from colliding on a single shared 'nosession'
    map -- which would let one flow's placeholder rehydrate to ANOTHER flow's value (a cross-session PII
    leak). Cost: no cross-turn placeholder stability for handle-less flows, which cannot be provided
    correctly anyway when there is nothing to correlate turns by."""
    return 'ephemeral-' + os.urandom(12).hex()


def derive_session(header_session, system_text='', tenant=''):
    """Stable session key: the client-provided session id, else a hash of the system prompt (SPECS §2.2).
    With neither handle, return a UNIQUE ephemeral id (never a shared constant -- see _ephemeral_session).

    `tenant` (a hash of the upstream credential, optional) namespaces the SYSTEM-PROMPT FALLBACK so two
    DIFFERENT credentials that share an identical system prompt get SEPARATE maps. Without it, two header-less
    multi-tenant clients with the same system prompt landed in one `sys-<hash>` map, and a client could guess
    another tenant's predictable placeholder (<EMAIL_001>, ...) and rehydrate its value on the response. Same
    credential + same prompt still shares one map (cross-turn continuity preserved). Empty tenant (a single
    shared upstream key / no credential = one trust domain) keeps the prior behavior. The header-session path
    is unchanged: a client-provided session id is already per-client unique."""
    if header_session:
        return header_session
    if system_text:
        base = hashlib.sha256(system_text.encode('utf-8', 'ignore')).hexdigest()[:32]  # 128-bit: collision-free namespace
        return 'sys-' + (tenant + '-' if tenant else '') + base
    return _ephemeral_session()


def _label_key(label):
    return re.sub(r'[^a-z0-9]', '', str(label).casefold())


def _placeholder_label(ph):
    m = _PH_LABEL_RE.match(str(ph))
    return m.group(1) if m else ''


def _case_sensitive_label(label):
    return _label_key(label) in _CASE_SENSITIVE_LABEL_KEYS


def _case_sensitive_placeholder(ph):
    return _case_sensitive_label(_placeholder_label(ph))


class EntityMap:
    def __init__(self, session, project='default'):
        self.session = session or _ephemeral_session()
        self.project = project or 'default'
        self.path = map_path_for(self.session, self.project)
        self.v2p = {}
        self.p2v = {}
        self.v2p_cf = {}   # casefold(value) -> placeholder, in-memory dedup index (rebuilt on load)
        self.counters = {}
        self.created = time.time()
        self.new_this_load = 0
        self.evicted_this_load = set()
        self._lock = _key_lock(self.path)
        self._load()

    def _load(self):
        try:
            if not os.path.exists(self.path):
                return
            blob = open(self.path, 'rb').read()
            if len(blob) < 13:
                return
            nonce, ct = blob[:12], blob[12:]
            data = json.loads(_AES.decrypt(nonce, ct, None))
            if time.time() - data.get('created', 0) > TTL_S:
                try:
                    os.remove(self.path)
                except OSError:
                    pass
                return
            self.v2p = data.get('v2p', {})
            self.p2v = data.get('p2v', {})
            self.counters = data.get('counters', {})
            # Older maps may contain case-variant aliases that all point at the first placeholder. Drop only
            # those stale aliases in memory so a future exact-case value can mint its own token.
            for value, ph in list(self.v2p.items()):
                if _case_sensitive_placeholder(ph) and self.p2v.get(ph) not in (None, value):
                    self.v2p.pop(value, None)
            self.v2p_cf = {k.casefold(): p for k, p in self.v2p.items()
                           if not _case_sensitive_placeholder(p)}  # rebuild non-sensitive dedup index
            self.created = data.get('created', time.time())
        except Exception as e:
            print(f"[entity_map load err] {type(e).__name__}", flush=True)  # never log values

    def save(self):
        try:
            _ensure_maps_dir()
            data = json.dumps({'v2p': self.v2p, 'p2v': self.p2v,
                               'counters': self.counters, 'created': self.created}).encode()
            nonce = os.urandom(12)
            ct = _AES.encrypt(nonce, data, None)
            tmp = self.path + '.tmp'
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, nonce + ct)
            finally:
                os.close(fd)
            os.replace(tmp, self.path)  # atomic
        except Exception as e:
            print(f"[entity_map save err] {type(e).__name__}", flush=True)

    def placeholder_for(self, value, label):
        """Return (placeholder, is_new). Stable across turns for the same value+session+project.

        The whole read-modify-write runs under the per-map-file lock so two callers sharing this instance
        cannot mint two placeholders for one value or corrupt the counters. (Cross-INSTANCE concurrency --
        the egress builds a fresh EntityMap per request -- still needs caller-level locking across
        load->mint->save; tracked as a follow-up. This guard fixes the in-instance RMW Codex flagged.)
        """
        case_sensitive = _case_sensitive_label(label)
        with self._lock:
            ph = self.v2p.get(value)
            if ph is not None:
                return ph, False
            # Ordinary non-name PII keeps case-variant dedup for cross-turn stability. Case-significant labels
            # mint distinct placeholders for case-only-different values so replay stays lossless.
            if not case_sensitive:
                vcf = value.casefold()
                ph = self.v2p_cf.get(vcf)
                if ph is not None:
                    if len(self.v2p) < MAX_ENTITIES:
                        self.v2p[value] = ph   # bind this exact form too for O(1) future exact lookups
                    return ph, False
            lab = re.sub(r'[^A-Z0-9]', '', label.upper()) or 'PII'
            self.counters[lab] = self.counters.get(lab, 0) + 1
            ph = f"<{lab}_{self.counters[lab]:03d}>"
            # Bounded eviction: the prior code minted-but-did-NOT-store once len(v2p) hit MAX_ENTITIES, so
            # replay() could not rehydrate the new placeholder (the user saw a raw <LABEL_NNN>) and the next
            # turn re-minted a different token. Evict oldest-first to guarantee the new placeholder is stored.
            self._evict_if_full()
            self.v2p[value] = ph
            self.p2v[ph] = value
            if not case_sensitive:
                self.v2p_cf[value.casefold()] = ph
            self.new_this_load += 1
            return ph, True

    def _evict_if_full(self):
        """FIFO-evict oldest entries until there is room for one more value (call under self._lock).
        Bounds memory for long/looping sessions while keeping rehydration correct for recent entities."""
        while len(self.v2p) >= MAX_ENTITIES and self.v2p:
            old_val = next(iter(self.v2p))             # oldest inserted (dict preserves insertion order)
            old_ph = self.v2p.pop(old_val)
            self.evicted_this_load.add(old_ph)
            self.p2v.pop(old_ph, None)
            if self.v2p_cf.get(old_val.casefold()) == old_ph:
                self.v2p_cf.pop(old_val.casefold(), None)

    def replay(self):
        """placeholder->value for response rehydration (full session map: the model may reference any
        entity present in the conversation history, all of which were redacted to these placeholders)."""
        return dict(self.p2v)
