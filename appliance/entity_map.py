#!/usr/bin/env python3
"""Session+project entity map for the egress proxy (SPECS §2.2).

Gives cross-turn placeholder stability: the same value -> the same placeholder this turn and next, keyed on
(session, project). Persisted encrypted at rest (AES-GCM, 256-bit key in a local 0600 file). Bidirectional
(value<->placeholder). TTL'd + size-capped. NEVER logs values or the key.
"""
import os, re, json, time, base64, hashlib, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAPS_DIR = os.environ.get('GATEWAY_MAPS_DIR', os.path.expanduser('~/.ossredact/maps'))
KEY_FILE = os.environ.get('GATEWAY_MAP_KEY', os.path.join(MAPS_DIR, '.mapkey'))
TTL_S = int(os.environ.get('GATEWAY_MAP_TTL_H', '24')) * 3600
MAX_ENTITIES = int(os.environ.get('GATEWAY_MAP_MAX', '5000'))
_CASE_SENSITIVE_LABEL_KEYS = {'password', 'secret', 'username', 'accesstoken', 'apikey', 'filepath'}
_PH_LABEL_RE = re.compile(r'^<([A-Z0-9_]+)_\d{3,}>$')

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
            lk = _LOCKS[path] = threading.Lock()
        return lk


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


def derive_session(header_session, system_text=''):
    """Stable session key: the client-provided session id, else a hash of the system prompt (SPECS §2.2)."""
    if header_session:
        return header_session
    if system_text:
        return 'sys-' + hashlib.sha256(system_text.encode('utf-8', 'ignore')).hexdigest()[:16]
    return 'nosession'


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
        self.session = session or 'nosession'
        self.project = project or 'default'
        self.path = os.path.join(MAPS_DIR, _safe_name(self.session, self.project) + '.json.enc')
        self.v2p = {}
        self.p2v = {}
        self.v2p_cf = {}   # casefold(value) -> placeholder, in-memory dedup index (rebuilt on load)
        self.counters = {}
        self.created = time.time()
        self.new_this_load = 0
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
            # Older maps may contain case-variant credential aliases that all point at the first placeholder.
            # Drop only those stale aliases in memory so a future exact-case credential can mint its own token.
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
        """Return (placeholder, is_new). Stable across turns for the same value+session+project."""
        ph = self.v2p.get(value)
        if ph is not None:
            return ph, False
        case_sensitive = _case_sensitive_label(label)
        # Ordinary PII keeps case-variant dedup for cross-turn stability. Credentials and paths are
        # case-significant, so a case-only-different value must mint a distinct placeholder for lossless replay.
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
        if len(self.v2p) < MAX_ENTITIES:
            self.v2p[value] = ph
            self.p2v[ph] = value
            if not case_sensitive:
                self.v2p_cf[value.casefold()] = ph
        self.new_this_load += 1
        return ph, True

    def replay(self):
        """placeholder->value for response rehydration (full session map: the model may reference any
        entity present in the conversation history, all of which were redacted to these placeholders)."""
        return dict(self.p2v)
