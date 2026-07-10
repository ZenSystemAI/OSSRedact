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
# Eviction TOMBSTONE bound: when v2p evicts to stay <= MAX_ENTITIES, the value->placeholder binding is preserved
# in a compact tomb so a re-sent value reuses its ORIGINAL placeholder (prompt-cache stability) instead of
# re-minting. Default 1x MAX_ENTITIES (a session with >5000 distinct redacted values is unusual); operator-tunable.
MAX_TOMB = int(os.environ.get('GATEWAY_MAP_TOMB_MAX', str(MAX_ENTITIES)))
# Absolute map-age cap (default 7d): the idle TTL below keeps an ACTIVE session's placeholders stable, but a
# long-lived SHARED sys-<hash> fallback map (multi-tenant, one upstream key) must still rotate -- this cap restores
# the daily-rotation defence-in-depth that a pure idle TTL would remove.
HARD_MAX_S = int(os.environ.get('GATEWAY_MAP_HARD_MAX_H', '168')) * 3600
TOUCH_REFRESH_S = TTL_S // 4   # debounce window for last_used touch-saves (refresh an active map without writing every turn)
_CASE_SENSITIVE_LABEL_KEYS = {'password', 'secret', 'username', 'person', 'name', 'accesstoken', 'apikey', 'filepath'}
# Canonical placeholder contract shared with packages/redaction-core/src/placeholder.ts.
# Any change here must update the TypeScript side and both guard tests:
# <LABEL_NNN>, label [A-Z0-9_]+, 3 or more decimal digits.
PLACEHOLDER_CONTRACT_PATTERN = r'^<([A-Z0-9_]+)_\d{3,}>$'
_PH_LABEL_RE = re.compile(PLACEHOLDER_CONTRACT_PATTERN)
_PH_LABEL_NUM_RE = re.compile(r'^<([A-Z0-9_]+)_(\d{3,})>$')   # label + numeric suffix, for counter high-water reconciliation

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


def gc_maps(ttl_days=None, now=None):
    """Best-effort garbage-collect the maps dir. Removes (a) *.json.enc whose mtime is older than the TTL (with
    their sibling .lock), and (b) ORPHANED *.lock whose .json.enc no longer exists. Orphan locks are only removed
    when they are themselves older than 1h, so a lock freshly created for a map whose .enc has not yet been written
    is never swept out from under an active load->mint->save cycle. Returns {'enc': n, 'lock': n} removed counts.

    Rationale: every session mints a per-(session,project) .enc + a persistent .lock; the lock file was never
    unlinked, so orphaned locks accumulated without bound (audit: 3502 .lock vs 2567 .enc). Expired maps are stale
    at-rest PII that should not linger either. TTL default = the absolute map-age hard cap (GATEWAY_MAP_HARD_MAX_H,
    7d) so GC never deletes a map that could still be live; override with GATEWAY_MAPS_TTL_DAYS. 0 disables."""
    if ttl_days is None:
        ttl_days = float(os.environ.get('GATEWAY_MAPS_TTL_DAYS', str(HARD_MAX_S / 86400)))
    if ttl_days <= 0 or not os.path.isdir(MAPS_DIR):
        return {'enc': 0, 'lock': 0}
    now = now if now is not None else time.time()
    ttl_s = ttl_days * 86400
    removed = {'enc': 0, 'lock': 0}

    def _age(p):
        try:
            return now - os.path.getmtime(p)
        except OSError:
            return -1.0

    def _unlink(p):
        try:
            os.unlink(p)
            return True
        except OSError:
            return False

    try:
        names = os.listdir(MAPS_DIR)
    except OSError:
        return removed
    for name in names:
        if not name.endswith('.json.enc'):
            continue
        path = os.path.join(MAPS_DIR, name)
        age = _age(path)
        if age > ttl_s:
            if _unlink(path):
                removed['enc'] += 1
            if _unlink(path + '.lock'):
                removed['lock'] += 1
    # Second pass: sweep locks whose .enc is gone (orphans), guarded by a 1h floor to avoid a load-in-flight race.
    for name in os.listdir(MAPS_DIR):
        if not name.endswith('.json.enc.lock'):
            continue
        lock_path = os.path.join(MAPS_DIR, name)
        enc_path = lock_path[:-len('.lock')]
        if not os.path.exists(enc_path) and _age(lock_path) > 3600:
            if _unlink(lock_path):
                removed['lock'] += 1
    return removed


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
        self.tomb = {}     # eviction tombstone: key(value) -> placeholder, preserves minting stability past eviction
        self.counters = {}
        self.created = time.time()
        self.last_used = self.created
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
            created = data.get('created', 0)
            last_used = data.get('last_used', created)   # backward-compat: old maps had no last_used
            now = time.time()
            # Expire on IDLE (unused within TTL_S) so an ACTIVE long session's placeholders never reset
            # (the cache-stability goal), OR on absolute AGE (created older than HARD_MAX_S) so a long-lived
            # SHARED sys-<hash> fallback map still rotates (defence in depth for multi-tenant single-key reuse).
            if (now - last_used) > TTL_S or (now - created) > HARD_MAX_S:
                try:
                    os.remove(self.path)
                except OSError:
                    pass
                return
            self.v2p = data.get('v2p', {})
            self.p2v = data.get('p2v', {})
            self.tomb = data.get('tomb', {})
            self.counters = data.get('counters', {})
            # Older maps may contain case-variant aliases that all point at the first placeholder. Drop only
            # those stale aliases in memory so a future exact-case value can mint its own token.
            for value, ph in list(self.v2p.items()):
                if _case_sensitive_placeholder(ph) and self.p2v.get(ph) not in (None, value):
                    self.v2p.pop(value, None)
            self.v2p_cf = {k.casefold(): p for k, p in self.v2p.items()
                           if not _case_sensitive_placeholder(p)}  # rebuild non-sensitive dedup index
            # Counter high-water reconciliation: the monotonic counter is the SOLE guard against re-minting a
            # tombstoned <LABEL_NNN> for a NEW value (which would then rehydrate to the wrong value). If a
            # persisted map's counters ever lag a placeholder still live in p2v or tomb, lift each label's
            # counter to the max suffix seen so no number is ever reissued.
            for ph in list(self.p2v.keys()) + list(self.tomb.values()):
                m = _PH_LABEL_NUM_RE.match(ph)
                if m and int(m.group(2)) > self.counters.get(m.group(1), 0):
                    self.counters[m.group(1)] = int(m.group(2))
            self.created = data.get('created', time.time())
            self.last_used = data.get('last_used', self.created)
        except Exception as e:
            print(f"[entity_map load err] {type(e).__name__}", flush=True)  # never log values

    def save(self):
        try:
            _ensure_maps_dir()
            self.last_used = time.time()   # refresh the idle clock on every persist (incl. touch-saves)
            data = json.dumps({'v2p': self.v2p, 'p2v': self.p2v, 'tomb': self.tomb,
                               'counters': self.counters, 'created': self.created,
                               'last_used': self.last_used}).encode()
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
            # Eviction TOMBSTONE: a value evicted to bound memory kept its ORIGINAL placeholder here, so a
            # re-sent value reuses that exact token instead of re-minting a different one (which would shift the
            # redacted prefix bytes -> Anthropic prompt-cache MISS). Re-activate it into the active maps for this
            # turn's known-value sweep + rehydration. Evict FIRST (mirror the mint path) so the re-insert can
            # never push v2p past MAX_ENTITIES; gate v2p_cf on case-sensitivity exactly like minting so a
            # case-sensitive value never pollutes the shared casefold dedup index.
            tkey = value if case_sensitive else value.casefold()
            tph = self.tomb.get(tkey)
            if tph is not None:
                self._evict_if_full()
                self.v2p[value] = tph
                self.p2v[tph] = value
                if not case_sensitive:
                    self.v2p_cf[value.casefold()] = tph
                self.tomb.pop(tkey, None)
                self.evicted_this_load.discard(tph)   # reactivated -> no longer a cache-bust signal
                return tph, False
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
        Bounds memory for long/looping sessions while keeping rehydration correct for recent entities. The
        evicted value->placeholder BINDING is MOVED to the tomb (not discarded) so a re-sent value reuses its
        original placeholder instead of re-minting -- placeholder bytes stay stable across eviction (prompt
        cache). The rehydration entry (p2v) IS dropped: an evicted-and-not-resent value would show a raw
        placeholder in a response (over-redaction, the safe error), never a wrong value."""
        while len(self.v2p) >= MAX_ENTITIES and self.v2p:
            old_val = next(iter(self.v2p))             # oldest inserted (dict preserves insertion order)
            old_ph = self.v2p.pop(old_val)
            self.evicted_this_load.add(old_ph)
            self.p2v.pop(old_ph, None)
            if self.v2p_cf.get(old_val.casefold()) == old_ph:
                self.v2p_cf.pop(old_val.casefold(), None)
            # Key the tomb by the SAME class-derivation the lookup uses (exact for case-sensitive labels, else
            # casefold); pop-then-set moves a re-evicted key to most-recent for correct FIFO.
            tkey = old_val if _case_sensitive_placeholder(old_ph) else old_val.casefold()
            self.tomb.pop(tkey, None)
            self.tomb[tkey] = old_ph
        while len(self.tomb) > MAX_TOMB:           # bound the tombstone (FIFO); ancient values re-mint (safe tail)
            self.tomb.pop(next(iter(self.tomb)), None)

    def needs_touch(self):
        """True when an ACTIVE map (has entries) has not been persisted within the debounce window. Lets the
        egress refresh last_used on a long stretch of PII-free turns so an in-use session never idle-expires
        (which would re-mint every placeholder -> prompt-cache miss). Debounced so clean turns don't write
        on every request."""
        return bool(self.v2p or self.tomb) and (time.time() - self.last_used) > TOUCH_REFRESH_S

    def replay(self):
        """placeholder->value for response rehydration (full session map: the model may reference any
        entity present in the conversation history, all of which were redacted to these placeholders)."""
        return dict(self.p2v)
