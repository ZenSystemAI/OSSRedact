#!/usr/bin/env python3
"""credential_dump / env_form generator: synthetic .env files, connection strings, config dumps (FR/EN).

Fills the password / secret / username / file_path coverage gap (research doc 2026-06-14 section 8). The
body is a mix of three shapes: .env KEY=value lines, user:pass@host connection strings, and a small config
dump. Positives are the four credential labels; everything else is filler or an explicit hard-negative decoy
so the model learns to NOT redact public/operational tokens.

Per research doc section 7, this generator TEACHES three load-bearing collisions:
 - secret vs hex-hash decoy: an API key shape (sk-/ghp_/AKIA/...) is `secret`; a 64-char build hash is a
   DECOY. A Stripe PUBLISHABLE key (pk_live_/pk_test_) is designed-public, so it is a DECOY, never `secret`.
 - password vs username: the human-set value after password=/mot de passe/DB_PASS/the pass half of a
   user:pass pair is `password`; the login id after USER=/login:/db user is `username`. Same line, two labels.
 - username vs file_path: a path-embedded username is part of the `file_path` span, NOT a separate `username`.
   Only a bare login id is `username`.

Decoys (NEVER labeled): Stripe pk_live_/pk_test_ (inline), 64-hex build hash (V.build_hash), port numbers,
version strings (v2.14.1), ticket ids (JIRA-1234). All generated INLINE here or via values.py; values.py is
never edited.

gen(lang) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402

_APPS = ["payments-api", "kyc-worker", "releve-ingest", "billing-svc", "auth-gateway", "ci-parser",
         "notify-relay", "ledger-sync"]
_DB_HOSTS = ["db.internal", "postgres.local", "pg-primary", "mysql-rw", "redis-cache", "mongo-0"]
_DB_NAMES = ["appdb", "prod", "billing", "kyc", "ledger", "sessions"]


def _stripe_publishable() -> str:
    """Stripe PUBLISHABLE key: designed-public, a DECOY, never `secret`. Generated inline (not in values.py)."""
    alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    pre = random.choice(["pk_live_", "pk_test_"])
    return pre + "".join(random.choice(alnum) for _ in range(24))


def _port() -> str:
    return str(random.choice([8080, 8000, 5432, 6379, 27017, 3306, 443, 9100, 5678, 8222]))


def _version() -> str:
    return random.choice(["v", ""]) + f"{random.randint(0,4)}.{random.randint(0,30)}.{random.randint(0,40)}"


def _ticket() -> str:
    proj = random.choice(["JIRA", "OPS", "SEC", "PII", "INFRA", "PAY"])
    return f"{proj}-{random.randint(100, 9999)}"


def _conn_string(fr: bool) -> Doc:
    """A user:pass@host connection string. user -> username, pass -> password, port -> DECOY."""
    d_scheme = random.choice(["postgres://", "postgresql://", "mysql://", "mongodb://", "redis://"])
    return d_scheme


def gen(lang: str = None, split: str = "train") -> dict:
    # `split` accepted for the uniform corpus API; this synthetic-structure doctype (sole source of
    # secret/password/username/file_path) contributes to BOTH splits.
    lang = lang or ("fr" if random.random() < 0.65 else "en")
    fr = lang == "fr"
    d = Doc(doctype="credential_dump", lang=lang)

    app = random.choice(_APPS)
    d.add(("# Configuration " if fr else "# Configuration for ") + app + "\n")
    d.add(("# Environnement: production  Version: " if fr else "# Environment: production  Version: "))
    d.decoy(_version())                                            # version string = DECOY
    d.add("  (" + (("ticket " if fr else "ticket ")))
    d.decoy(_ticket()); d.add(")\n")                              # ticket id = DECOY
    d.add(("# Build: " if fr else "# Build: ")); d.decoy(V.build_hash()); d.add("\n\n")   # 64-hex hash = DECOY

    # ---- .env KEY=value block ----
    # username (DB user / login) -> username ; the human-set pass -> password
    d.add("DB_HOST=" + random.choice(_DB_HOSTS) + "\n")
    d.add("DB_PORT="); d.decoy(_port()); d.add("\n")             # port = DECOY
    d.add("DB_NAME=" + random.choice(_DB_NAMES) + "\n")
    d.add(random.choice(["DB_USER=", "POSTGRES_USER=", "USER="]))
    d.field(V.username(), "username"); d.add("\n")
    d.add(random.choice(["DB_PASS=", "DB_PASSWORD=", "POSTGRES_PASSWORD=",
                         ("MOT_DE_PASSE=" if fr else "PASSWORD=")]))
    d.field(V.password(), "password"); d.add("\n")
    if random.random() < 0.5:                                    # email cue next to the password cue: teach
        d.add(random.choice(["CONTACT_EMAIL=", "ADMIN_EMAIL=", "ALERT_EMAIL="]))   # email-cue -> email vs
        d.field(V.email(), "email"); d.add("\n")                                    # password-cue -> password

    # secret: an API key shape. Stripe publishable key on an adjacent line is a DECOY (secret-vs-public).
    d.add(random.choice(["API_KEY=", "SECRET_KEY=", "OPENAI_API_KEY=", "STRIPE_SECRET_KEY=", "TOKEN="]))
    d.field(V.secret(), "secret"); d.add("\n")
    if random.random() < 0.7:
        d.add("STRIPE_PUBLISHABLE_KEY="); d.decoy(_stripe_publishable()); d.add("\n")   # public key = DECOY

    # second secret sometimes (JWT / webhook signing) to lift secret volume
    if random.random() < 0.45:
        d.add(random.choice(["JWT_SECRET=", "WEBHOOK_SIGNING_SECRET=", "SESSION_SECRET="]))
        d.field(V.secret(), "secret"); d.add("\n")

    # file_path: a config / key file path; embedded username is part of the path span, NOT separate.
    d.add(random.choice(["TLS_KEY_PATH=", "CONFIG_PATH=", "CREDENTIALS_FILE=", "SSH_KEY="]))
    d.field(V.file_path(), "file_path"); d.add("\n")

    # ---- connection string: user:pass@host (same line teaches password-vs-username) ----
    if random.random() < 0.85:
        d.add("\n" + ("# Chaine de connexion\n" if fr else "# Connection string\n"))
        d.add("DATABASE_URL=" + _conn_string(fr))
        d.field(V.username(), "username"); d.add(":")
        d.field(V.password(), "password")
        d.add("@" + random.choice(_DB_HOSTS) + ":"); d.decoy(_port())   # host:port, port = DECOY
        d.add("/" + random.choice(_DB_NAMES) + "\n")

    # ---- small config dump tail with a bare login id + another file_path (the moat lines) ----
    if random.random() < 0.6:
        d.add("\n" + ("[admin]\n" if not fr else "[admin]\n"))
        d.add(("login: " if not fr else "identifiant: ")); d.field(V.username(), "username"); d.add("\n")
        d.add(("mot de passe: " if fr else "password: ")); d.field(V.password(), "password"); d.add("\n")
        d.add(("fichier de log: " if fr else "log file: ")); d.field(V.file_path(), "file_path"); d.add("\n")

    # footer decoys: another version + build-hash variant so secret-vs-hash is reinforced at the bottom
    d.add(("\n# Genere automatiquement  build " if fr else "\n# Auto-generated  build "))
    d.decoy(V.build_hash()[:40]); d.add("  ")
    d.add("rev "); d.decoy(_version()); d.add("\n")
    return d.row()


if __name__ == "__main__":
    random.seed(0)
    for _ in range(2):
        r = gen()
        t = r["input"]
        print("=" * 70, r["meta"]["lang"], r["meta"]["doctype"])
        print(t[:500])
        print("POSITIVES:", [(lab, t[s:e]) for s, e, lab in r["output"]["spans"]])
        print()
