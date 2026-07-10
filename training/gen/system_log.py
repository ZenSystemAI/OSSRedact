#!/usr/bin/env python3
"""system_log generator: synthetic application/server log lines (FR/EN), fills the ip_address/file_path gap.

Positives are the RARE genuinely-identifying tokens that surface in real logs: a routable PUBLIC client IP
(research doc section 5/7: only a public IP = ip_address), a concrete file_path, and the occasional
person/email/username when a log line names a real user. EVERYTHING that merely LOOKS sensitive is a decoy
emitted via .decoy() so the model learns to NOT redact infrastructure noise: this is the operator's
false-positive fix, and noise-line volume is the moat. Per research doc 2026-06-14:
 - public routable IP -> ip_address; RFC1918 (10/8, 172.16/12, 192.168/16) + loopback 127/8 + link-local
   169.254/16 = NEGATIVE (V.private_ip()).
 - file_path -> file_path (the embedded username is part of the path span, not a separate username).
 - PIDs, ports, ISO timestamps + clock, semver/version strings, log levels, build hashes = NEGATIVE decoys.
 - a bare @handle / login: id is a username positive; an email-shaped token is an email positive.

gen(lang) -> one offset-true row dict. Caller seeds `random`.
"""
from __future__ import annotations
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from framework import Doc       # noqa: E402
import values as V              # noqa: E402

_SERVICES = ["nginx", "sshd", "auth-api", "gateway", "worker", "postgres", "redis", "cron",
             "kernel", "systemd", "app", "billing-svc", "ingest", "scheduler"]
_LEVELS_EN = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "NOTICE", "CRITICAL"]
_LEVELS_FR = ["DEBOGAGE", "INFO", "AVERT", "AVERTISSEMENT", "ERREUR", "AVIS", "CRITIQUE"]
_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
_HTTP_ROUTES = ["/api/v2/login", "/api/v2/accounts", "/health", "/static/app.js", "/upload",
                "/api/v1/statements", "/auth/token", "/metrics", "/favicon.ico", "/api/v2/users"]
_HTTP_CODES = ["200", "201", "204", "301", "302", "400", "401", "403", "404", "429", "500", "502", "503"]


def _clock() -> str:
    return f"{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"


def _timestamp() -> str:
    """ISO date + clock + optional millis/zone -> a NEGATIVE decoy."""
    base = f"{V.iso_date()}T{_clock()}"
    r = random.random()
    if r < 0.4:
        return base + f".{random.randint(0,999):03d}Z"
    if r < 0.7:
        return base + "Z"
    return base


def _version() -> str:
    """semver-ish version string -> NEGATIVE decoy (looks numeric, never a PII)."""
    v = f"{random.randint(0,9)}.{random.randint(0,30)}.{random.randint(0,99)}"
    if random.random() < 0.4:
        v += random.choice(["-rc1", "-beta", "+build", "-alpha2", ""])
    return random.choice(["v", ""]) + v


def _pid() -> str:
    return str(random.randint(100, 99999))


def _port() -> str:
    return str(random.choice([22, 80, 443, 5432, 6379, 8080, 8443, 9100, 3000, 5173]
                             + [random.randint(1024, 65535)]))


def _level(fr: bool) -> str:
    return random.choice(_LEVELS_FR if fr else _LEVELS_EN)


def _emit_line(d: Doc, fr: bool) -> None:
    """Append one realistic log line. May add 0+ positives and several decoys."""
    svc = random.choice(_SERVICES)
    kind = random.random()

    # leading timestamp (decoy) + service[pid] + level
    d.decoy(_timestamp()); d.add(" ")
    d.add(svc + "["); d.decoy(_pid()); d.add("] ")
    d.add(_level(fr)); d.add(": ")

    if kind < 0.34:
        # --- HTTP access line: PUBLIC client IP is the positive ---
        if fr:
            d.add("requete ")
        else:
            d.add("request ")
        d.field(V.public_ip(), "ip_address")              # routable client IP -> POSITIVE
        d.add(" \"" + random.choice(_HTTP_METHODS) + " " + random.choice(_HTTP_ROUTES) + "\" ")
        d.decoy(random.choice(_HTTP_CODES)); d.add(" ")     # status code -> decoy
        d.decoy(str(random.randint(60, 999999))); d.add("b ")  # bytes -> decoy
        if random.random() < 0.45:
            d.add(("utilisateur " if fr else "user "))
            if random.random() < 0.55:
                d.field("@" + V.username(), "username")
            else:
                d.field(V.email(), "email")
        d.add("\n")

    elif kind < 0.55:
        # --- auth / ssh line: public IP positive, optional username/person ---
        if fr:
            d.add("connexion " + random.choice(["acceptee", "refusee"]) + " pour ")
        else:
            d.add(random.choice(["accepted", "failed"]) + " login for ")
        if random.random() < 0.6:
            d.field("@" + V.username(), "username")
        else:
            d.field(V.person(lang="fr" if fr else "en", caps=False), "person")
        d.add((" depuis " if fr else " from "))
        d.field(V.public_ip(), "ip_address")                # remote source IP -> POSITIVE
        d.add((" port " if fr else " port "))
        d.decoy(_port())                                     # port -> decoy
        d.add("\n")

    elif kind < 0.74:
        # --- file IO line: file_path positive; private host IP is a DECOY ---
        if fr:
            d.add(random.choice(["ecriture", "lecture", "rotation"]) + " du fichier ")
        else:
            d.add(random.choice(["writing", "reading", "rotating"]) + " file ")
        d.field(V.file_path(), "file_path")                  # path -> POSITIVE
        d.add((" sur l'hote " if fr else " on host "))
        d.decoy(V.private_ip())                              # internal host IP -> NEGATIVE decoy
        if random.random() < 0.4:
            d.add((" version " if fr else " version "))
            d.decoy(_version())                              # version string -> decoy
        d.add("\n")

    elif kind < 0.88:
        # --- internal infra noise: ALL decoys (private IP, port, version, pid, hash) ---
        if fr:
            d.add("verification etat du service vers ")
        else:
            d.add("health check upstream ")
        d.decoy(V.private_ip()); d.add(":"); d.decoy(_port())   # internal endpoint -> NEGATIVE
        d.add((" repondu en " if fr else " responded in "))
        d.decoy(str(random.randint(1, 9999))); d.add("ms ")     # latency -> decoy
        d.add(("loopback " if fr else "loopback "))
        d.decoy("127.0.0.1")                                     # loopback -> NEGATIVE decoy
        if random.random() < 0.5:
            d.add(" build ")
            d.decoy(V.build_hash()[: random.choice([7, 12, 40])])  # build hash -> decoy
        d.add("\n")

    else:
        # --- error/stacktrace line: file_path positive, version + pid decoys ---
        if fr:
            d.add("exception non geree dans ")
        else:
            d.add("unhandled exception in ")
        d.field(V.file_path(), "file_path")                  # path in stacktrace -> POSITIVE
        d.add((" ligne " if fr else " line "))
        d.decoy(str(random.randint(1, 4000)))                # line number -> decoy
        d.add((" pid " if fr else " pid "))
        d.decoy(_pid())                                      # pid -> decoy
        d.add((" version " if fr else " version "))
        d.decoy(_version())                                  # version -> decoy
        d.add("\n")


def gen(lang: str = None, split: str = "train") -> dict:
    # `split` accepted for the uniform corpus API; sole source of public ip_address + file_path -> BOTH splits.
    lang = lang or ("fr" if random.random() < 0.65 else "en")
    fr = lang == "fr"
    d = Doc(doctype="system_log", lang=lang)

    # header banner (filler/decoys)
    d.add(("Journal d'application " if fr else "Application log "))
    d.add(random.choice(_SERVICES) + " ")
    d.add(("demarre a " if fr else "started at "))
    d.decoy(_timestamp()); d.add("\n")
    d.add(("Version du processus: " if fr else "Process version: "))
    d.decoy(_version()); d.add("  pid="); d.decoy(_pid())
    d.add("  port="); d.decoy(_port()); d.add("\n")
    d.add(("Hote interne: " if fr else "Internal host: "))
    d.decoy(V.private_ip()); d.add("\n\n")                    # bind address -> NEGATIVE decoy

    # body: guarantee both required positives appear, then fill with mixed lines
    n = random.randint(7, 20)
    for _ in range(n):
        _emit_line(d, fr)

    # ensure at least one ip_address positive and one file_path positive every row
    spans = [lab for _, _, lab in d._spans]
    if "ip_address" not in spans:
        d.add(("connexion entrante depuis " if fr else "inbound connection from "))
        d.field(V.public_ip(), "ip_address"); d.add((" port " if fr else " port "))
        d.decoy(_port()); d.add("\n")
    if "file_path" not in spans:
        d.add(("rotation du fichier " if fr else "rotating file "))
        d.field(V.file_path(), "file_path"); d.add("\n")

    # footer noise (decoys)
    d.add(("\nArret du service apres " if fr else "\nService stopped after "))
    d.decoy(str(random.randint(1, 720))); d.add(("h, code de sortie " if fr else "h, exit code "))
    d.decoy(str(random.choice([0, 1, 2, 137, 143])))
    d.add(("  derniere mise a jour " if fr else "  last refresh "))
    d.decoy(_timestamp()); d.add("\n")
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
