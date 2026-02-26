#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║       SAML TestBench — Single-file Dev Tool           ║
║  Run:  python saml_testbench.py                       ║
║  Port: set PORT below, or Admin → Settings → Port     ║
╚══════════════════════════════════════════════════════╝
"""

# ═══════════════════════════════════════════════════════════════
# PHASE 1 — STDLIB IMPORTS
# ═══════════════════════════════════════════════════════════════
import sys, os, json, sqlite3, hashlib, secrets, uuid, threading, platform, shutil
import subprocess, importlib, tempfile, webbrowser, time, re, base64, argparse
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════
# PHASE 2 — APP PATHS  (frozen-safe: use exe dir when bundled)
# ═══════════════════════════════════════════════════════════════
_FROZEN  = getattr(sys, 'frozen', False)
APP_DIR  = Path(sys.executable).resolve().parent if _FROZEN else Path(__file__).resolve().parent
DB_PATH  = APP_DIR / "saml_testbench.db"
SAML_TMP = APP_DIR / ".saml_cache"
# ─── Port (override here or via Admin → Settings → Port after first run) ────
# ─── Port: change this number OR use Admin → Settings → Port ────────────────
PORT     = 5000   # overridden at startup by the value saved in Admin → Settings
SAML_TMP.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════
# PHASE 3 — DEPENDENCY BOOTSTRAP
# ═══════════════════════════════════════════════════════════════
REQUIRED = [
    ("flask",               "flask>=3.0.0",              "Flask web framework"),
    ("onelogin.saml2.auth", "python3-saml>=1.16.0",      "SAML 2.0 library"),
    ("requests",            "requests>=2.31.0",           "HTTP client (OIDC token exchange)"),
    ("jwt",                 "PyJWT[cryptography]>=2.8.0", "JWT validation (OIDC ID tokens)"),
]

def _import_ok(module_name: str) -> bool:
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False

def _get_missing() -> list:
    return [(pip, desc) for mod, pip, desc in REQUIRED if not _import_ok(mod)]

def _check_outdated() -> list:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            capture_output=True, text=True, timeout=20
        )
        items = json.loads(result.stdout or "[]")
        return [i["name"].lower() for i in items]
    except Exception:
        return []

def bootstrap():
    missing = _get_missing()
    if missing:
        print("\n╔══════════════════════════════════════════════════════╗")
        print("║  Installing required packages…                        ║")
        print("╚══════════════════════════════════════════════════════╝\n")
        for pkg, desc in missing:
            print(f"  → Installing {pkg}  ({desc})")
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"], check=True)
        print("\n  ✓ All packages installed. Starting…\n")

    outdated = _check_outdated()
    needs = [(pip, desc) for mod, pip, desc in REQUIRED if pip.split(">=")[0].lower() in outdated]
    if needs:
        print("  ⟳ Updating packages…")
        for pkg, _ in needs:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q", "--upgrade"], check=True)

# ── Run dep check BEFORE importing Flask/saml ────────────────────────────────
if not _FROZEN:
    bootstrap()

# ═══════════════════════════════════════════════════════════════
# PHASE 4 — MAIN IMPORTS (safe now)
# ═══════════════════════════════════════════════════════════════
from flask import (Flask, request, session, redirect, url_for,
                   flash, make_response, jsonify, get_flashed_messages)
from itsdangerous import URLSafeTimedSerializer as _ItsSer

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    SAML_OK = True
except ImportError:
    SAML_OK = False

# Optional OIDC dependencies
try:
    import requests as _http
    _HTTP_OK = True
except ImportError:
    _HTTP_OK = False
    class _FakeHttp:
        @staticmethod
        def get(*a, **k): raise RuntimeError("requests not installed")
        @staticmethod
        def post(*a, **k): raise RuntimeError("requests not installed")
    _http = _FakeHttp()

try:
    import jwt as _jwt
    _JWT_OK = True
    # RSA/EC signature verification requires PyJWT[cryptography].
    # Probe it now so we fall back to claims-only validation instead of
    # crashing at callback time with an ImportError.
    try:
        from jwt.algorithms import RSAAlgorithm as _RSAAlgorithm, ECAlgorithm as _ECAlgorithm
        _JWT_CRYPTO_OK = True
    except ImportError:
        _RSAAlgorithm  = None
        _ECAlgorithm   = None
        _JWT_CRYPTO_OK = False
except ImportError:
    _jwt           = None
    _RSAAlgorithm  = None
    _ECAlgorithm   = None
    _JWT_OK        = False
    _JWT_CRYPTO_OK = False

OIDC_OK = _HTTP_OK


# ═══════════════════════════════════════════════════════════════
# PHASE 5 — DATABASE
# ═══════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def _db_one(sql, params=()):
    with get_db() as db:
        return db.execute(sql, params).fetchone()

def _db_all(sql, params=()):
    with get_db() as db:
        return [dict(r) for r in db.execute(sql, params).fetchall()]

def _db_write(sql, params=()):
    with get_db() as db:
        db.execute(sql, params)
        db.commit()

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS app_meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS users (
            id        TEXT PRIMARY KEY,
            username  TEXT UNIQUE NOT NULL,
            email     TEXT,
            pw_hash   TEXT NOT NULL,
            role      TEXT NOT NULL DEFAULT 'user',
            created   TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_attributes (
            id       TEXT PRIMARY KEY,
            user_id  TEXT NOT NULL,
            key      TEXT NOT NULL,
            value    TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS idp_config (
            name        TEXT PRIMARY KEY,
            label       TEXT,
            entity_id   TEXT DEFAULT '',
            sso_url     TEXT DEFAULT '',
            slo_url     TEXT DEFAULT '',
            x509_cert   TEXT DEFAULT '',
            sp_entity   TEXT DEFAULT 'http://localhost:5000/saml/metadata',
            sp_acs      TEXT DEFAULT 'http://localhost:5000/saml/acs',
            sp_slo      TEXT DEFAULT 'http://localhost:5000/saml/slo',
            enabled     INTEGER DEFAULT 0,
            attr_mapping TEXT DEFAULT '{}',
            is_custom   INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS idp_watched_attrs (
            idp_name    TEXT NOT NULL,
            attr_name   TEXT NOT NULL,
            description TEXT DEFAULT '',
            required    INTEGER DEFAULT 0,
            sort_order  INTEGER DEFAULT 99,
            PRIMARY KEY (idp_name, attr_name)
        );
        CREATE TABLE IF NOT EXISTS auth_log (
            id          TEXT PRIMARY KEY,
            session_id  TEXT,
            ts          TEXT NOT NULL,
            step        TEXT,
            event       TEXT,
            idp         TEXT,
            level       TEXT DEFAULT 'summary',
            success     INTEGER,
            username    TEXT,
            detail_json TEXT,
            error       TEXT,
            ip          TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS oidc_config (
            name                       TEXT PRIMARY KEY,
            label                      TEXT,
            discovery_url              TEXT DEFAULT '',
            client_id                  TEXT DEFAULT '',
            client_secret              TEXT DEFAULT '',
            authorization_endpoint     TEXT DEFAULT '',
            token_endpoint             TEXT DEFAULT '',
            userinfo_endpoint          TEXT DEFAULT '',
            jwks_uri                   TEXT DEFAULT '',
            issuer                     TEXT DEFAULT '',
            scopes                     TEXT DEFAULT 'openid profile email',
            redirect_uri               TEXT DEFAULT '',
            use_pkce                   INTEGER DEFAULT 1,
            token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',
            extra_params               TEXT DEFAULT '{}',
            response_type              TEXT DEFAULT 'code',
            claims_source              TEXT DEFAULT 'both',
            end_session_endpoint       TEXT DEFAULT '',
            logout_redirect_uri        TEXT DEFAULT '',
            enabled                    INTEGER DEFAULT 0,
            is_custom                  INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS oidc_watched_attrs (
            oidc_name   TEXT NOT NULL,
            attr_name   TEXT NOT NULL,
            description TEXT DEFAULT '',
            required    INTEGER DEFAULT 0,
            sort_order  INTEGER DEFAULT 99,
            PRIMARY KEY (oidc_name, attr_name)
        );
        """)
        db.execute("INSERT OR IGNORE INTO idp_config (name,label,is_custom) VALUES ('okta','Okta',0),('duo','Duo',0)")
        for k, v in [("debug_enabled","1"), ("active_idp","duo"), ("active_oidc","duo")]:
            db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k, v))
        # Default watched attribute: mail (required)
        for idp in ("okta","duo"):
            db.execute("""INSERT OR IGNORE INTO idp_watched_attrs
                          (idp_name,attr_name,description,required,sort_order)
                          VALUES (?,?,?,?,?)""",
                       (idp, "mail", "User email address", 1, 0))
        # Default OIDC configs
        for n, lbl in [("okta","Okta"),("duo","Duo")]:
            db.execute("""INSERT OR IGNORE INTO oidc_config
                          (name,label,scopes,redirect_uri,use_pkce,is_custom)
                          VALUES (?,?,?,?,?,0)""",
                       (n, lbl, "openid profile email",
                        f"http://localhost:{PORT}/oidc/callback", 1))
        _oidc_default_claims = [
            ("sub",        "Subject (unique user ID)", 1),
            ("email",      "User email address",       1),
            ("name",       "Full display name",        0),
            ("given_name", "First name",               0),
            ("family_name","Last name",                0),
        ]
        for n in ("okta","duo"):
            for i, (attr, desc, req) in enumerate(_oidc_default_claims):
                db.execute("""INSERT OR IGNORE INTO oidc_watched_attrs
                              (oidc_name,attr_name,description,required,sort_order)
                              VALUES (?,?,?,?,?)""",
                           (n, attr, desc, req, i))
        db.commit()

    # ── Schema migrations ─────────────────────────────────────────────────────
    _migrations = [
        "ALTER TABLE auth_log  ADD COLUMN session_id  TEXT",
        "ALTER TABLE auth_log  ADD COLUMN step        TEXT",
        "ALTER TABLE auth_log  ADD COLUMN level       TEXT DEFAULT 'summary'",
        "ALTER TABLE auth_log  ADD COLUMN detail_json TEXT",
        "ALTER TABLE idp_config ADD COLUMN attr_mapping TEXT DEFAULT '{}'",
        "ALTER TABLE idp_config ADD COLUMN is_custom   INTEGER DEFAULT 0",
        "ALTER TABLE idp_config ADD COLUMN label       TEXT",
        "ALTER TABLE app_meta  ADD COLUMN value TEXT",
        "ALTER TABLE oidc_config ADD COLUMN end_session_endpoint TEXT DEFAULT ''",
        "ALTER TABLE oidc_config ADD COLUMN logout_redirect_uri  TEXT DEFAULT ''",
    ]
    with get_db() as db:
        for sql in _migrations:
            try:
                db.execute(sql)
            except Exception:
                pass
        db.execute("UPDATE auth_log SET level='summary' WHERE level IS NULL")
        db.commit()

    for meta_key in ("user_secret", "admin_secret"):
        if not _db_one("SELECT 1 FROM app_meta WHERE key=?", (meta_key,)):
            _db_write("INSERT INTO app_meta VALUES (?,?)", (meta_key, secrets.token_hex(32)))
    ensure_default_admin()

def _get_secret(key: str) -> str:
    row = _db_one("SELECT value FROM app_meta WHERE key=?", (key,))
    return row["value"] if row else secrets.token_hex(32)

def _user_secret()  -> str: return _get_secret("user_secret")
def _admin_secret() -> str: return _get_secret("admin_secret")

# ── Reset / cache ──────────────────────────────────────────────────────────────
def factory_reset():
    with get_db() as db:
        db.executescript("""
            DELETE FROM auth_log; DELETE FROM users; DELETE FROM idp_config;
            DELETE FROM settings; DELETE FROM app_meta; DELETE FROM user_attributes;
            DELETE FROM idp_watched_attrs; DELETE FROM oidc_config; DELETE FROM oidc_watched_attrs;
        """)
        db.execute("INSERT OR IGNORE INTO idp_config (name,label,is_custom) VALUES ('okta','Okta',0),('duo','Duo',0)")
        for k, v in [("debug_enabled","1"), ("active_idp","duo"), ("active_oidc","duo")]:
            db.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k, v))
        for idp in ("okta","duo"):
            db.execute("""INSERT OR IGNORE INTO idp_watched_attrs
                          (idp_name,attr_name,description,required,sort_order)
                          VALUES (?,?,?,?,?)""",
                       (idp, "mail", "User email address", 1, 0))
        for n, lbl in [("okta","Okta"),("duo","Duo")]:
            db.execute("""INSERT OR IGNORE INTO oidc_config
                          (name,label,scopes,redirect_uri,use_pkce,is_custom)
                          VALUES (?,?,?,?,?,0)""",
                       (n, lbl, "openid profile email",
                        f"http://localhost:{PORT}/oidc/callback", 1))
        _oidc_rc = [("sub","Subject",1),("email","Email",1),("name","Name",0),
                    ("given_name","First name",0),("family_name","Last name",0)]
        for n in ("okta","duo"):
            for i,(a,d,r) in enumerate(_oidc_rc):
                db.execute("INSERT OR IGNORE INTO oidc_watched_attrs VALUES (?,?,?,?,?)", (n,a,d,r,i))
        for mk in ("user_secret","admin_secret"):
            db.execute("INSERT INTO app_meta VALUES (?,?)", (mk, secrets.token_hex(32)))
        db.commit()
    clear_saml_cache()
    ensure_default_admin()

def clear_saml_cache():
    if SAML_TMP.exists():
        shutil.rmtree(str(SAML_TMP), ignore_errors=True)
    SAML_TMP.mkdir(parents=True, exist_ok=True)

# ── Settings ───────────────────────────────────────────────────────────────────
def get_setting(key: str, default="") -> str:
    row = _db_one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default

def set_setting(key: str, value: str):
    _db_write("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))

def export_settings_doc() -> str:
    """Generate a human-readable settings export document."""
    from datetime import datetime as _dt
    now_str = _dt.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    active_idp  = get_setting("active_idp","duo")
    debug_mode  = "Enabled" if is_debug() else "Disabled"

    # Gather IdP summary (no secrets — just names and status)
    idp_lines = []
    for idp in list_idps():
        n   = idp["name"]
        lbl = idp.get("label") or n.capitalize()
        ena = "✓ Enabled" if idp.get("enabled") else "✗ Disabled"
        has_sso = "configured" if idp.get("sso_url") else "NOT configured"
        idp_lines.append(f"  {lbl} ({n})  —  {ena},  SSO URL {has_sso}")
    idp_summary = "\n".join(idp_lines) or "  (none)"

    watched_lines = []
    for idp in list_idps():
        n  = idp["name"]
        wa = get_watched_attrs(n)
        lbl = idp.get("label") or n.capitalize()
        attrs_str = ", ".join(w["attr_name"] for w in wa) or "(none)"
        watched_lines.append(f"  {lbl}: {attrs_str}")
    watched_summary = "\n".join(watched_lines) or "  (none)"

    sep  = "═" * 64
    sep2 = "─" * 64

    doc = f"""{sep}
SAML TestBench — Settings Export
Generated: {now_str}
{sep}

This document describes every configurable setting currently active
in SAML TestBench, where each value lives, and exactly where in the
admin interface (or source code) you can change it.

NOTE: IdP credentials and certificates are NOT included here for
security reasons. Export those separately via Admin → IdP Config →
"Export IdP Configs" (produces a separate idp_config_export.json).

{sep}
SECTION 1 — Authentication Defaults
{sep2}

Setting:       Active SAML IdP
Current Value: {active_idp}
Location:      Admin → Settings → "Active Identity Provider" dropdown
               Also saved per-page on Admin → IdP Config when you click
               "Set as Active IdP" on any IdP form.
Database key:  settings.active_idp
Description:   The default Identity Provider used for SAML flows when no
               ?idp= query parameter is present in the /saml/login request.
               Changing this affects which SSO button is shown on the login page
               and which IdP certificate is used to verify assertions at /saml/acs.

{sep}
SECTION 2 — Logging
{sep2}

Setting:       Debug Logging
Current Value: {debug_mode}
Location:      Admin → Settings → "Debug Logging" toggle
               Also toggle via Admin → Dashboard (the DEBUG ON pill in topbar).
Database key:  settings.debug_enabled  (value "1" = on, "0" = off)
Description:   When enabled, every SAML step is logged at the "debug" level in
               addition to the normal summary record. Debug entries include:
                 • Full SAMLRequest and SAMLResponse XML (base64-decoded)
                 • All attributes from the assertion (not just watched ones)
                 • NameID, NameID format, and session index
                 • Signature and digest algorithm details
                 • Initiating URL, user-agent string, and relay state
               Debug logs are visible on Admin → Logs (look for the DEBUG badge).
               Disabling this reduces database size significantly in high-volume
               testing scenarios.

{sep}
SECTION 3 — Identity Provider Configurations
{sep2}

IdP configurations are stored separately and should be backed up via
Admin → IdP Config → "Export IdP Configs". The summary below shows
current status without sensitive values.

Configured IdPs:
{idp_summary}

{sep2}
SECTION 3a — Watched SAML Attributes (per IdP)
{sep2}

These control which attributes are captured from the SAML assertion and
stored in the user's session after a successful SSO login.
Location: Admin → IdP Config → [select IdP] → "Watched SAML Attributes" card
Database: idp_watched_attrs table  (columns: idp_name, attr_name, description,
          required, sort_order)

Current watched attributes:
{watched_summary}

{sep}
SECTION 4 — Service Provider (SP) Endpoints
{sep2}

These values are generated automatically from the running port ({PORT})
and are shown for reference. They cannot be changed here — if you need
different URLs, run the script on a different port or behind a reverse
proxy and update the "SP Entity ID / ACS URL / SLO URL" fields on each
IdP's configuration form.

ACS URL:     http://localhost:{PORT}/saml/acs
Entity ID:   http://localhost:{PORT}/saml/metadata
SLO URL:     http://localhost:{PORT}/saml/slo

{sep}
SECTION 5 — Application Metadata
{sep2}

Install directory: {APP_DIR}
Database file:     {DB_PATH}
SAML cache dir:    {SAML_TMP}

Cryptographic signing keys (user session secret, admin cookie secret) are
stored in the app_meta table in the database.  They are rotated automatically
on factory reset.  Do NOT share or export these keys.

{sep}
SECTION 6 — Redefining Settings Programmatically
{sep2}

Every setting above can also be changed by calling set_setting() directly
in a Python session against the same database, or by editing the settings
table with an SQLite client:

  sqlite3 {DB_PATH}
  UPDATE settings SET value='duo' WHERE key='active_idp';
  UPDATE settings SET value='1'   WHERE key='debug_enabled';

To restore factory defaults, use Admin → Settings → Danger Zone →
Factory Reset (requires typing RESET and confirming).

{sep}
END OF EXPORT
{sep}
"""
    return doc

def is_debug() -> bool:
    return get_setting("debug_enabled") == "1"

# ── IdP config ─────────────────────────────────────────────────────────────────
def get_idp(name: str) -> dict:
    row = _db_one("SELECT * FROM idp_config WHERE name=?", (name,))
    return dict(row) if row else {}

def list_idps() -> list:
    return _db_all("SELECT * FROM idp_config ORDER BY is_custom, name")

def save_idp(name: str, data: dict):
    existing = get_idp(name)
    if existing:
        _db_write("""UPDATE idp_config SET
            entity_id=?, sso_url=?, slo_url=?, x509_cert=?,
            sp_entity=?, sp_acs=?, sp_slo=?, enabled=?, attr_mapping=?, label=?
            WHERE name=?""",
            (data.get("entity_id",""), data.get("sso_url",""),
             data.get("slo_url",""), data.get("x509_cert",""),
             data.get("sp_entity", f"http://localhost:{PORT}/saml/metadata"),
             data.get("sp_acs",    f"http://localhost:{PORT}/saml/acs"),
             data.get("sp_slo",    f"http://localhost:{PORT}/saml/slo"),
             1 if data.get("enabled") else 0,
             json.dumps(data.get("attr_mapping",{})),
             data.get("label", name.capitalize()),
             name))
    else:
        _db_write("""INSERT INTO idp_config
            (name,label,entity_id,sso_url,slo_url,x509_cert,sp_entity,sp_acs,sp_slo,enabled,attr_mapping,is_custom)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,1)""",
            (name, data.get("label", name),
             data.get("entity_id",""), data.get("sso_url",""),
             data.get("slo_url",""), data.get("x509_cert",""),
             data.get("sp_entity", f"http://localhost:{PORT}/saml/metadata"),
             data.get("sp_acs",    f"http://localhost:{PORT}/saml/acs"),
             data.get("sp_slo",    f"http://localhost:{PORT}/saml/slo"),
             1 if data.get("enabled") else 0,
             json.dumps(data.get("attr_mapping",{}))))

def delete_custom_idp(name: str):
    _db_write("DELETE FROM idp_config WHERE name=? AND is_custom=1", (name,))
    _db_write("DELETE FROM idp_watched_attrs WHERE idp_name=?", (name,))

def export_idp_config() -> dict:
    """Produce a portable dict of all IdP configs + watched attrs."""
    idps = []
    for idp in list_idps():
        n = idp["name"]
        watched = get_watched_attrs(n)
        idps.append({
            "name":         n,
            "label":        idp.get("label") or n.capitalize(),
            "entity_id":    idp.get("entity_id",""),
            "sso_url":      idp.get("sso_url",""),
            "slo_url":      idp.get("slo_url",""),
            "x509_cert":    idp.get("x509_cert",""),
            "sp_entity":    idp.get("sp_entity",""),
            "sp_acs":       idp.get("sp_acs",""),
            "sp_slo":       idp.get("sp_slo",""),
            "enabled":      bool(idp.get("enabled")),
            "attr_mapping": json.loads(idp.get("attr_mapping") or "{}"),
            "is_custom":    bool(idp.get("is_custom")),
            "watched_attrs": [
                {"attr_name":   w["attr_name"],
                 "description": w.get("description",""),
                 "required":    bool(w.get("required")),
                 "sort_order":  w.get("sort_order", 99)}
                for w in watched
            ],
        })
    return {
        "export_version": "1",
        "app":            "saml_testbench",
        "exported_at":    _now_ts(),
        "idps":           idps,
    }

def import_idp_config(payload: dict) -> tuple:
    """
    Import IdP configs from an export_idp_config() payload.
    Returns (imported_count, skipped_count, error_msg).
    """
    idps = payload.get("idps", [])
    if not isinstance(idps, list):
        return 0, 0, "Invalid format: 'idps' list not found."
    imported = 0
    skipped  = 0
    for entry in idps:
        try:
            name = entry.get("name","").strip().lower()
            if not name:
                skipped += 1; continue
            save_idp(name, {
                "label":       entry.get("label", name.capitalize()),
                "entity_id":   entry.get("entity_id",""),
                "sso_url":     entry.get("sso_url",""),
                "slo_url":     entry.get("slo_url",""),
                "x509_cert":   entry.get("x509_cert",""),
                "sp_entity":   entry.get("sp_entity", f"http://localhost:{PORT}/saml/metadata"),
                "sp_acs":      entry.get("sp_acs",    f"http://localhost:{PORT}/saml/acs"),
                "sp_slo":      entry.get("sp_slo",    f"http://localhost:{PORT}/saml/slo"),
                "enabled":     entry.get("enabled", False),
                "attr_mapping":entry.get("attr_mapping", {}),
            })
            # Restore watched attrs (skip if already have required ones)
            for wa in entry.get("watched_attrs", []):
                an = wa.get("attr_name","").strip()
                if not an:
                    continue
                with get_db() as db:
                    db.execute("""INSERT OR REPLACE INTO idp_watched_attrs
                                  (idp_name,attr_name,description,required,sort_order)
                                  VALUES (?,?,?,?,?)""",
                               (name, an, wa.get("description",""),
                                1 if wa.get("required") else 0,
                                wa.get("sort_order",99)))
                    db.commit()
            imported += 1
        except Exception:
            skipped += 1
    return imported, skipped, None

# ═══════════════════════════════════════════════════════════════
# OIDC DATA LAYER
# ═══════════════════════════════════════════════════════════════
def get_oidc_config(name: str) -> dict:
    row = _db_one("SELECT * FROM oidc_config WHERE name=?", (name,))
    return dict(row) if row else {}

def list_oidc_configs() -> list:
    return _db_all("SELECT * FROM oidc_config ORDER BY is_custom, name")

def save_oidc_config(name: str, data: dict):
    redirect_uri = data.get("redirect_uri") or f"http://localhost:{PORT}/oidc/callback"
    extra_raw = data.get("extra_params", {})
    extra_json = json.dumps(extra_raw) if isinstance(extra_raw, dict) else (extra_raw or "{}")
    vals = (
        data.get("label", name.capitalize()),
        data.get("discovery_url",""), data.get("client_id",""),
        data.get("client_secret",""),
        data.get("authorization_endpoint",""), data.get("token_endpoint",""),
        data.get("userinfo_endpoint",""), data.get("jwks_uri",""),
        data.get("issuer",""), data.get("scopes","openid profile email"),
        redirect_uri,
        1 if data.get("use_pkce", True) else 0,
        data.get("token_endpoint_auth_method","client_secret_post"),
        extra_json,
        data.get("response_type","code"),
        data.get("claims_source","both"),
        data.get("end_session_endpoint",""),
        data.get("logout_redirect_uri",""),
        1 if data.get("enabled") else 0,
    )
    if get_oidc_config(name):
        _db_write("""UPDATE oidc_config SET
            label=?,discovery_url=?,client_id=?,client_secret=?,
            authorization_endpoint=?,token_endpoint=?,userinfo_endpoint=?,
            jwks_uri=?,issuer=?,scopes=?,redirect_uri=?,use_pkce=?,
            token_endpoint_auth_method=?,extra_params=?,response_type=?,
            claims_source=?,end_session_endpoint=?,logout_redirect_uri=?,enabled=?
            WHERE name=?""", vals + (name,))
    else:
        _db_write("""INSERT INTO oidc_config
            (label,discovery_url,client_id,client_secret,
             authorization_endpoint,token_endpoint,userinfo_endpoint,
             jwks_uri,issuer,scopes,redirect_uri,use_pkce,
             token_endpoint_auth_method,extra_params,response_type,
             claims_source,end_session_endpoint,logout_redirect_uri,enabled,is_custom,name)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)""", vals + (name,))

def delete_custom_oidc(name: str):
    _db_write("DELETE FROM oidc_config WHERE name=? AND is_custom=1", (name,))
    _db_write("DELETE FROM oidc_watched_attrs WHERE oidc_name=?", (name,))

def get_oidc_watched_attrs(oidc_name: str) -> list:
    return _db_all(
        "SELECT * FROM oidc_watched_attrs WHERE oidc_name=? ORDER BY sort_order,attr_name",
        (oidc_name,))

def save_oidc_watched_attrs(oidc_name: str, attrs: list):
    with get_db() as db:
        db.execute("DELETE FROM oidc_watched_attrs WHERE oidc_name=? AND required=0", (oidc_name,))
        for i, a in enumerate(attrs):
            if a.get("attr_name","").strip():
                db.execute("""INSERT OR REPLACE INTO oidc_watched_attrs
                              (oidc_name,attr_name,description,required,sort_order)
                              VALUES (?,?,?,?,?)""",
                           (oidc_name, a["attr_name"].strip(),
                            a.get("description",""), 0, i+1))
        db.commit()

def export_oidc_config() -> dict:
    oidcs = []
    for cfg in list_oidc_configs():
        n = cfg["name"]
        watched = get_oidc_watched_attrs(n)
        oidcs.append({
            "name": n, "label": cfg.get("label") or n.capitalize(),
            "discovery_url": cfg.get("discovery_url",""),
            "client_id": cfg.get("client_id",""),
            "authorization_endpoint": cfg.get("authorization_endpoint",""),
            "token_endpoint": cfg.get("token_endpoint",""),
            "userinfo_endpoint": cfg.get("userinfo_endpoint",""),
            "jwks_uri": cfg.get("jwks_uri",""),
            "issuer": cfg.get("issuer",""),
            "scopes": cfg.get("scopes","openid profile email"),
            "redirect_uri": cfg.get("redirect_uri",""),
            "use_pkce": bool(cfg.get("use_pkce",1)),
            "token_endpoint_auth_method": cfg.get("token_endpoint_auth_method","client_secret_post"),
            "extra_params": json.loads(cfg.get("extra_params") or "{}"),
            "response_type": cfg.get("response_type","code"),
            "claims_source": cfg.get("claims_source","both"),
            "end_session_endpoint": cfg.get("end_session_endpoint",""),
            "logout_redirect_uri": cfg.get("logout_redirect_uri",""),
            "enabled": bool(cfg.get("enabled")),
            "is_custom": bool(cfg.get("is_custom")),
            "watched_attrs": [{"attr_name":w["attr_name"],"description":w.get("description",""),
                                "required":bool(w.get("required")),"sort_order":w.get("sort_order",99)}
                               for w in watched],
        })
    return {"export_version":"1","app":"saml_testbench","type":"oidc",
            "exported_at":_now_ts(),"oidcs":oidcs}

def import_oidc_config(payload: dict) -> tuple:
    oidcs = payload.get("oidcs",[])
    if not isinstance(oidcs, list):
        return 0, 0, "'oidcs' list not found"
    imported = skipped = 0
    for entry in oidcs:
        try:
            name = entry.get("name","").strip().lower()
            if not name: skipped += 1; continue
            save_oidc_config(name, {k:v for k,v in entry.items()
                                    if k not in ("name","watched_attrs","is_custom")})
            for wa in entry.get("watched_attrs",[]):
                an = wa.get("attr_name","").strip()
                if not an: continue
                with get_db() as db:
                    db.execute("INSERT OR REPLACE INTO oidc_watched_attrs VALUES (?,?,?,?,?)",
                               (name, an, wa.get("description",""),
                                1 if wa.get("required") else 0, wa.get("sort_order",99)))
                    db.commit()
            imported += 1
        except Exception:
            skipped += 1
    return imported, skipped, None


# ── Watched attributes ─────────────────────────────────────────────────────────
def get_watched_attrs(idp_name: str) -> list:
    return _db_all(
        "SELECT * FROM idp_watched_attrs WHERE idp_name=? ORDER BY sort_order, attr_name",
        (idp_name,)
    )

def save_watched_attrs(idp_name: str, attrs: list):
    """attrs = [{'attr_name':str, 'description':str, 'required':bool}]"""
    with get_db() as db:
        db.execute("DELETE FROM idp_watched_attrs WHERE idp_name=? AND required=0", (idp_name,))
        for i, a in enumerate(attrs):
            if a.get("attr_name","").strip():
                db.execute("""INSERT OR REPLACE INTO idp_watched_attrs
                              (idp_name,attr_name,description,required,sort_order)
                              VALUES (?,?,?,?,?)""",
                           (idp_name, a["attr_name"].strip(),
                            a.get("description",""), 0, i+1))
        db.commit()

# ── User management ────────────────────────────────────────────────────────────
def _hash_pw(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2:{salt}:{dk.hex()}"

def _check_pw(stored: str, candidate: str) -> bool:
    try:
        _, salt, dk_hex = stored.split(":", 2)
        dk = hashlib.pbkdf2_hmac("sha256", candidate.encode(), salt.encode(), 260000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

def ensure_default_admin():
    row = _db_one("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if not row:
        _db_write("INSERT INTO users VALUES (?,?,?,?,?,?)",
                  (str(uuid.uuid4()), "admin", "admin@localhost",
                   _hash_pw("admin123"), "admin", _now_ts()))
        print("\n┌─────────────────────────────────────────┐")
        print("│  Default admin account created:          │")
        print("│    Username : admin                      │")
        print("│    Password : admin123                   │")
        print("│  Change this after first login!          │")
        print("└─────────────────────────────────────────┘\n")

def list_users() -> list:
    return _db_all("SELECT * FROM users ORDER BY created DESC")

def get_user_by_username(username: str):
    row = _db_one("SELECT * FROM users WHERE username=?", (username,))
    return dict(row) if row else None

def create_user(username: str, email: str, password: str, role="user"):
    if not username or not password:
        return False, "Username and password are required."
    if get_user_by_username(username):
        return False, f"Username '{username}' already exists."
    try:
        uid = str(uuid.uuid4())
        _db_write("INSERT INTO users VALUES (?,?,?,?,?,?)",
                  (uid, username, email, _hash_pw(password), role, _now_ts()))
        return True, uid
    except Exception as e:
        return False, str(e)

def delete_user(uid: str):
    _db_write("DELETE FROM users WHERE id=?", (uid,))
    _db_write("DELETE FROM user_attributes WHERE user_id=?", (uid,))

def get_user_attrs(user_id: str) -> list:
    return _db_all("SELECT * FROM user_attributes WHERE user_id=? ORDER BY key", (user_id,))

def set_user_attrs(user_id: str, attrs: dict):
    """Replace all custom attributes for a user."""
    with get_db() as db:
        db.execute("DELETE FROM user_attributes WHERE user_id=?", (user_id,))
        for k, v in attrs.items():
            if k.strip():
                db.execute("INSERT INTO user_attributes VALUES (?,?,?,?)",
                           (str(uuid.uuid4()), user_id, k.strip(), v))
        db.commit()

# ── Timestamps ─────────────────────────────────────────────────────────────────
def _now_ts() -> str:
    """Current local time as ISO string with offset."""
    return datetime.now().astimezone().isoformat(timespec="seconds")

def _fmt_ts(ts_str: str) -> str:
    """Parse any ISO timestamp and format in local time."""
    if not ts_str:
        return "—"
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_str[:19].replace("T", " ")

# ── Auth logging ───────────────────────────────────────────────────────────────
def _current_ip() -> str:
    try:
        return request.remote_addr or "—"
    except RuntimeError:
        return "—"

def log_step(step: str, event: str, idp: str, success: bool,
             username: str = None, error: str = None,
             detail: dict = None, level: str = "summary",
             session_id: str = None):
    if level == "debug" and not is_debug():
        return
    detail_json = json.dumps(detail, default=str) if (detail and is_debug()) else None
    with get_db() as db:
        db.execute(
            """INSERT INTO auth_log
               (id,session_id,ts,step,event,idp,level,success,username,detail_json,error,ip)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), session_id or "",
             _now_ts(), step, event, idp, level,
             1 if success else 0,
             username, detail_json, error, _current_ip())
        )
        db.commit()

def get_auth_logs(limit: int = 500) -> list:
    return _db_all("SELECT * FROM auth_log ORDER BY ts DESC LIMIT ?", (limit,))

def clear_auth_logs():
    _db_write("DELETE FROM auth_log")

def group_logs(events: list) -> list:
    """
    Group log entries by session_id, then merge orphaned no-username groups
    (Steps 1/2 whose session_id was lost across the IdP redirect, or logout
    entries logged with no session_id) into the nearest same-IP/same-IdP group
    within a 30-minute window.
    """
    # ── Pass 1: group by session_id ────────────────────────────────────────────
    seen = {}
    groups = []
    for ev in events:
        sid = ev.get("session_id") or f"__solo_{ev.get('id','')}"
        if sid not in seen:
            seen[sid] = len(groups)
            groups.append({"session_id": sid, "steps": []})
        groups[seen[sid]]["steps"].append(ev)

    # ── Pass 2: build per-group summary metadata ───────────────────────────────
    def _summarise(g):
        steps = g["steps"]
        steps.reverse()   # sort chronological (events came in DESC order)
        username = next((s["username"] for s in reversed(steps) if s.get("username")), None)
        for s in steps:
            s["_display_user"] = s.get("username") or username or "—"
        summary_steps = [s for s in steps if s.get("level") != "debug"]
        last_summary  = summary_steps[-1] if summary_steps else (steps[-1] if steps else {})
        g["_username"]  = username
        g["_ip"]        = steps[0].get("ip","") if steps else ""
        g["_idp"]       = steps[0].get("idp","") if steps else ""
        g["_ts_first"]  = steps[0].get("ts","")  if steps else ""
        g["_ts_last"]   = steps[-1].get("ts","") if steps else ""
        g["summary"]    = {
            "ts":         g["_ts_first"],
            "idp":        g["_idp"] or "—",
            "username":   username or "—",
            "ip":         g["_ip"] or "—",
            "success":    last_summary.get("success"),
            "error":      next((s.get("error") for s in steps if s.get("error")), None),
            "step_count": len(summary_steps),
            "last_step":  last_summary.get("step",""),
        }

    for g in groups:
        _summarise(g)

    # ── Pass 3: merge orphaned groups into the closest named group ─────────────
    # An "orphan" group has no username across all its steps, AND its session_id
    # either never existed (solo) or represents only steps without identity data
    # (Steps 1/2 whose saml_flow_id was lost across the IdP redirect).
    def _ts_epoch(ts_str):
        if not ts_str:
            return 0
        try:
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return 0

    # ── Pass 3a: merge orphaned (no-username) groups by IP+IdP proximity ─────────
    # Handles: Steps 1/2 whose saml_flow_id was lost across the IdP redirect.
    MERGE_WINDOW_SECS = 1800   # 30 minutes — same browser session
    named_groups  = [g for g in groups if g["_username"]]
    orphan_groups = [g for g in groups if not g["_username"]]

    absorbed = set()
    for orphan in orphan_groups:
        o_ip  = orphan["_ip"]
        o_idp = orphan["_idp"]
        o_t1  = _ts_epoch(orphan["_ts_first"])
        o_t2  = _ts_epoch(orphan["_ts_last"])

        best_match = None
        best_dist  = float("inf")

        for named in named_groups:
            if o_ip and named["_ip"] and o_ip != named["_ip"]:
                continue
            if o_idp and named["_idp"] and o_idp != named["_idp"]:
                continue
            n_t1 = _ts_epoch(named["_ts_first"])
            n_t2 = _ts_epoch(named["_ts_last"])
            dist = max(0, max(o_t1, n_t1) - min(o_t2, n_t2))
            if dist <= MERGE_WINDOW_SECS and dist < best_dist:
                best_dist  = dist
                best_match = named

        if best_match is not None:
            best_match["steps"].extend(orphan["steps"])
            best_match["steps"].sort(key=lambda s: s.get("ts",""))
            absorbed.add(id(orphan))
            _summarise(best_match)

    groups = [g for g in groups if id(g) not in absorbed]

    # ── Pass 3b: merge solo named groups (e.g. bare logout entry) into the
    #    primary flow group with the same username + IP + IdP ──────────────────
    # A "solo" group is one with only 1 summary step — typically a logout that
    # was logged without a session_id, or any other standalone event that
    # belongs to a larger already-merged flow.
    named_groups = [g for g in groups if g["_username"]]
    named_groups.sort(key=lambda g: len(g["steps"]), reverse=True)  # biggest first

    absorbed2 = set()
    for solo in named_groups:
        if len(solo["steps"]) > 2:          # not a solo/tiny group → skip
            continue
        if id(solo) in absorbed2:
            continue
        s_user = solo["_username"]
        s_ip   = solo["_ip"]
        s_idp  = solo["_idp"]
        s_t1   = _ts_epoch(solo["_ts_first"])
        s_t2   = _ts_epoch(solo["_ts_last"])

        best_match = None
        best_dist  = float("inf")

        for named in named_groups:
            if id(named) == id(solo):
                continue
            if id(named) in absorbed2:
                continue
            if named["_username"] != s_user:
                continue
            if s_ip and named["_ip"] and s_ip != named["_ip"]:
                continue
            if s_idp and named["_idp"] and s_idp != named["_idp"]:
                continue
            if len(named["steps"]) <= len(solo["steps"]):
                continue   # don't merge bigger into smaller
            n_t1 = _ts_epoch(named["_ts_first"])
            n_t2 = _ts_epoch(named["_ts_last"])
            dist = max(0, max(s_t1, n_t1) - min(s_t2, n_t2))
            if dist <= MERGE_WINDOW_SECS and dist < best_dist:
                best_dist  = dist
                best_match = named

        if best_match is not None:
            best_match["steps"].extend(solo["steps"])
            best_match["steps"].sort(key=lambda s: s.get("ts",""))
            absorbed2.add(id(solo))
            _summarise(best_match)

    groups = [g for g in groups if id(g) not in absorbed2]

    # Final sort: newest group first (by first-step timestamp)
    groups.sort(key=lambda g: g["_ts_first"], reverse=True)
    return groups

# ── Browser detection ──────────────────────────────────────────────────────────
def detect_browsers() -> list:
    """Return list of {name, path, incognito_flag} for installed browsers."""
    found = []
    sys_platform = platform.system()

    def _check(name, paths, flag):
        for p in paths:
            expanded = os.path.expandvars(p)
            if os.path.isfile(expanded):
                found.append({"name": name, "path": expanded, "flag": flag})
                return

    if sys_platform == "Windows":
        _check("Google Chrome", [
            r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe",
            r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe",
            r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe",
        ], "--incognito")
        _check("Microsoft Edge", [
            r"%PROGRAMFILES(X86)%\Microsoft\Edge\Application\msedge.exe",
            r"%PROGRAMFILES%\Microsoft\Edge\Application\msedge.exe",
        ], "--inprivate")
        _check("Mozilla Firefox", [
            r"%PROGRAMFILES%\Mozilla Firefox\firefox.exe",
            r"%PROGRAMFILES(X86)%\Mozilla Firefox\firefox.exe",
        ], "--private-window")
        _check("Brave", [
            r"%PROGRAMFILES%\BraveSoftware\Brave-Browser\Application\brave.exe",
            r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe",
        ], "--incognito")
        _check("Opera", [
            r"%LOCALAPPDATA%\Programs\Opera\opera.exe",
        ], "--private")

    elif sys_platform == "Darwin":
        _check("Google Chrome", [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ], "--incognito")
        _check("Microsoft Edge", [
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ], "--inprivate")
        _check("Mozilla Firefox", [
            "/Applications/Firefox.app/Contents/MacOS/firefox",
        ], "--private-window")
        _check("Brave", [
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ], "--incognito")

    else:  # Linux
        for cmd, flag in [
            ("google-chrome", "--incognito"),
            ("google-chrome-stable", "--incognito"),
            ("chromium", "--incognito"),
            ("chromium-browser", "--incognito"),
            ("microsoft-edge", "--inprivate"),
            ("firefox", "--private-window"),
            ("brave-browser", "--incognito"),
            ("opera", "--private"),
        ]:
            try:
                result = subprocess.run(["which", cmd], capture_output=True, text=True)
                if result.returncode == 0:
                    path = result.stdout.strip()
                    name = cmd.replace("-stable","").replace("-browser","").replace("-"," ").title()
                    found.append({"name": name, "path": path, "flag": flag})
            except Exception:
                pass

    # Add custom saved browsers from DB
    raw = _db_one("SELECT value FROM app_meta WHERE key='custom_browsers'")
    if raw and raw["value"]:
        try:
            for cb in json.loads(raw["value"]):
                if os.path.isfile(cb["path"]):
                    found.append(cb)
        except Exception:
            pass

    return found

def save_custom_browser(name: str, path: str, flag: str):
    existing_raw = _db_one("SELECT value FROM app_meta WHERE key='custom_browsers'")
    existing = json.loads(existing_raw["value"]) if existing_raw and existing_raw["value"] else []
    # Dedup by path
    existing = [b for b in existing if b["path"] != path]
    existing.append({"name": name, "path": path, "flag": flag})
    val = json.dumps(existing)
    _db_write("INSERT OR REPLACE INTO app_meta VALUES ('custom_browsers',?)", (val,))

# ═══════════════════════════════════════════════════════════════
# OIDC HELPERS
# ═══════════════════════════════════════════════════════════════
def oidc_fetch_discovery(url: str) -> tuple:
    if not _HTTP_OK:
        return {}, "requests library not installed"
    try:
        r = _http.get(url, timeout=10)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return {}, str(e)

def oidc_pkce_pair() -> tuple:
    import hashlib as _hl
    verifier  = base64.urlsafe_b64encode(secrets.token_bytes(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(_hl.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge

def oidc_build_auth_url(cfg: dict, state: str, nonce: str, code_challenge: str = None) -> str:
    from urllib.parse import urlencode
    params = {
        "client_id":     cfg["client_id"],
        "response_type": cfg.get("response_type","code"),
        "scope":         cfg.get("scopes","openid profile email"),
        "redirect_uri":  cfg.get("redirect_uri", f"http://localhost:{PORT}/oidc/callback"),
        "state": state, "nonce": nonce,
    }
    if code_challenge:
        params["code_challenge"]        = code_challenge
        params["code_challenge_method"] = "S256"
    try:
        extra = json.loads(cfg.get("extra_params") or "{}")
        params.update({k:v for k,v in extra.items() if k and v})
    except Exception:
        pass
    return cfg["authorization_endpoint"] + "?" + urlencode(params)

def oidc_exchange_code(cfg: dict, code: str, code_verifier: str = None) -> tuple:
    if not _HTTP_OK:
        return {}, "requests not installed"
    data = {
        "grant_type":   "authorization_code",
        "code":         code,
        "redirect_uri": cfg.get("redirect_uri", f"http://localhost:{PORT}/oidc/callback"),
        "client_id":    cfg["client_id"],
    }
    if code_verifier:
        data["code_verifier"] = code_verifier
    auth = None
    if cfg.get("client_secret"):
        if cfg.get("token_endpoint_auth_method","client_secret_post") == "client_secret_basic":
            auth = (cfg["client_id"], cfg["client_secret"])
        else:
            data["client_secret"] = cfg["client_secret"]
    try:
        r = _http.post(cfg["token_endpoint"], data=data,
                       headers={"Accept":"application/json"}, auth=auth, timeout=15)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        body = ""
        try: body = e.response.text[:300]
        except Exception: pass
        return {}, f"{e}" + (f" — {body}" if body else "")

def oidc_get_userinfo(cfg: dict, access_token: str) -> tuple:
    ep = cfg.get("userinfo_endpoint","")
    if not ep or not _HTTP_OK:
        return {}, None
    try:
        r = _http.get(ep, headers={"Authorization":f"Bearer {access_token}"}, timeout=10)
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return {}, str(e)

def oidc_decode_id_token(cfg: dict, id_token: str, nonce: str) -> tuple:
    import time as _t
    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            return {}, "Malformed JWT (expected 3 parts)"
        def _b64d(s):
            s += "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s)
        header  = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
    except Exception as e:
        return {}, f"JWT decode error: {e}"
    now = int(_t.time())
    if payload.get("exp",0) and now > payload["exp"] + 60:
        return {}, "ID token expired"
    if payload.get("iat",0) and now < payload["iat"] - 300:
        return {}, "ID token issued in the future"
    if nonce and payload.get("nonce") and payload["nonce"] != nonce:
        return {}, "Nonce mismatch"
    if cfg.get("issuer") and payload.get("iss","") != cfg["issuer"]:
        return {}, f"Issuer mismatch: expected {cfg['issuer']!r}"
    client_id = cfg.get("client_id","")
    if client_id and payload.get("aud"):
        aud = payload["aud"]
        if client_id not in (aud if isinstance(aud, list) else [aud]):
            return {}, "Audience mismatch"
    if _JWT_OK and _JWT_CRYPTO_OK and cfg.get("jwks_uri") and _HTTP_OK:
        try:
            alg = header.get("alg","RS256")
            kid = header.get("kid")
            r = _http.get(cfg["jwks_uri"], timeout=8)
            r.raise_for_status()
            keys = r.json().get("keys",[])
            kd = next((k for k in keys if k.get("kid")==kid), None) if kid else (keys[0] if keys else None)
            if kd:
                AlgCls = _RSAAlgorithm if alg.startswith(("RS","PS")) else _ECAlgorithm
                pub = AlgCls.from_jwk(json.dumps(kd))
                return _jwt.decode(id_token, pub, algorithms=[alg],
                                   audience=client_id or None,
                                   options={"verify_iat":False,"verify_nbf":False}), None
        except Exception as sig_err:
            return {}, f"Signature verification failed: {sig_err}"
    elif _JWT_OK and not _JWT_CRYPTO_OK:
        # PyJWT is installed but without cryptography — skip sig verification,
        # log a warning in the claims so it surfaces in debug logs.
        payload["_signature_not_verified"] = True
        payload["_sig_skip_reason"] = "PyJWT installed without cryptography (pip install PyJWT[cryptography])"
    payload["_signature_not_verified"] = True
    return payload, None

def oidc_extract_username(claims: dict) -> str:
    return (claims.get("preferred_username") or
            claims.get("email") or claims.get("sub") or "unknown")


# ═══════════════════════════════════════════════════════════════
# PHASE 6 — SAML HELPERS
# ═══════════════════════════════════════════════════════════════
def _prepare_saml_dir(idp_name: str):
    cfg = get_idp(idp_name)
    if not cfg or not cfg.get("sso_url"):
        return None
    tmpdir = SAML_TMP / idp_name
    tmpdir.mkdir(parents=True, exist_ok=True)

    cert = re.sub(r"-----.*?-----|\s", "", cfg.get("x509_cert", ""))
    settings = {
        "strict": True, "debug": False,
        "sp": {
            "entityId": cfg["sp_entity"],
            "assertionConsumerService": {
                "url": cfg["sp_acs"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": cfg["sp_slo"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": "", "privateKey": ""
        },
        "idp": {
            "entityId": cfg["entity_id"],
            "singleSignOnService": {"url": cfg["sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
            "singleLogoutService": {"url": cfg["slo_url"] or cfg["sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"},
            "x509cert": cert
        }
    }
    adv = {"security": {
        "nameIdEncrypted": False, "authnRequestsSigned": False,
        "logoutRequestSigned": False, "logoutResponseSigned": False,
        "signMetadata": False, "wantMessagesSigned": False,
        "wantAssertionsSigned": False, "wantAssertionsEncrypted": False,
        "wantNameIdEncrypted": False, "requestedAuthnContext": False,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm":    "http://www.w3.org/2001/04/xmlenc#sha256"
    }}
    with open(tmpdir / "settings.json", "w") as f:
        json.dump(settings, f)
    with open(tmpdir / "advanced_settings.json", "w") as f:
        json.dump(adv, f)
    return str(tmpdir)

def init_saml(idp_name: str):
    if not SAML_OK:
        raise RuntimeError("python3-saml is not installed.")
    path = _prepare_saml_dir(idp_name)
    if not path:
        raise ValueError(f"IdP '{idp_name}' is not configured. Go to Admin → IdP Config and fill in details.")
    req = {
        "https":       "on" if request.scheme == "https" else "off",
        "http_host":   request.host,
        "server_port": request.environ.get("SERVER_PORT", PORT),
        "script_name": request.path,
        "get_data":    request.args.copy(),
        "post_data":   request.form.copy(),
    }
    return OneLogin_Saml2_Auth(req, custom_base_path=path)

def _safe_redirect_url(relay: str, fallback: str) -> str:
    from urllib.parse import urlparse
    if relay:
        try:
            p = urlparse(relay)
            if not p.scheme or p.netloc in ("", f"localhost:{PORT}", f"127.0.0.1:{PORT}"):
                return relay
        except Exception:
            pass
    return fallback

# ═══════════════════════════════════════════════════════════════
# PHASE 7 — CSS & SHARED LAYOUT
# ═══════════════════════════════════════════════════════════════

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Instrument+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&family=JetBrains+Mono:wght@400;600;700&display=swap');
:root{
  --bg:#07090f;--surface:#0e1420;--surface2:#141d2e;
  --border:#1a2640;--border2:#243552;
  --accent:#00e5ff;--accent2:#7c3aed;
  --success:#22c55e;--danger:#ef4444;--warning:#f59e0b;
  --text:#dde6f5;--muted:#4a637a;
  --ff:'Instrument Sans',sans-serif;--fm:'JetBrains Mono',monospace;
  --r:10px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--ff);
  min-height:100vh;display:flex;flex-direction:column;
  font-size:15px;font-stretch:normal;letter-spacing:normal}

/* TOPBAR */
.topbar{display:flex;align-items:center;gap:1rem;padding:.7rem 1.5rem;
  background:var(--surface);border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:100}
.topbar-brand{font-size:.95rem;font-weight:700;
  color:var(--accent);text-decoration:none;display:flex;align-items:center;gap:.5rem}
.topbar-brand span{color:var(--text)}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:.75rem}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--success);
  box-shadow:0 0 6px var(--success)}
.status-dot.off{background:var(--muted);box-shadow:none}
.topbar-user{font-family:var(--fm);font-size:.72rem;color:var(--muted)}
.btn-folder{background:transparent;border:1px solid var(--border2);
  color:var(--muted);font-size:.72rem;padding:.3rem .65rem;border-radius:6px;
  cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:.35rem;
  font-family:var(--ff);transition:all .15s}
.btn-folder:hover{color:var(--text);border-color:var(--accent)}

/* LAYOUT */
.layout{display:flex;flex:1}
.sidebar{width:215px;flex-shrink:0;background:var(--surface);
  border-right:1px solid var(--border);padding:1.5rem 0}
.sidebar-section{font-family:var(--fm);font-size:.63rem;font-weight:700;
  letter-spacing:.12em;text-transform:uppercase;color:var(--muted);
  padding:.5rem 1.25rem;margin-top:.75rem}
.sidebar a{display:flex;align-items:center;gap:.6rem;
  font-size:.82rem;font-weight:600;color:var(--muted);
  text-decoration:none;padding:.52rem 1.25rem;
  border-left:3px solid transparent;transition:color .15s,background .15s,border-color .15s}
.sidebar a:hover{color:var(--text);background:var(--surface2)}
.sidebar a.active{color:var(--accent);border-left-color:var(--accent);background:rgba(0,229,255,.06)}
.sidebar-icon{font-size:.88rem;width:1.2rem;text-align:center}
.content{flex:1;padding:2rem;overflow-y:auto;max-width:1200px}

/* FLASH */
.alert{font-size:.82rem;font-weight:600;padding:.7rem 1rem;
  border-radius:var(--r);border-left:3px solid;margin-bottom:.6rem}
.alert-success{background:rgba(34,197,94,.08);border-color:var(--success);color:var(--success)}
.alert-danger{background:rgba(239,68,68,.08);border-color:var(--danger);color:var(--danger)}
.alert-warning{background:rgba(245,158,11,.08);border-color:var(--warning);color:var(--warning)}
.alert-info{background:rgba(0,229,255,.08);border-color:var(--accent);color:var(--accent)}

/* PAGE TITLE */
.page-hd{margin-bottom:1.75rem}
.page-hd h1{font-size:1.55rem;font-weight:700;letter-spacing:-.02em}
.page-hd p{color:var(--muted);font-size:.85rem;margin-top:.3rem}

/* CARDS */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  overflow:hidden;margin-bottom:1.5rem}
.card-hd{padding:.85rem 1.2rem;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;gap:.75rem}
.card-title{font-family:var(--fm);font-size:.68rem;font-weight:700;
  letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.card-body{padding:1.2rem}

/* GRID */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}
@media(max-width:800px){.g2,.g3,.g4{grid-template-columns:1fr}}

/* STAT CARD */
.stat{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);
  padding:1.1rem;display:flex;flex-direction:column;gap:.4rem}
.stat-label{font-family:var(--fm);font-size:.65rem;font-weight:700;
  letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.stat-value{font-family:var(--fm);font-size:1.45rem;font-weight:700;color:var(--accent)}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:.45rem;
  font-family:var(--ff);font-size:.78rem;font-weight:600;
  letter-spacing:.02em;
  padding:.5rem 1.05rem;border-radius:8px;border:none;
  cursor:pointer;text-decoration:none;transition:opacity .15s,transform .1s}
.btn:active{transform:scale(.97)}
.btn-primary{background:var(--accent);color:#000}
.btn-secondary{background:var(--border2);color:var(--text)}
.btn-danger{background:var(--danger);color:#fff}
.btn-outline{background:transparent;color:var(--accent);border:1.5px solid var(--accent)}
.btn-success{background:var(--success);color:#000}
.btn-launch{background:linear-gradient(135deg,var(--accent),#0090ff);color:#000;
  font-size:.88rem;padding:.65rem 1.4rem;border-radius:10px;font-weight:700;
  box-shadow:0 0 18px rgba(0,229,255,.28);animation:pulse-btn 2.5s ease-in-out infinite}
@keyframes pulse-btn{0%,100%{box-shadow:0 0 18px rgba(0,229,255,.28)}
  50%{box-shadow:0 0 32px rgba(0,229,255,.55)}}
.btn:hover{opacity:.88}
.btn-sm{font-size:.7rem;padding:.34rem .68rem}

/* FORMS */
.form-group{margin-bottom:1.1rem}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.1rem}
label{display:block;font-family:var(--fm);font-size:.68rem;font-weight:700;
  letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:.38rem}
input,select,textarea{width:100%;background:var(--bg);color:var(--text);
  border:1px solid var(--border2);border-radius:8px;
  font-family:var(--fm);font-size:.82rem;padding:.58rem .88rem;
  outline:none;transition:border-color .15s}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
textarea{resize:vertical;min-height:100px}
.form-hint{font-family:var(--fm);font-size:.68rem;color:var(--muted);margin-top:.32rem}

/* TOGGLE */
.toggle-row{display:flex;align-items:center;gap:1rem;padding:.85rem 1rem;
  border-radius:8px;background:var(--bg);border:1px solid var(--border2)}
.toggle-info{flex:1}
.toggle-info strong{display:block;font-size:.85rem}
.toggle-info small{color:var(--muted);font-size:.73rem}
.switch{position:relative;width:42px;height:22px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;border-radius:22px;background:var(--border2);
  cursor:pointer;transition:background .2s}
.slider:before{content:'';position:absolute;width:16px;height:16px;border-radius:50%;
  background:var(--text);left:3px;top:3px;transition:transform .2s}
input:checked~.slider{background:var(--accent)}
input:checked~.slider:before{transform:translateX(20px);background:#000}

/* TABLE */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{font-family:var(--fm);font-size:.65rem;letter-spacing:.09em;
  text-transform:uppercase;color:var(--muted);padding:.62rem 1rem;
  border-bottom:1px solid var(--border);text-align:left;white-space:nowrap}
td{padding:.62rem 1rem;border-bottom:1px solid rgba(26,38,64,.5);
  font-family:var(--fm);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.012)}

/* PILLS */
.pill{display:inline-block;font-family:var(--fm);font-size:.65rem;
  font-weight:700;letter-spacing:.04em;padding:.16rem .52rem;border-radius:20px}
.p-ok{background:rgba(34,197,94,.12);color:var(--success)}
.p-err{background:rgba(239,68,68,.12);color:var(--danger)}
.p-info{background:rgba(0,229,255,.1);color:var(--accent)}
.p-warn{background:rgba(245,158,11,.1);color:var(--warning)}
.p-purple{background:rgba(124,58,237,.15);color:#a78bfa}
.p-gray{background:rgba(74,99,122,.15);color:var(--muted)}
.p-debug{background:rgba(245,158,11,.08);color:var(--warning);border:1px solid rgba(245,158,11,.2)}
.p-active{background:rgba(34,197,94,.12);color:var(--success);border:1px solid rgba(34,197,94,.2)}

/* IDP TABS */
.idp-tab{padding:.65rem 1.4rem;font-weight:600;font-size:.83rem;
  text-decoration:none;display:inline-flex;align-items:center;gap:.45rem;
  transition:color .15s;border-bottom:2px solid transparent;position:relative;top:1px}

/* LOG GROUPS */
.log-group{border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:.6rem}
.log-group-hd{display:flex;align-items:center;gap:.65rem;padding:.65rem 1rem;
  cursor:pointer;user-select:none;transition:background .12s;
  background:var(--surface);flex-wrap:wrap}
.log-group-hd:hover{background:var(--surface2)}
.log-group-body{display:none;border-top:1px solid var(--border)}
.log-group-body.open{display:block}
.log-group-body table{margin:0}
.log-group-body td,.log-group-body th{font-size:.72rem;padding:.45rem .8rem}

/* ATTR ROWS */
.attr-row{display:grid;grid-template-columns:1fr 1fr auto;gap:.5rem;
  align-items:center;margin-bottom:.5rem}

/* LOGIN PAGE */
.login-wrap{min-height:100vh;display:flex;align-items:center;
  justify-content:center;background:var(--bg);padding:2rem}
.login-box{width:100%;max-width:420px;background:var(--surface);
  border:1px solid var(--border);border-radius:16px;overflow:hidden}
.login-header{background:linear-gradient(135deg,#0e1420,#0d1730);
  padding:2rem 2rem 1.5rem;border-bottom:1px solid var(--border)}
.login-header h1{font-size:1.35rem;font-weight:700;letter-spacing:-.02em}
.login-header p{font-size:.78rem;color:var(--muted);margin-top:.35rem}
.login-body{padding:1.75rem 2rem}
.login-sep{display:flex;align-items:center;gap:.75rem;margin:1.25rem 0;
  font-family:var(--fm);font-size:.68rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}
.login-sep::before,.login-sep::after{content:'';flex:1;height:1px;background:var(--border)}
.saml-btn{width:100%;display:flex;align-items:center;justify-content:center;gap:.65rem;
  padding:.68rem;border-radius:9px;border:1.5px solid var(--border2);background:var(--bg);
  color:var(--text);font-family:var(--ff);font-size:.83rem;font-weight:600;
  cursor:pointer;text-decoration:none;transition:all .15s;margin-bottom:.6rem}
.saml-btn:hover{border-color:var(--accent);color:var(--accent)}
.saml-btn.duo:hover{border-color:#a78bfa;color:#a78bfa}

/* WELCOME PAGE */
.welcome-wrap{min-height:100vh;display:flex;flex-direction:column;
  align-items:center;justify-content:center;padding:2rem;
  background:radial-gradient(ellipse at 50% 0%,#0d2040 0%,var(--bg) 70%)}
.welcome-card{position:relative;text-align:center;max-width:600px;width:100%;
  background:rgba(14,20,32,.95);border:1px solid rgba(0,229,255,.2);
  border-radius:20px;padding:3rem 2.5rem;
  box-shadow:0 0 60px rgba(0,229,255,.08),0 24px 80px rgba(0,0,0,.6)}
.welcome-checkmark{font-size:4rem;margin-bottom:1.1rem;display:block;
  animation:pop-in .5s cubic-bezier(.175,.885,.32,1.275) both}
@keyframes pop-in{0%{transform:scale(0) rotate(-10deg);opacity:0}
  100%{transform:scale(1) rotate(0);opacity:1}}
.welcome-title{font-size:clamp(1.6rem,4vw,2.4rem);font-weight:700;
  letter-spacing:-.03em;line-height:1.15;margin-bottom:.6rem}
.welcome-title .highlight{color:var(--accent);text-shadow:0 0 28px rgba(0,229,255,.45)}
.welcome-subtitle{color:var(--muted);font-size:.92rem;margin-bottom:1.75rem;line-height:1.6}
.welcome-info{background:rgba(0,229,255,.04);border:1px solid rgba(0,229,255,.12);
  border-radius:12px;padding:1.2rem 1.5rem;text-align:left;
  font-family:var(--fm);font-size:.78rem;margin-bottom:1.75rem}
.welcome-info-row{display:flex;justify-content:space-between;align-items:baseline;
  padding:.32rem 0;border-bottom:1px solid rgba(26,38,64,.5)}
.welcome-info-row:last-child{border-bottom:none}
.welcome-info-label{color:var(--muted);font-size:.67rem;letter-spacing:.08em;text-transform:uppercase}
.welcome-info-value{color:var(--accent);word-break:break-all;text-align:right;max-width:70%}
.welcome-actions{display:flex;gap:.75rem;justify-content:center;flex-wrap:wrap}

/* MISC */
.divider{height:1px;background:var(--border);margin:1.25rem 0}
.mono{font-family:var(--fm)}
.muted{color:var(--muted)}
.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px}
pre{font-family:var(--fm);font-size:.7rem;color:var(--muted);
  background:var(--bg);border:1px solid var(--border);border-radius:6px;
  padding:.7rem 1rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin-top:.5rem}
/* TUTORIAL */
.tut-btn{background:transparent;border:1px solid var(--border2);
  color:var(--muted);font-size:.72rem;padding:.28rem .65rem;border-radius:6px;
  cursor:pointer;font-family:var(--ff);transition:all .15s;
  display:inline-flex;align-items:center;gap:.3rem}
.tut-btn:hover{color:var(--accent);border-color:var(--accent)}

/* TYPOGRAPHY — consistent scale */
.cfg-heading{font-size:.97rem;font-weight:700;color:var(--text);letter-spacing:-.01em}
.cfg-subhead{font-size:.78rem;color:var(--muted);margin-top:.18rem}
.body-text{font-size:.82rem;color:var(--text);line-height:1.55}
.hint-text{font-size:.73rem;color:var(--muted);line-height:1.5}
.section-label{font-family:var(--fm);font-size:.65rem;font-weight:700;
  letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}

/* TOGGLE SAVE — instant AJAX */
.toggle-saving{opacity:.55;pointer-events:none}

/* STEP REFERENCE TABS */
.ref-tab-bar{display:flex;gap:0;border-bottom:1px solid var(--border2);margin-bottom:0}
.ref-tab{padding:.5rem 1rem;font-size:.72rem;font-weight:600;
  cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;
  transition:color .15s,border-color .15s;font-family:var(--fm);
  background:none;border-top:none;border-left:none;border-right:none;
  user-select:none;white-space:nowrap}
.ref-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.ref-tab:hover{color:var(--text)}
.ref-panel-content{display:none;padding:.7rem .85rem}
.ref-panel-content.active{display:block}

/* CFG FORM — top header row */
.cfg-form-hd{display:flex;align-items:center;justify-content:space-between;
  flex-wrap:wrap;gap:.75rem;margin-bottom:1.5rem;padding-bottom:1.1rem;
  border-bottom:1px solid var(--border)}
.cfg-form-hd-left{display:flex;align-items:center;gap:.75rem}
.cfg-form-hd-right{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}

/* FLOATING SAVE BUTTON */

/* Quick Setup card */
.qs-row{display:flex;align-items:center;gap:.5rem;background:var(--bg);
  border:1px solid var(--border);border-radius:8px;padding:.45rem .7rem;flex-wrap:wrap}
.qs-label{font-size:.68rem;color:var(--muted);flex:0 0 auto;min-width:155px}
.qs-val{font-family:var(--fm);font-size:.68rem;color:var(--accent);word-break:break-all;flex:1}
.qs-copy{flex-shrink:0;font-size:.72rem!important;padding:.2rem .5rem!important}
.qs-need{display:flex;align-items:center;gap:.55rem;padding:.4rem .7rem;border-radius:8px;
  border:1px solid transparent}
.qs-ok{background:rgba(34,197,94,.06);border-color:rgba(34,197,94,.2)}
.qs-miss{background:rgba(239,68,68,.05);border-color:rgba(239,68,68,.15)}
.qs-opt{background:rgba(0,229,255,.03);border-color:rgba(0,229,255,.1)}
.qs-dot{font-size:.85rem;min-width:1rem;text-align:center}
.qs-ok .qs-dot{color:var(--success)}
.qs-miss .qs-dot{color:rgba(239,68,68,.5)}
.qs-field{font-size:.75rem;flex:1}
.qs-pill{font-size:.6rem;padding:.15rem .45rem;border-radius:5px;
  background:rgba(34,197,94,.15);color:var(--success);margin-left:auto}
.qs-pill-miss{background:rgba(239,68,68,.12);color:var(--danger)}

.float-save{
  position:fixed;bottom:1.5rem;right:1.75rem;z-index:200;
  display:none;
  background:var(--accent);color:#000;
  font-family:var(--ff);font-size:.82rem;font-weight:700;
  padding:.6rem 1.3rem;border-radius:10px;border:none;cursor:pointer;
  box-shadow:0 4px 24px rgba(0,229,255,.45),0 2px 8px rgba(0,0,0,.5);
  animation:float-pulse 2s ease-in-out infinite;
  gap:.4rem;align-items:center;
}
.float-save.visible{display:inline-flex}
@keyframes float-pulse{
  0%,100%{box-shadow:0 4px 24px rgba(0,229,255,.45),0 2px 8px rgba(0,0,0,.5)}
  50%{box-shadow:0 4px 36px rgba(0,229,255,.75),0 2px 12px rgba(0,0,0,.5)}
}

/* BOOKMARK DROPDOWN */
.bm-wrap{position:relative}
.bm-btn{background:transparent;border:1px solid var(--border2);
  color:var(--muted);font-size:.72rem;padding:.28rem .65rem;border-radius:6px;
  cursor:pointer;font-family:var(--ff);transition:all .15s;
  display:inline-flex;align-items:center;gap:.3rem}
.bm-btn:hover{color:var(--text);border-color:var(--accent)}
.bm-drop{display:none;position:absolute;top:calc(100% + 6px);right:0;
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  width:300px;z-index:300;box-shadow:0 8px 32px rgba(0,0,0,.55);overflow:hidden}
.bm-drop.open{display:block}
.bm-drop-hd{padding:.65rem 1rem;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between}
.bm-drop-title{font-family:var(--fm);font-size:.65rem;font-weight:700;
  letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.bm-list{max-height:260px;overflow-y:auto}
.bm-item{display:flex;align-items:center;gap:.5rem;padding:.5rem 1rem;
  border-bottom:1px solid rgba(26,38,64,.5);transition:background .1s}
.bm-item:last-child{border-bottom:none}
.bm-item:hover{background:var(--surface2)}
.bm-item a{flex:1;color:var(--text);text-decoration:none;
  font-size:.8rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bm-item .bm-url{font-family:var(--fm);font-size:.65rem;color:var(--muted);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.bm-del{background:none;border:none;color:var(--muted);cursor:pointer;
  font-size:.85rem;padding:.1rem .3rem;border-radius:4px;flex-shrink:0;
  transition:color .15s}
.bm-del:hover{color:var(--danger)}
.bm-add-row{padding:.65rem 1rem;border-top:1px solid var(--border);
  display:flex;flex-direction:column;gap:.4rem}
.bm-empty{padding:1rem;text-align:center;color:var(--muted);font-size:.78rem}
</style>"""



# ── Tutorial engine (Intro.js from cdnjs) ──────────────────────────────────────
_INTROJS_CSS = (
    '<link rel="stylesheet" href="' +
    'https://cdnjs.cloudflare.com/ajax/libs/intro.js/7.2.0/introjs.min.css">'
)
_INTROJS_JS = (
    '<script src="' +
    'https://cdnjs.cloudflare.com/ajax/libs/intro.js/7.2.0/intro.min.js"></script>'
)
_TUTORIAL_STYLE = """<style>
.introjs-tooltip{background:#0e1420;border:1px solid #00e5ff;color:#dde6f5;
  font-family:'Instrument Sans',sans-serif;border-radius:12px;
  box-shadow:0 10px 40px rgba(0,0,0,.75),0 0 0 1px rgba(0,229,255,.08)}
.introjs-tooltiptext{font-size:.84rem;line-height:1.65;color:#dde6f5}
.introjs-tooltip-title{color:#00e5ff;font-size:1rem;font-weight:700}
.introjs-arrow.top{border-bottom-color:#00e5ff}
.introjs-arrow.bottom{border-top-color:#00e5ff}
.introjs-arrow.left{border-right-color:#00e5ff}
.introjs-arrow.right{border-left-color:#00e5ff}
.introjs-helperLayer{border:2px solid #00e5ff;border-radius:10px;
  box-shadow:0 0 0 9999px rgba(2,7,20,.82),0 0 18px rgba(0,229,255,.3)}
.introjs-overlay{background:transparent}
.introjs-button{background:#141d2e;border:1px solid #1a2640;color:#dde6f5;
  font-family:'Instrument Sans',sans-serif;font-size:.78rem;border-radius:6px;padding:.35rem .9rem}
.introjs-button:hover,.introjs-button:focus{background:#1a2640;color:#00e5ff;border-color:#00e5ff;outline:none}
.introjs-nextbutton{background:#00e5ff;color:#000;border-color:#00e5ff;font-weight:700}
.introjs-nextbutton:hover,.introjs-nextbutton:focus{background:#00c8e0;color:#000;border-color:#00c8e0}
.introjs-donebutton{background:#22c55e;color:#000;border-color:#22c55e;font-weight:700}
.introjs-donebutton:hover{background:#16a34a;border-color:#16a34a}
.introjs-bullets ul li a{background:#1a2640}
.introjs-bullets ul li a.active,.introjs-bullets ul li a:hover{background:#00e5ff}
.introjs-progress{background:#1a2640}.introjs-progressbar{background:#00e5ff}
.introjs-skipbutton{color:rgba(255,255,255,.35)}.introjs-skipbutton:hover{color:#ef4444}
</style>"""
_TUTORIAL_ENGINE = _TUTORIAL_STYLE + """<script>
function _startTutorial(){
  var raw=window._PAGE_TUT||[];
  var steps=raw.map(function(s){
    var st={intro:s.body||'',title:s.title||''};
    if(s.sel){var el=document.querySelector(s.sel);if(el)st.element=el;}
    return st;
  });
  introJs().setOptions({
    steps:steps,showProgress:true,showBullets:true,
    exitOnOverlayClick:true,scrollToElement:true,disableInteraction:false,
    nextLabel:'Next &#8594;',prevLabel:'&#8592; Prev',doneLabel:'&#10003; Done',skipLabel:'&#10005;'
  }).start();
}
</script>"""


# ── Layout helpers ─────────────────────────────────────────────────────────────
def _flashes():
    msgs = ""
    for cat, msg in get_flashed_messages(with_categories=True):
        msgs += f'<div class="alert alert-{cat}">{msg}</div>'
    return f'<div style="margin-bottom:1rem">{msgs}</div>' if msgs else ""

def _topbar(extra_right=""):
    idp     = get_setting("active_idp", "okta")
    dbg     = is_debug()
    user    = get_admin_session().get("admin_user", "")
    saml_ok = '<span class="status-dot"></span>' if SAML_OK else '<span class="status-dot off" title="python3-saml not found"></span>'
    return f"""
<div class="topbar">
  <a href="/admin" class="topbar-brand">⬡ <span>SAML</span>TestBench</a>
  <span class="pill p-info" style="font-size:.62rem">{idp.upper()}</span>
  {'<span class="pill p-debug" style="font-size:.62rem">DEBUG ON</span>' if dbg else ''}
  <div class="topbar-right">
    {saml_ok}
    <button class="btn-folder" onclick="openFolder()" title="Open install folder">📁 Open Folder</button>
    <div class="bm-wrap" id="bm-wrap">
      <button class="bm-btn" id="bm-toggle" onclick="bmToggle()" title="Bookmarks">🔖 Bookmarks</button>
      <div class="bm-drop" id="bm-drop">
        <div class="bm-drop-hd">
          <span class="bm-drop-title">Bookmarks</span>
          <span class="hint-text">IdP admin portals &amp; links</span>
        </div>
        <div class="bm-list" id="bm-list"><div class="bm-empty">No bookmarks yet.</div></div>
        <div class="bm-add-row">
          <input type="text" id="bm-label" placeholder="Label (e.g. Okta Admin)"
            style="font-size:.78rem;margin-bottom:0">
          <input type="text" id="bm-url" placeholder="https://..."
            style="font-size:.78rem;margin-bottom:0">
          <button class="btn btn-sm btn-secondary" onclick="bmAdd()" style="width:100%;justify-content:center">＋ Add Bookmark</button>
        </div>
      </div>
    </div>
    {extra_right}
    {'<span class="topbar-user">'+user+'</span>' if user else ''}
  </div>
</div>
<script>
(function(){{
  var _bmOpen = false;
  window.bmToggle = function(){{
    _bmOpen = !_bmOpen;
    document.getElementById('bm-drop').classList.toggle('open', _bmOpen);
    if(_bmOpen) bmLoad();
  }};
  document.addEventListener('click', function(e){{
    if(!document.getElementById('bm-wrap').contains(e.target)){{
      _bmOpen = false;
      document.getElementById('bm-drop').classList.remove('open');
    }}
  }});
  window.bmLoad = function(){{
    fetch('/admin/bookmarks').then(r=>r.json()).then(function(d){{
      var list = document.getElementById('bm-list');
      if(!d.bookmarks || !d.bookmarks.length){{
        list.innerHTML = '<div class="bm-empty">No bookmarks yet.<br><span style="font-size:.7rem">Add your IdP admin portal URLs below.</span></div>';
        return;
      }}
      list.innerHTML = d.bookmarks.map(function(b,i){{
        return '<div class="bm-item">'
          + '<div style="flex:1;min-width:0">'
          + '<a href="'+b.url+'" target="_blank" rel="noopener">'+_bmEsc(b.label)+'</a>'
          + '<div class="bm-url">'+_bmEsc(b.url)+'</div>'
          + '</div>'
          + '<button class="bm-del" onclick="bmDel('+i+')" title="Remove">✕</button>'
          + '</div>';
      }}).join('');
    }});
  }};
  function _bmEsc(s){{
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }}
  window.bmAdd = function(){{
    var lbl = document.getElementById('bm-label').value.trim();
    var url = document.getElementById('bm-url').value.trim();
    if(!url){{ document.getElementById('bm-url').focus(); return; }}
    fetch('/admin/bookmarks/add',{{method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{label:lbl,url:url}})
    }}).then(r=>r.json()).then(function(d){{
      if(d.ok){{
        document.getElementById('bm-label').value='';
        document.getElementById('bm-url').value='';
        bmLoad();
      }} else alert('Error: '+(d.error||'unknown'));
    }});
  }};
  window.bmDel = function(idx){{
    fetch('/admin/bookmarks/delete',{{method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{index:idx}})
    }}).then(r=>r.json()).then(function(d){{ if(d.ok) bmLoad(); }});
  }};
  document.getElementById('bm-url').addEventListener('keydown',function(e){{
    if(e.key==='Enter'){{ e.preventDefault(); bmAdd(); }}
  }});
}})();
function openFolder(){{
  fetch('/admin/open-folder').then(r=>r.json()).then(d=>{{
    if(!d.ok) alert('Could not open folder: '+d.error);
  }}).catch(()=>alert('Error opening folder.'));
}}
</script>"""

def _sidebar(active=""):
    nav = [
        ("/admin",          "dashboard", "⬡", "Dashboard"),
        ("/admin/idp",      "idp",       "🔗", "IdP Config (SAML)"),
        ("/admin/oidc",     "oidc",      "🔐", "IdP Config (OIDC)"),
        ("/admin/users",    "users",     "👤", "User Management"),
        ("/admin/logs",     "logs",      "📋", "Logs"),
        ("/admin/settings", "settings",  "⚙",  "Settings"),
    ]
    items = "".join(
        f'<a href="{h}" class="{"active" if active==k else ""}"><span class="sidebar-icon">{i}</span>{l}</a>'
        for h, k, i, l in nav
    )
    return f"""
<div class="sidebar">
  <div class="sidebar-section">Admin</div>
  {items}
  <div class="sidebar-section" style="margin-top:1.5rem">Session</div>
  <a href="/admin/logout"><span class="sidebar-icon">🚪</span>Logout</a>
</div>"""

def _admin_page(title, active, body, tutorial_steps=None):
    tut_btn  = ""
    tut_init = ""
    tut_head = ""
    if tutorial_steps:
        import json as _j
        steps_json = _j.dumps(tutorial_steps)
        tut_btn  = '<button class="tut-btn" onclick="_startTutorial()" title="Page tutorial">\u2753 Tutorial</button>'
        tut_init = f"<script>window._PAGE_TUT={steps_json};</script>"
        tut_head = _INTROJS_CSS + "\n" + _INTROJS_JS + "\n" + _TUTORIAL_ENGINE
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} \u2014 SAML TestBench</title>{_CSS}
{tut_head}</head>
<body>
{_topbar(extra_right=tut_btn)}
<div class="layout">
{_sidebar(active)}
<div class="content">
{_flashes()}
{body}
</div></div>
{tut_init}
</body></html>"""

def _plain_page(title, body):
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — SAML TestBench</title>{_CSS}</head>
<body>{body}</body></html>"""

# ═══════════════════════════════════════════════════════════════
# PHASE 8 — FLASK APP
# ═══════════════════════════════════════════════════════════════
app = Flask(__name__)
_ADMIN_COOKIE = "saml_admin_session"

def _admin_serializer():
    return _ItsSer(app.config.get("ADMIN_SECRET", "unset"))

def get_admin_session() -> dict:
    raw = request.cookies.get(_ADMIN_COOKIE, "")
    if not raw:
        return {}
    try:
        return _admin_serializer().loads(raw, max_age=43200)
    except Exception:
        return {}

def _make_admin_cookie_response(dest: str, admin_user: str):
    resp = make_response(redirect(dest))
    signed = _admin_serializer().dumps({"admin_user": admin_user})
    resp.set_cookie(_ADMIN_COOKIE, signed, httponly=True, samesite="Lax", max_age=43200)
    return resp

def _clear_admin_cookie_response(dest: str):
    resp = make_response(redirect(dest))
    resp.delete_cookie(_ADMIN_COOKIE)
    return resp

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not get_admin_session().get("admin_user"):
            flash("Please log in to access the admin panel.", "warning")
            return redirect(url_for("admin_login"))
        return f(*a, **kw)
    return w

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("auth_ok"):
            flash("Please log in first.", "warning")
            return redirect(url_for("user_login_page"))
        return f(*a, **kw)
    return w

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — LOGIN / LOGOUT
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    reset_done = request.args.get("reset") == "1"
    if get_admin_session().get("admin_user"):
        return redirect(url_for("admin_dashboard"))
    error = ""
    if request.method == "POST":
        u = get_user_by_username(request.form.get("username",""))
        if u and u["role"] == "admin" and _check_pw(u["pw_hash"], request.form.get("password","")):
            log_step("Admin Login","admin_login","local",True,username=u["username"])
            return _make_admin_cookie_response(url_for("admin_dashboard"), u["username"])
        error = "Invalid credentials or insufficient privileges."
        log_step("Admin Login","admin_login_fail","local",False,error=error)

    banner = ""
    if reset_done:
        banner = '<div class="alert alert-success">Factory reset complete. Sign in with <strong>admin / admin123</strong>.</div>'
    body = f"""
<div class="login-wrap"><div class="login-box">
  <div class="login-header">
    <div style="font-size:2rem;margin-bottom:.65rem">⬡</div>
    <h1>SAML TestBench</h1><p>Admin Panel Login</p>
  </div>
  <div class="login-body">
    {banner}
    {'<div class="alert alert-danger">'+error+'</div>' if error else ''}
    <form method="post">
      <div class="form-group"><label>Username</label>
        <input type="text" name="username" autofocus autocomplete="username"></div>
      <div class="form-group"><label>Password</label>
        <input type="password" name="password" autocomplete="current-password"></div>
      <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center">Sign In to Admin</button>
    </form>
    <div class="divider"></div>
    <p style="font-size:.73rem;color:var(--muted);text-align:center">
      User login? <a href="/login" style="color:var(--accent)">Login Page →</a>
    </p>
  </div>
</div></div>"""
    return _plain_page("Admin Login", body)

@app.route("/admin/logout")
def admin_logout():
    return _clear_admin_cookie_response(url_for("admin_login"))

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin_dashboard():
    with get_db() as db:
        uc  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        lc  = db.execute("SELECT COUNT(*) FROM auth_log WHERE level='summary'").fetchone()[0]
        ok  = db.execute("SELECT COUNT(*) FROM auth_log WHERE success=1 AND level='summary'").fetchone()[0]
        err = db.execute("SELECT COUNT(*) FROM auth_log WHERE success=0 AND level='summary'").fetchone()[0]

    active  = get_setting("active_idp","okta")
    dbg     = is_debug()
    all_idps = {i["name"]: i for i in list_idps()}

    def _cfg_pill(name):
        c = all_idps.get(name,{})
        ok2 = bool(c.get("sso_url"))
        return f'<span class="pill {"p-ok" if ok2 else "p-err"}">{"Configured" if ok2 else "Not set"}</span>'

    saml_pill = f'<span class="pill {"p-ok" if SAML_OK else "p-err"}">{"Ready" if SAML_OK else "Library Missing"}</span>'

    # Grouped recent auth attempts (up to 10 groups)
    recent_events = get_auth_logs(300)
    groups = group_logs(recent_events)[:10]

    def _group_row(g):
        s = g["summary"]
        ts_disp  = _fmt_ts(s["ts"])
        idp_n    = s["idp"]
        idp_p    = f'<span class="pill {"p-info" if idp_n=="okta" else "p-purple" if idp_n=="duo" else "p-gray"}">{idp_n}</span>'
        res_p    = f'<span class="pill {"p-ok" if s["success"] else "p-err"}">{"✓ Success" if s["success"] else "✗ Fail"}</span>'
        sid      = g["session_id"].replace('"','')
        err_txt  = f'<div style="color:var(--danger);font-size:.68rem;margin-top:.25rem">{s["error"][:80]}</div>' if s.get("error") else ""

        # Sort steps: step-number first (Step 1, Step 2…), then timestamp
        def _step_sort_key(st):
            sn = st.get("step", "") or ""
            # Extract leading integer from "Step N" or "OIDC Step N" or "Local…"
            m = re.search(r"(?:OIDC\s+)?Step\s+(\d+)", sn, re.IGNORECASE)
            num = int(m.group(1)) if m else 999
            # Logout/SLO/Admin events go last
            if any(k in sn for k in ("Logout", "SLO", "Admin", "admin")):
                num = 900
            return (num, st.get("ts", ""))
        g["steps"].sort(key=_step_sort_key)
        steps_html = ""
        for st in g["steps"]:
            if st.get("level") == "debug":
                continue
            st_ok = st.get("success")
            st_pill = f'<span class="pill {"p-ok" if st_ok else "p-err"}" style="font-size:.6rem">{"✓" if st_ok else "✗"}</span>'
            st_err = f' — <span style="color:var(--danger)">{st.get("error","")[:60]}</span>' if st.get("error") else ""
            steps_html += f"""<tr>
              <td class="muted">{_fmt_ts(st.get("ts",""))}</td>
              <td style="font-family:var(--fm);font-size:.7rem">{st.get("step","")}</td>
              <td>{st_pill}{st_err}</td>
              <td class="muted">{st.get("_display_user","—")}</td>
            </tr>"""

        return f"""
<div class="log-group">
  <div class="log-group-hd" onclick="toggleGroup('{sid}')">
    <span style="font-family:var(--fm);font-size:.72rem;color:var(--muted);min-width:130px">{ts_disp}</span>
    {idp_p}
    {res_p}
    <span style="font-family:var(--fm);font-size:.75rem;color:var(--text)">{s["username"]}</span>
    <span class="muted" style="font-size:.7rem">{s["ip"]}</span>
    <span class="muted" style="font-size:.68rem;margin-left:auto">{s["step_count"]} step{"s" if s["step_count"]!=1 else ""} ▸</span>
    {err_txt}
  </div>
  <div class="log-group-body" id="grp-{sid}">
    <table><thead><tr><th>Time</th><th>Step</th><th>Result</th><th>User</th></tr></thead>
    <tbody>{steps_html}</tbody></table>
  </div>
</div>"""

    groups_html = "".join(_group_row(g) for g in groups) if groups else \
        '<div class="card-body muted" style="font-size:.85rem">No events logged yet.</div>'

    # Browser launcher
    browsers = detect_browsers()
    browser_opts = "".join(
        f'<option value="{b["path"]}" data-flag="{b["flag"]}">{b["name"]}</option>'
        for b in browsers
    )
    if not browsers:
        browser_opts = '<option value="default">System Default (no incognito)</option>'
    browser_opts += '<option value="__custom__">Custom browser…</option>'

    login_url = f"http://localhost:{PORT}/login"

    body = f"""
<div class="page-hd"><h1>Dashboard</h1>
  <p>Welcome back, <strong>{get_admin_session().get('admin_user')}</strong>.</p>
</div>

<!-- Launch card -->
<div id="dash-browsers" class="card" style="border-color:rgba(0,229,255,.25);background:linear-gradient(135deg,#0e1420,#0d1a30)">
  <div class="card-body">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1.25rem">
      <div>
        <div style="font-size:1rem;font-weight:700;margin-bottom:.3rem">🔐 User Authentication Page</div>
        <div style="color:var(--muted);font-size:.83rem">Open the end-user login page to test authentication flows.</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:.6rem;min-width:280px">
        <div style="display:flex;gap:.5rem;width:100%">
          <select id="browserSelect" style="flex:1;font-size:.78rem" onchange="onBrowserChange()">
            {browser_opts}
          </select>
          <button class="btn btn-launch" onclick="launchBrowser()">🚀 Launch</button>
        </div>
        <div id="customBrowserRow" style="display:none;width:100%;gap:.4rem;display:none">
          <input type="text" id="customBrowserPath" placeholder="Path to browser executable…"
            style="font-size:.75rem;margin-bottom:.4rem">
          <input type="text" id="customBrowserFlag" placeholder="Incognito flag (e.g. --incognito)"
            value="--incognito" style="font-size:.75rem;margin-bottom:.4rem">
          <input type="text" id="customBrowserName" placeholder="Display name"
            style="font-size:.75rem;margin-bottom:.4rem">
          <button class="btn btn-sm btn-secondary" onclick="saveCustomBrowser()" style="width:100%">Save &amp; Use Custom Browser</button>
        </div>
        <label style="display:flex;align-items:center;gap:.45rem;font-size:.75rem;
          color:var(--muted);text-transform:none;letter-spacing:0;cursor:pointer;margin:0">
          <input type="checkbox" id="incognitoCheck" checked style="width:auto">
          Open in private / incognito window
        </label>
      </div>
    </div>
  </div>
</div>

<script>
var LOGIN_URL = '{login_url}';
function onBrowserChange(){{
  var v = document.getElementById('browserSelect').value;
  document.getElementById('customBrowserRow').style.display = v==='__custom__' ? 'block':'none';
}}
function launchBrowser(){{
  var sel = document.getElementById('browserSelect');
  var path = sel.value;
  var flag = sel.options[sel.selectedIndex].getAttribute('data-flag') || '--incognito';
  var incognito = document.getElementById('incognitoCheck').checked;
  if(path==='__custom__'){{ alert('Please save the custom browser first.'); return; }}
  fetch('/admin/launch-browser',{{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{browser_path:path, incognito_flag:flag, use_incognito:incognito, url:LOGIN_URL}})
  }}).then(r=>r.json()).then(d=>{{
    if(!d.ok) alert('Launch error: '+(d.error||'unknown'));
  }}).catch(e=>alert('Could not reach server: '+e));
}}
function saveCustomBrowser(){{
  var path=document.getElementById('customBrowserPath').value.trim();
  var flag=document.getElementById('customBrowserFlag').value.trim()||'--incognito';
  var name=document.getElementById('customBrowserName').value.trim()||'Custom Browser';
  if(!path){{ alert('Enter a browser path.'); return; }}
  fetch('/admin/save-custom-browser',{{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{name,path,flag}})
  }}).then(r=>r.json()).then(d=>{{
    if(d.ok){{ location.reload(); }}
    else alert('Error: '+(d.error||'unknown'));
  }});
}}
function toggleGroup(sid){{
  var el=document.getElementById('grp-'+sid);
  if(el) el.classList.toggle('open');
}}
function showRefTab(proto){{
  ['saml','oidc'].forEach(function(p){{
    document.getElementById('ref-'+p).classList.toggle('active', p===proto);
    document.getElementById('ref-tab-'+p).classList.toggle('active', p===proto);
  }});
}}
</script>

<div id="dash-stats" class="g4" style="margin-bottom:1.5rem">
  <div class="stat"><div class="stat-label">Total Users</div><div class="stat-value">{uc}</div></div>
  <div class="stat"><div class="stat-label">Auth Steps Logged</div><div class="stat-value">{lc}</div></div>
  <div class="stat"><div class="stat-label">Successful</div>
    <div class="stat-value" style="color:var(--success)">{ok}</div></div>
  <div class="stat"><div class="stat-label">Failed</div>
    <div class="stat-value" style="color:var(--danger)">{err}</div></div>
</div>

<div id="dash-status" class="card">
  <div class="card-hd"><span class="card-title">System Status</span></div>
  <div class="card-body">
    <div class="g3">
      <div><span class="muted" style="font-size:.68rem;font-family:var(--fm)">SAML LIBRARY</span>
        <div style="margin-top:.3rem">{saml_pill}</div></div>
      {''.join(f"""<div><span class="muted" style="font-size:.68rem;font-family:var(--fm)">{i["name"].upper()}</span>
        <div style="margin-top:.3rem">{_cfg_pill(i["name"])}</div></div>""" for i in list_idps())}
      <div><span class="muted" style="font-size:.68rem;font-family:var(--fm)">ACTIVE IDP</span>
        <div style="margin-top:.3rem"><span class="pill p-info">{active.upper()}</span></div></div>
      <div><span class="muted" style="font-size:.68rem;font-family:var(--fm)">DEBUG LOGGING</span>
        <div style="margin-top:.3rem">
          {'<span class="pill p-warn">ENABLED</span>' if dbg else '<span class="pill p-gray">DISABLED</span>'}
        </div>
      </div>
      <div><span class="muted" style="font-size:.68rem;font-family:var(--fm)">OIDC LIBRARY</span>
        <div style="margin-top:.3rem">
          {'<span class="pill p-ok">Ready</span>' if OIDC_OK else '<span class="pill p-err">No requests</span>'}
        </div>
      </div>
      {''.join(f'''<div><span class="muted" style="font-size:.68rem;font-family:var(--fm)">{oc["name"].upper()} OIDC</span>
        <div style="margin-top:.3rem"><span class="pill {'p-ok' if oc.get('client_id') else 'p-err'}">{'Configured' if oc.get('client_id') else 'Not set'}</span></div></div>''' for oc in list_oidc_configs())}
    </div>
  </div>
</div>

<div id="dash-recent" class="card">
  <div class="card-hd">
    <span class="card-title">Recent Authentication Attempts</span>
    <a href="/admin/logs" class="btn btn-sm btn-secondary">View All →</a>
  </div>
  <div style="padding:.75rem">
    {groups_html}
  </div>
</div>"""

    tutorial = [
      {"sel": None,
       "title": "Dashboard Overview",
       "body": "The Dashboard is your control centre. It shows live system status, recent login sessions, and lets you launch a browser directly to the test login page."},
      {"sel": ".topbar",
       "title": "Top Bar",
       "body": "Shows the currently active IdP and whether debug logging is on. The green dot confirms python3-saml is installed. Use the 📁 button to open the install folder in your file manager."},
      {"sel": "#bm-wrap",
       "title": "🔖 Bookmarks",
       "body": "Click <strong>Bookmarks</strong> to open a dropdown where you can save direct links to your IdP admin portals — for example your Okta admin console, Duo admin panel, or Azure AD app registrations page. Add a label and paste the URL, then press Enter or click Add. Bookmarks are stored in the database and available from any page. Use them to jump straight to the right IdP portal when you're copying SSO URLs or certificates into SAML TestBench."},
      {"sel": ".sidebar",
       "title": "Navigation Sidebar",
       "body": "Move between all admin sections — Dashboard, IdP Config, User Management, Logs, and Settings — from here. The highlighted entry is the current page."},
      {"sel": "#dash-browsers",
       "title": "Browser Launcher",
       "body": "Select a browser and click Launch to open the end-user login page in a new window. Enable the incognito checkbox to start a clean session. Add a custom browser path if yours isn't auto-detected."},
      {"sel": "#dash-stats",
       "title": "Activity Counters",
       "body": "At-a-glance counts of local users, total log entries, successful authentications, and failures since the last log clear."},
      {"sel": "#dash-status",
       "title": "System Status",
       "body": "Green 'Configured' pills mean that IdP has an SSO URL saved. 'Library Missing' means python3-saml isn't installed — SAML flows won't work until it is (pip install python3-saml)."},
      {"sel": "#dash-recent",
       "title": "Recent Authentication Attempts",
       "body": "Each card is one complete login session. Click a card header to expand it and see every individual SAML step with timestamps, results, and any error detail. Use 'View All' to see the full log history."},
    ]
    return _admin_page("Dashboard", "dashboard", body, tutorial)

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — IDP CONFIG
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/idp", methods=["GET","POST"])
@admin_required
def admin_idp():
    if request.method == "POST":
        action = request.form.get("_action","save")
        name   = request.form.get("idp_name","okta")

        if action == "delete_custom":
            delete_custom_idp(name)
            flash(f"Custom IdP '{name}' deleted.", "success")
            return redirect("/admin/idp")

        if action == "clone":
            src_cfg    = get_idp(name)
            all_idps   = list_idps()
            if len(all_idps) >= 8:
                flash("Maximum of 8 SAML IdP configurations reached. Delete one before cloning.", "danger")
                return redirect(f"/admin/idp?tab={name}")
            base = re.sub(r"_clone\d*$", "", name)
            new_name = base + "_clone"
            ctr = 2
            while get_idp(new_name):
                new_name = f"{base}_clone{ctr}"; ctr += 1
            new_lbl = (src_cfg.get("label") or name.capitalize()) + " (Clone)"
            clone_data = {**src_cfg, "label": new_lbl, "enabled": False, "is_custom": True}
            # Ensure attr_mapping is a dict before passing to save_idp
            am = clone_data.get("attr_mapping", {})
            if isinstance(am, str):
                try: am = json.loads(am)
                except: am = {}
            clone_data["attr_mapping"] = am
            save_idp(new_name, clone_data)
            for w in get_watched_attrs(name):
                if not w.get("required"):
                    with get_db() as db:
                        db.execute("INSERT OR IGNORE INTO idp_watched_attrs VALUES (?,?,?,0,?)",
                                   (new_name, w["attr_name"], w.get("description",""), w.get("sort_order",99)))
                        db.commit()
            with get_db() as db:
                db.execute("INSERT OR IGNORE INTO idp_watched_attrs VALUES (?,?,?,1,0)",
                           (new_name, "mail", "User email address"))
                db.commit()
            flash(f"Cloned '{src_cfg.get('label',name)}' to '{new_lbl}'.", "success")
            return redirect(f"/admin/idp?tab={new_name}")

        if action == "create_custom":
            new_name = re.sub(r"[^a-z0-9_-]","",
                              request.form.get("new_idp_name","").lower().replace(" ","_"))
            if not new_name:
                flash("IdP name is required (letters, numbers, _ and - only).", "danger")
                return redirect("/admin/idp?tab=__new__")
            if get_idp(new_name):
                flash(f"An IdP named '{new_name}' already exists.", "danger")
                return redirect("/admin/idp?tab=__new__")
            save_idp(new_name, {
                "label":     request.form.get("new_idp_label", new_name),
                "entity_id": request.form.get("entity_id",""),
                "sso_url":   request.form.get("sso_url",""),
                "slo_url":   request.form.get("slo_url",""),
                "x509_cert": request.form.get("x509_cert",""),
                "sp_entity": request.form.get("sp_entity", f"http://localhost:{PORT}/saml/metadata"),
                "sp_acs":    request.form.get("sp_acs",    f"http://localhost:{PORT}/saml/acs"),
                "sp_slo":    request.form.get("sp_slo",    f"http://localhost:{PORT}/saml/slo"),
                "enabled":   request.form.get("enabled") == "1",
                "attr_mapping": _parse_attr_mapping(request),
            })
            # Save watched attrs
            _save_watched_attrs_from_form(new_name, request)
            # Seed the required "mail" attr if not already present
            with get_db() as db:
                db.execute("""INSERT OR IGNORE INTO idp_watched_attrs
                              (idp_name,attr_name,description,required,sort_order)
                              VALUES (?,?,?,?,?)""",
                           (new_name, "mail","User email address",1,0))
                db.commit()
            flash(f"Custom IdP '{request.form.get('new_idp_label',new_name)}' created.", "success")
            return redirect(f"/admin/idp?tab={new_name}")

        # Default: save existing IdP — auto-set enabled based on required fields
        entity_id = request.form.get("entity_id","").strip()
        sso_url   = request.form.get("sso_url","").strip()
        x509_cert = request.form.get("x509_cert","").strip()
        saml_missing_fields = []
        if not entity_id: saml_missing_fields.append("IdP Entity ID / Issuer URL")
        if not sso_url:   saml_missing_fields.append("SSO URL")
        if not x509_cert: saml_missing_fields.append("X.509 Certificate")
        # Auto-determine enabled state — override whatever the checkbox said
        auto_enabled = len(saml_missing_fields) == 0
        save_idp(name, {
            "entity_id": entity_id,
            "sso_url":   sso_url,
            "slo_url":   request.form.get("slo_url","").strip(),
            "x509_cert": x509_cert,
            "sp_entity": request.form.get("sp_entity", f"http://localhost:{PORT}/saml/metadata"),
            "sp_acs":    request.form.get("sp_acs",    f"http://localhost:{PORT}/saml/acs"),
            "sp_slo":    request.form.get("sp_slo",    f"http://localhost:{PORT}/saml/slo"),
            "enabled":   auto_enabled,
            "attr_mapping": _parse_attr_mapping(request),
            "_ever_saved": True,
        })
        if request.form.get("set_active"):
            set_setting("active_idp", name)
        _save_watched_attrs_from_form(name, request)
        lbl_saved = get_idp(name).get("label", name)
        if saml_missing_fields:
            missing_list = ", ".join(saml_missing_fields)
            flash(f"{lbl_saved} saved — but the following required fields are missing and this IdP has been disabled on the login page until they are filled in: {missing_list}.", "warning")
        else:
            flash(f"{lbl_saved} configuration saved — all required fields are present. IdP has been enabled on the login page.", "success")
        return redirect(f"/admin/idp?tab={name}")

    active = get_setting("active_idp","okta")
    tab    = request.args.get("tab", active)
    idps   = list_idps()

    SAML_MAX_IDPS = 8
    tabs_html = ""
    for idp in idps:
        n = idp["name"]
        lbl = idp.get("label") or n.capitalize()
        is_active_idp = (active == n)
        color = "var(--accent)" if tab==n else "var(--muted)"
        border = "var(--accent)" if tab==n else "transparent"
        active_badge = ' <span class="p-active pill" style="font-size:.58rem">Active</span>' if is_active_idp else ""
        tabs_html += f'<a href="?tab={n}" class="idp-tab" style="color:{color};border-bottom-color:{border}">{_idp_icon(n)} {lbl}{active_badge}</a>'
    if len(idps) < SAML_MAX_IDPS:
        tabs_html += f'<a href="?tab=__new__" class="idp-tab" style="color:{"var(--accent)" if tab=="__new__" else "var(--muted)"};border-bottom-color:{"var(--accent)" if tab=="__new__" else "transparent"}">&#xFF0B; Add Custom</a>'
    else:
        tabs_html += f'<span class="idp-tab" style="color:var(--muted);cursor:default" title="Maximum of {SAML_MAX_IDPS} SAML IdPs reached">&#xFF0B; Add Custom ({len(idps)}/{SAML_MAX_IDPS})</span>'

    forms_html = ""
    for idp in idps:
        forms_html += _idp_form_html(idp["name"], idp, active, tab)
    forms_html += _new_idp_form_html(tab)

    body = f"""
<div class="page-hd"><h1>IdP Configuration</h1>
  <p>Configure SAML Identity Providers. All values are stored securely in the local database.</p>
</div>
<div id="idp-export-row" style="display:flex;gap:.6rem;margin-bottom:1.1rem;flex-wrap:wrap;align-items:center">
  <a href="/admin/idp/export" class="btn btn-sm btn-secondary" download>⬇ Export IdP Configs</a>
  <label class="btn btn-sm btn-secondary" style="cursor:pointer;margin:0">
    ⬆ Import IdP Configs
    <input type="file" accept=".json" style="display:none" onchange="importIdpConfig(this)">
  </label>
  <span class="muted" style="font-size:.72rem">Back up before upgrading — import restores all IdP settings and watched attributes.</span>
</div>
<div id="idp-tabs" style="display:flex;gap:0;margin-bottom:1.5rem;border-bottom:1px solid var(--border);flex-wrap:wrap">
  {tabs_html}
</div>
{forms_html}
<script>
// ── Quick Setup copy buttons ────────────────────────────────────────────────
function qsCopy(elId, btn){{
  var el=document.getElementById(elId);
  if(!el) return;
  var text=el.textContent||el.innerText;
  navigator.clipboard.writeText(text).then(function(){{
    var orig=btn.innerHTML; btn.innerHTML='&#x2713;';
    setTimeout(function(){{btn.innerHTML=orig;}},1200);
  }}).catch(function(){{
    var ta=document.createElement('textarea');
    ta.value=text; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
    var orig=btn.innerHTML; btn.innerHTML='&#x2713;';
    setTimeout(function(){{btn.innerHTML=orig;}},1200);
  }});
}}

// ── SAML Metadata XML parser ──────────────────────────────────────────────────
function toggleXmlImport(name){{
  var body = document.getElementById('xml-import-body-'+name);
  var chev = document.getElementById('xml-chevron-'+name);
  if(!body) return;
  body.classList.toggle('open');
  if(chev) chev.textContent = body.classList.contains('open') ? '▾' : '▸';
}}
function samlXmlFile(name, input){{
  var file = input.files[0]; if(!file) return;
  var reader = new FileReader();
  reader.onload = function(e){{
    var ta = document.getElementById('xml-paste-'+name);
    if(ta) ta.value = e.target.result;
    // auto-open panel if closed
    var body = document.getElementById('xml-import-body-'+name);
    if(body && !body.classList.contains('open')){{
      body.classList.add('open');
      var chev = document.getElementById('xml-chevron-'+name);
      if(chev) chev.textContent = '▾';
    }}
  }};
  reader.readAsText(file);
}}
function clearXmlImport(name){{
  var ta = document.getElementById('xml-paste-'+name);
  if(ta) ta.value = '';
  var res = document.getElementById('xml-result-'+name);
  if(res) res.innerHTML = '';
}}
function _xmlEsc(s){{return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}}
function applySamlXml(name){{
  var ta  = document.getElementById('xml-paste-'+name);
  var res = document.getElementById('xml-result-'+name);
  if(!ta||!ta.value.trim()){{ res.innerHTML='<span style="color:var(--warning);font-size:.75rem">Nothing to parse.</span>'; return; }}
  var parser = new DOMParser();
  var doc;
  try{{ doc = parser.parseFromString(ta.value,'text/xml'); }}
  catch(e){{ res.innerHTML='<span style="color:var(--danger);font-size:.75rem">XML parse error: '+_xmlEsc(e)+'</span>'; return; }}
  var parseErr = doc.querySelector('parsererror');
  if(parseErr){{ res.innerHTML='<span style="color:var(--danger);font-size:.75rem">XML parse error — check the pasted text.</span>'; return; }}

  // Extract EntityID
  var entityId = '';
  var ed = doc.querySelector('EntityDescriptor,IDPSSODescriptor') ||
           doc.documentElement;
  if(doc.documentElement.getAttribute('entityID'))
    entityId = doc.documentElement.getAttribute('entityID');
  else{{
    var edEl = doc.querySelector('*[entityID]');
    if(edEl) entityId = edEl.getAttribute('entityID');
  }}

  // SSO URL — prefer HTTP-Redirect binding, fall back to POST
  var ssoUrl = '';
  var ssoServices = doc.querySelectorAll('SingleSignOnService');
  for(var i=0;i<ssoServices.length;i++){{
    var b = ssoServices[i].getAttribute('Binding')||'';
    if(b.indexOf('HTTP-Redirect')>=0){{ ssoUrl = ssoServices[i].getAttribute('Location')||''; break; }}
  }}
  if(!ssoUrl && ssoServices.length)
    ssoUrl = ssoServices[0].getAttribute('Location')||'';

  // SLO URL
  var sloUrl = '';
  var sloService = doc.querySelector('SingleLogoutService');
  if(sloService) sloUrl = sloService.getAttribute('Location')||'';

  // X.509 Certificate — prefer signing, fall back to any
  var cert = '';
  var kds = doc.querySelectorAll('KeyDescriptor');
  for(var j=0;j<kds.length;j++){{
    var use = (kds[j].getAttribute('use')||'').toLowerCase();
    if(use==='signing'||use===''){{
      var certEl = kds[j].querySelector('X509Certificate');
      if(certEl){{ cert = certEl.textContent.trim(); break; }}
    }}
  }}
  if(!cert){{
    var certEl2 = doc.querySelector('X509Certificate');
    if(certEl2) cert = certEl2.textContent.trim();
  }}

  // Apply to form fields
  var found = [];
  function _fill(fieldName, val){{
    if(!val) return;
    var el = document.querySelector('[name="'+fieldName+'"]');
    if(el){{ el.value = val; found.push(fieldName); }}
  }}
  _fill('entity_id', entityId);
  _fill('sso_url',   ssoUrl);
  _fill('slo_url',   sloUrl);
  _fill('x509_cert', cert);

  // Mark form dirty so float-save appears
  if(found.length > 0) markDirty('saml-form-'+name);

  // Show result summary
  if(found.length===0){{
    res.innerHTML = '<span style="color:var(--warning);font-size:.75rem">&#x26A0; No recognisable SAML metadata fields found. Is this a valid IdP metadata XML?</span>';
  }} else {{
    var rows = [
      entityId ? '<li><strong>Entity ID:</strong> '+_xmlEsc(entityId)+'</li>' : '',
      ssoUrl   ? '<li><strong>SSO URL:</strong> '+_xmlEsc(ssoUrl)+'</li>' : '',
      sloUrl   ? '<li><strong>SLO URL:</strong> '+_xmlEsc(sloUrl)+'</li>' : '',
      cert     ? '<li><strong>X.509 Certificate:</strong> '+cert.length+' chars extracted</li>' : '',
    ].filter(Boolean).join('');
    res.innerHTML = '<div style="background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.25);'
      +'border-radius:8px;padding:.55rem .85rem;font-size:.74rem">'
      +'<strong style="color:var(--success)">&#x2713; Applied '+found.length+' field(s):</strong>'
      +'<ul style="margin:.3rem 0 0 1.1rem;padding:0;color:var(--text)">'+rows+'</ul></div>';
    // Scroll to identity provider details card
    var card = document.querySelector('.idp-form-main');
    if(card) card.scrollIntoView({{behavior:'smooth',block:'nearest'}});
  }}
}}
// ─────────────────────────────────────────────────────────────────────────────
function importIdpConfig(input){{
  var file=input.files[0]; if(!file)return;
  var reader=new FileReader();
  reader.onload=function(e){{
    try{{
      var payload=JSON.parse(e.target.result);
      fetch('/admin/idp/import',{{
        method:'POST',
        headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify(payload)
      }}).then(r=>r.json()).then(d=>{{
        if(d.ok){{
          alert('Imported '+d.imported+' IdP(s).'+(d.skipped?' ('+d.skipped+' skipped)':''));
          location.reload();
        }} else {{
          alert('Import error: '+(d.error||'unknown'));
        }}
      }});
    }}catch(ex){{alert('Invalid JSON file: '+ex);}}
  }};
  reader.readAsText(file);
}}
</script>"""

    tutorial = [
      {"sel": None,
       "title": "SAML IdP Configuration",
       "body": "This page connects SAML TestBench to your real SAML Identity Provider. Each IdP (Okta, Duo, or custom) has its own tab — up to 8 total. Use the Clone button to duplicate a config as a starting point for a second environment (staging, prod). Changes here directly control how SAML assertions are validated."},
      {"sel": "#idp-export-row",
       "title": "Export & Import Configs",
       "body": "Before upgrading to a new version, click <strong>Export IdP Configs</strong> to download a JSON backup of all IdP settings and watched attributes. Use <strong>Import</strong> to restore them — it's non-destructive and won't overwrite unrelated settings."},
      {"sel": "#idp-tabs",
       "title": "IdP Tabs",
       "body": "Each tab is one configured IdP. The green <em>Active</em> badge shows which one is currently used for SAML flows by default. Click <strong>+ Add Custom</strong> to register an IdP other than Okta or Duo."},
      {"sel": ".idp-form-main",
       "title": "Connection Settings",
       "body": "Paste in the values from your IdP's SAML metadata: Entity ID, SSO URL (the redirect endpoint), SLO URL (logout), and the X.509 signing certificate. These come from your Okta app's Sign On tab or Duo's SAML application page."},
      {"sel": ".idp-sp-section",
       "title": "SP (Service Provider) Settings",
       "body": "These are the URLs <em>your IdP needs to know about</em>. Copy the ACS URL and Entity ID into your IdP's SAML application config exactly as shown. The SLO URL is optional but needed for single logout to work."},
      {"sel": ".idp-mapping-section",
       "title": "Attribute Mapping",
       "body": "If your IdP sends attributes under non-standard names (e.g. <code>http://schemas.xmlsoap.org/...</code> instead of <code>email</code>), map them here. The left column is the SP name, the right column is what your IdP actually sends."},
      {"sel": ".idp-watched-section",
       "title": "Watched SAML Attributes",
       "body": "<strong>mail</strong> is always captured and required. Add any other attribute names your IdP includes in its assertion — they'll appear on the successful login page and in debug logs. Use the exact attribute name your IdP sends."},
    ]
    return _admin_page("IdP Config","idp",body,tutorial)

def _idp_icon(name):
    return "🔵" if name=="okta" else "🟣" if name=="duo" else "🔷"

def _parse_attr_mapping(req) -> dict:
    mapping = {}
    for key in ["username","email","display_name","first_name","last_name"]:
        val = req.form.get(f"map_{key}","").strip()
        if val:
            mapping[key] = val
    return mapping

def _save_watched_attrs_from_form(idp_name: str, req):
    names = req.form.getlist("watched_attr_name")
    descs = req.form.getlist("watched_attr_desc")
    attrs = [{"attr_name": n, "description": d}
             for n, d in zip(names, descs) if n.strip()]
    save_watched_attrs(idp_name, attrs[:16])

def _idp_form_html(name, cfg, active_idp, tab):
    display = "" if tab == name else "display:none"
    is_active = (active_idp == name)
    is_custom = bool(cfg.get("is_custom"))
    lbl = cfg.get("label") or name.capitalize()
    configured = bool(cfg.get("sso_url"))
    icon = _idp_icon(name)

    # Watched attrs
    watched = get_watched_attrs(name)
    custom_watched = [w for w in watched if not w.get("required")]
    watched_rows = ""
    for i in range(16):
        a = custom_watched[i] if i < len(custom_watched) else {}
        watched_rows += f"""<div class="attr-row" id="wattr-row-{name}-{i}" {"" if i<len(custom_watched) else 'style="display:none"' if i>0 else ""}>
          <input type="text" name="watched_attr_name" value="{a.get('attr_name','')}"
            placeholder="Attribute name (e.g. groups)" style="font-size:.78rem">
          <input type="text" name="watched_attr_desc" value="{a.get('description','')}"
            placeholder="Description (optional)" style="font-size:.78rem">
          <button type="button" class="btn btn-sm btn-danger"
            onclick="removeWatchedRow('{name}',{i})">✕</button>
        </div>"""

    # Attribute mapping (custom IdPs)
    mapping = {}
    try:
        mapping = json.loads(cfg.get("attr_mapping") or "{}")
        if not isinstance(mapping, dict):
            mapping = {}
    except Exception:
        pass

    mapping_html = ""
    if is_custom:
        sp_attrs = [
            ("username",     "Username",     "The SP login/username field"),
            ("email",        "Email Address","The SP email field"),
            ("display_name", "Display Name", "Full display name"),
            ("first_name",   "First Name",   "Given name"),
            ("last_name",    "Last Name",    "Family name"),
        ]
        rows_m = ""
        for key, label, hint in sp_attrs:
            rows_m += f"""<div class="attr-row">
              <div style="font-family:var(--fm);font-size:.75rem;color:var(--muted);
                padding:.5rem;background:var(--bg);border-radius:6px;border:1px solid var(--border2)">
                &lt;{label}&gt;</div>
              <input type="text" name="map_{key}" value="{mapping.get(key,'')}"
                placeholder="IdP attribute name" style="font-size:.78rem">
              <span style="font-family:var(--fm);font-size:.65rem;color:var(--muted);
                padding:.45rem 0">{hint}</span>
            </div>"""
        mapping_html = f"""
    <div class="card idp-mapping-section" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Attribute Mapping</span>
        <span class="pill p-info">Map SP fields → IdP attributes</span>
      </div>
      <div class="card-body">
        <p class="hint-text" style="margin-bottom:.9rem">Map what this SP expects to the actual attribute names your IdP sends.</p>
        <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:.5rem;margin-bottom:.4rem">
          <span class="muted" style="font-size:.65rem;font-family:var(--fm);padding:.3rem">SP Default Attribute</span>
          <span class="muted" style="font-size:.65rem;font-family:var(--fm);padding:.3rem">IdP Attribute Name</span>
          <span></span>
        </div>
        {rows_m}
      </div>
    </div>"""

    delete_btn = ""
    delete_html_inline = ""
    if is_custom:
        delete_btn = f"""
    <form method="post" style="display:inline;margin-left:.5rem"
      onsubmit="return confirm('Delete IdP {lbl}? This cannot be undone.')">
      <input type="hidden" name="idp_name" value="{name}">
      <input type="hidden" name="_action" value="delete_custom">
      <button type="submit" class="btn btn-sm btn-danger">&#x1F5D1; Delete</button>
    </form>"""
        delete_html_inline = (f'<form method="post" style="display:inline-flex"'
            f' onsubmit="return confirm(\'Delete IdP {lbl}? This cannot be undone.\');">'
            f'<input type="hidden" name="idp_name" value="{name}">'
            f'<input type="hidden" name="_action" value="delete_custom">'
            f'<button type="submit" class="btn btn-sm btn-danger" style="flex-shrink:0">&#x1F5D1; Delete</button>'
            f'</form>')

    # Required field check for SAML
    saml_missing = []
    if not cfg.get("entity_id"): saml_missing.append("IdP Entity ID / Issuer URL")
    if not cfg.get("sso_url"):   saml_missing.append("SSO URL")
    if not cfg.get("x509_cert"): saml_missing.append("X.509 Certificate")
    saml_all_filled = not saml_missing
    # Auto-enable if fully configured and not yet explicitly disabled
    if saml_all_filled and not cfg.get("_ever_saved"):
        enabled_val = True
    else:
        enabled_val = bool(cfg.get("enabled"))

    missing_banner = ""
    if saml_missing:
        items_html = "".join(f"<li><strong>{m}</strong></li>" for m in saml_missing)
        missing_banner = f'''<div class="alert alert-warning" style="margin-bottom:1rem">
          <strong>⚠ Configuration Incomplete</strong> — The following required fields are missing.
          They are highlighted in red below.<ul style="margin:.5rem 0 0 1.2rem;padding:0">{items_html}</ul>
        </div>'''

    def _req_style(val):
        return ' style="border-color:var(--danger);box-shadow:0 0 0 2px rgba(239,68,68,.18)"' if not val else ""

    return f"""
<div id="tab-{name}" style="{display}">
  <form method="post" id="saml-form-{name}" onchange="markDirty('saml-form-{name}')">
    <input type="hidden" name="idp_name" value="{{name}}">
    {{missing_banner}}

    <!-- ── "Register these in your IdP" pinned top bar ── -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:1rem;
      background:rgba(0,229,255,.04);border:1.5px solid rgba(0,229,255,.22);
      border-radius:10px;padding:.9rem 1.1rem">
      <div>
        <div style="font-size:.62rem;font-weight:700;text-transform:uppercase;
          letter-spacing:.09em;color:var(--accent);margin-bottom:.5rem">
          &#x1F4CB; Register these in {{lbl}}
        </div>
        <div style="display:flex;flex-direction:column;gap:.35rem">
          <div class="qs-row">
            <div class="qs-label" style="min-width:155px">ACS / SSO URL</div>
            <div class="qs-val" id="top-acs-{{name}}">http://localhost:{{PORT}}/saml/acs</div>
            <button type="button" class="btn btn-sm btn-outline qs-copy"
              onclick="qsCopy('top-acs-{{name}}',this)" title="Copy">&#x2398;</button>
          </div>
          <div class="qs-row">
            <div class="qs-label" style="min-width:155px">SP Entity ID / Audience</div>
            <div class="qs-val" id="top-ent-{{name}}">http://localhost:{{PORT}}/saml/metadata</div>
            <button type="button" class="btn btn-sm btn-outline qs-copy"
              onclick="qsCopy('top-ent-{{name}}',this)" title="Copy">&#x2398;</button>
          </div>
          <div class="qs-row">
            <div class="qs-label" style="min-width:155px">SLO URL <span class="muted">(opt)</span></div>
            <div class="qs-val" id="top-slo-{{name}}">http://localhost:{{PORT}}/saml/slo</div>
            <button type="button" class="btn btn-sm btn-outline qs-copy"
              onclick="qsCopy('top-slo-{{name}}',this)" title="Copy">&#x2398;</button>
          </div>
        </div>
      </div>
      <div>
        <div style="font-size:.62rem;font-weight:700;text-transform:uppercase;
          letter-spacing:.09em;color:var(--muted);margin-bottom:.5rem">
          &#x1F4E5; Required from {{lbl}}
        </div>
        <div style="display:flex;flex-direction:column;gap:.3rem;font-size:.75rem">
          <div style="display:flex;align-items:center;gap:.55rem;padding:.3rem .5rem;
            border-radius:6px;background:{{"rgba(34,197,94,.06)" if cfg.get("entity_id") else "rgba(239,68,68,.07)"}}">
            <span style="font-size:.85rem">{{"&#x2713;" if cfg.get("entity_id") else "&#x25CB;"}}</span>
            <span style="color:{{"var(--success)" if cfg.get("entity_id") else "var(--danger)"}}">IdP Entity ID / Issuer URL</span>
            {{'<span class="pill p-ok" style="font-size:.6rem;margin-left:auto">Set</span>' if cfg.get("entity_id") else '<span class="pill p-err" style="font-size:.6rem;margin-left:auto">Missing</span>'}}
          </div>
          <div style="display:flex;align-items:center;gap:.55rem;padding:.3rem .5rem;
            border-radius:6px;background:{{"rgba(34,197,94,.06)" if cfg.get("sso_url") else "rgba(239,68,68,.07)"}}">
            <span style="font-size:.85rem">{{"&#x2713;" if cfg.get("sso_url") else "&#x25CB;"}}</span>
            <span style="color:{{"var(--success)" if cfg.get("sso_url") else "var(--danger)"}}">SSO URL (HTTP-Redirect)</span>
            {{'<span class="pill p-ok" style="font-size:.6rem;margin-left:auto">Set</span>' if cfg.get("sso_url") else '<span class="pill p-err" style="font-size:.6rem;margin-left:auto">Missing</span>'}}
          </div>
          <div style="display:flex;align-items:center;gap:.55rem;padding:.3rem .5rem;
            border-radius:6px;background:{{"rgba(34,197,94,.06)" if cfg.get("x509_cert") else "rgba(239,68,68,.07)"}}">
            <span style="font-size:.85rem">{{"&#x2713;" if cfg.get("x509_cert") else "&#x25CB;"}}</span>
            <span style="color:{{"var(--success)" if cfg.get("x509_cert") else "var(--danger)"}}">X.509 Signing Certificate</span>
            {{'<span class="pill p-ok" style="font-size:.6rem;margin-left:auto">Set</span>' if cfg.get("x509_cert") else '<span class="pill p-err" style="font-size:.6rem;margin-left:auto">Missing</span>'}}
          </div>
          <div style="display:flex;align-items:center;gap:.55rem;padding:.3rem .5rem;
            border-radius:6px;background:rgba(245,158,11,.05);color:var(--muted)">
            <span>&#x25CB;</span><span>SLO URL (optional)</span>
          </div>
        </div>
      </div>
    </div>

    <div class="cfg-form-hd">
      <div class="cfg-form-hd-left">
        <span style="font-size:1.4rem">{icon}</span>
        <div>
          <div class="cfg-heading">{lbl} SAML Configuration</div>
          <div class="cfg-subhead">{'All required fields filled' if saml_all_filled else f'{len(saml_missing)} required field(s) missing'}</div>
        </div>
      </div>
      <div class="cfg-form-hd-right">
        <div class="toggle-row" style="margin:0;padding:.45rem .75rem">
          <div class="toggle-info">
            <strong class="body-text">Show on Login Page</strong>
            <small class="hint-text">{'Ready to enable' if saml_all_filled else 'Fill required fields first'}</small>
          </div>
          <label class="switch" style="margin-left:.75rem">
            <input type="checkbox" name="enabled" value="1" {'checked' if enabled_val else ''}
              onchange="ajaxToggleIdp('{name}', this.checked, this)">
            <span class="slider"></span>
          </label>
        </div>
        {'<span class="pill p-active">&#x25CF; Active IdP</span>' if is_active else
         '<button type="submit" name="set_active" value="1" class="btn btn-sm btn-secondary">Set as Active</button>'}
        <button type="submit" class="btn btn-sm btn-secondary" name="_action" value="clone" title="Duplicate this configuration">&#x2398; Clone</button>
        {delete_html_inline}
        <a href="/saml/metadata?idp={name}" target="_blank" class="btn btn-sm btn-outline" title="View SP metadata XML">&#x1F4C4; Metadata</a>
        <button type="submit" class="btn btn-primary">&#x1F4BE; Save Configuration</button>
      </div>
    </div>

    <!-- Quick Setup reference card -->
    <div class="card" style="margin-bottom:1rem;border-color:rgba(0,229,255,.25);background:rgba(0,229,255,.02)">
      <div class="card-hd" style="border-color:rgba(0,229,255,.2)">
        <span class="card-title" style="color:var(--accent)">&#x26A1; Quick Setup Reference</span>
        <span class="pill p-info" style="font-size:.62rem">What goes where</span>
      </div>
      <div class="card-body" style="display:grid;grid-template-columns:1fr 1fr;gap:1.25rem">
        <!-- LEFT: register these in your IdP -->
        <div>
          <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
            color:var(--muted);margin-bottom:.65rem">Register these in {lbl}</div>
          <div style="display:flex;flex-direction:column;gap:.5rem">
            <div class="qs-row">
              <div class="qs-label">ACS URL (Single Sign-On URL)</div>
              <div class="qs-val" id="qs-acs-{name}">http://localhost:{PORT}/saml/acs</div>
              <button type="button" class="btn btn-sm btn-outline qs-copy"
                onclick="qsCopy('qs-acs-{name}',this)" title="Copy">&#x2398;</button>
            </div>
            <div class="qs-row">
              <div class="qs-label">SP Entity ID / Audience URI</div>
              <div class="qs-val" id="qs-ent-{name}">http://localhost:{PORT}/saml/metadata</div>
              <button type="button" class="btn btn-sm btn-outline qs-copy"
                onclick="qsCopy('qs-ent-{name}',this)" title="Copy">&#x2398;</button>
            </div>
            <div class="qs-row">
              <div class="qs-label">SLO URL (optional)</div>
              <div class="qs-val" id="qs-slo-{name}">http://localhost:{PORT}/saml/slo</div>
              <button type="button" class="btn btn-sm btn-outline qs-copy"
                onclick="qsCopy('qs-slo-{name}',this)" title="Copy">&#x2398;</button>
            </div>
            <div class="qs-row">
              <div class="qs-label">SP Metadata XML</div>
              <a href="/saml/metadata?idp={name}" target="_blank"
                class="btn btn-sm btn-outline" style="font-size:.7rem">&#x1F4C4; View / Download</a>
            </div>
          </div>
        </div>
        <!-- RIGHT: what you need from IdP -->
        <div>
          <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
            color:var(--muted);margin-bottom:.65rem">What you need from {lbl}</div>
          <div style="display:flex;flex-direction:column;gap:.45rem">
            <div class="qs-need {'qs-ok' if cfg.get('entity_id') else 'qs-miss'}">
              <span class="qs-dot">{'&#x2713;' if cfg.get('entity_id') else '&#x25CB;'}</span>
              <span class="qs-field">IdP Entity ID / Issuer URL</span>
              {'<span class="qs-pill">Set</span>' if cfg.get('entity_id') else '<span class="qs-pill qs-pill-miss">Missing</span>'}
            </div>
            <div class="qs-need {'qs-ok' if cfg.get('sso_url') else 'qs-miss'}">
              <span class="qs-dot">{'&#x2713;' if cfg.get('sso_url') else '&#x25CB;'}</span>
              <span class="qs-field">SSO URL (HTTP-Redirect or POST)</span>
              {'<span class="qs-pill">Set</span>' if cfg.get('sso_url') else '<span class="qs-pill qs-pill-miss">Missing</span>'}
            </div>
            <div class="qs-need {'qs-ok' if cfg.get('x509_cert') else 'qs-miss'}">
              <span class="qs-dot">{'&#x2713;' if cfg.get('x509_cert') else '&#x25CB;'}</span>
              <span class="qs-field">X.509 Signing Certificate</span>
              {'<span class="qs-pill">Set</span>' if cfg.get('x509_cert') else '<span class="qs-pill qs-pill-miss">Missing</span>'}
            </div>
            <div class="qs-need qs-opt">
              <span class="qs-dot" style="color:var(--muted)">&#x25CB;</span>
              <span class="qs-field" style="color:var(--muted)">SLO URL <em>(optional)</em></span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- XML Metadata import card -->
    <div class="card idp-xml-section" style="margin-bottom:1rem">
      <div class="card-hd" onclick="toggleXmlImport('{name}')" style="cursor:pointer;user-select:none">
        <span class="card-title">Import from IdP XML Metadata</span>
        <span class="pill p-info">paste or upload</span>
        <span id="xml-chevron-{name}" style="margin-left:auto;color:var(--muted);font-size:.8rem">▸</span>
      </div>
      <div class="log-group-body" id="xml-import-body-{name}" style="padding:0">
        <div class="card-body" style="padding-top:.85rem">
          <p class="hint-text" style="margin-bottom:.75rem">
            Paste your IdP's SAML metadata XML below (or upload the file) and click
            <strong>Apply</strong> — Entity ID, SSO URL, SLO URL and the X.509 signing
            certificate will be extracted and filled in automatically.
          </p>
          <div style="display:flex;gap:.5rem;margin-bottom:.65rem;flex-wrap:wrap;align-items:center">
            <label class="btn btn-sm btn-secondary" style="cursor:pointer;margin:0">
              &#x1F4C2; Upload XML file
              <input type="file" accept=".xml,text/xml,application/xml,application/samlmetadata+xml"
                style="display:none" onchange="samlXmlFile('{name}', this)">
            </label>
            <span class="hint-text">or paste below</span>
          </div>
          <textarea id="xml-paste-{name}" style="min-height:130px;font-family:var(--fm);font-size:.7rem;
            border:1.5px solid var(--border2);border-radius:8px;margin-bottom:.65rem"
            placeholder="Paste SAML metadata XML here…&#10;&lt;EntityDescriptor entityID=&quot;…&quot;&gt;…&lt;/EntityDescriptor&gt;"></textarea>
          <div id="xml-result-{name}" style="margin-bottom:.5rem"></div>
          <div style="display:flex;gap:.5rem">
            <button type="button" class="btn btn-sm btn-secondary"
              onclick="applySamlXml('{name}')">&#x2713; Apply to fields</button>
            <button type="button" class="btn btn-sm btn-secondary"
              onclick="clearXmlImport('{name}')">✕ Clear</button>
          </div>
        </div>
      </div>
    </div>

    <div class="card idp-form-main" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Identity Provider Details</span>
        <span class="pill {'p-ok' if saml_all_filled else 'p-err'}">{'Configured' if saml_all_filled else f'{len(saml_missing)} field(s) missing'}</span>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label>IdP Entity ID / Issuer URL {'<span style="color:var(--danger)">*</span>' if not cfg.get('entity_id') else ''}</label>
          <input type="text" name="entity_id" value="{cfg.get('entity_id','')}"
            placeholder="https://your-org.{name}.com/..."{_req_style(cfg.get('entity_id'))}>
        </div>
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>SSO URL (Single Sign-On) {'<span style="color:var(--danger)">*</span>' if not cfg.get('sso_url') else ''}</label>
            <input type="text" name="sso_url" value="{cfg.get('sso_url','')}"{_req_style(cfg.get('sso_url'))}>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>SLO URL (Single Logout)</label>
            <input type="text" name="slo_url" value="{cfg.get('slo_url','')}"
              placeholder="Leave blank to reuse SSO URL">
            <div class="form-hint">Optional</div>
          </div>
        </div>
        <div class="form-group" style="margin-top:1rem">
          <label>X.509 Certificate {'<span style="color:var(--danger)">*</span>' if not cfg.get('x509_cert') else ''}</label>
          <textarea name="x509_cert" style="min-height:120px;font-size:.72rem{';border-color:var(--danger);box-shadow:0 0 0 2px rgba(239,68,68,.18)' if not cfg.get('x509_cert') else ''}"
            placeholder="Paste certificate (with or without headers)"
            >{cfg.get('x509_cert','')}</textarea>
        </div>
      </div>
    </div>

    <div class="card idp-sp-section" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Service Provider (SP) Settings</span>
        <span class="pill p-info">Register these in {lbl}</span>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label>SP Entity ID / Audience URI</label>
          <input type="text" name="sp_entity" value="{cfg.get('sp_entity', f'http://localhost:{PORT}/saml/metadata')}">
        </div>
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>ACS URL (Single Sign-On URL)</label>
            <input type="text" name="sp_acs" value="{cfg.get('sp_acs', f'http://localhost:{PORT}/saml/acs')}">
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>SLO URL</label>
            <input type="text" name="sp_slo" value="{cfg.get('sp_slo', f'http://localhost:{PORT}/saml/slo')}">
          </div>
        </div>
      </div>
    </div>

    {mapping_html}

    <div class="card idp-watched-section" style="margin-bottom:1rem">
      <div class="card-hd">
        <span class="card-title">Watched SAML Attributes</span>
        <span class="pill p-gray">Up to 16 custom + required "mail"</span>
      </div>
      <div class="card-body">
        <p class="hint-text" style="margin-bottom:.9rem">These attributes will be extracted from SAML assertions and shown in logs. The <code style="color:var(--accent)">mail</code> attribute is always required.</p>
        <div style="background:rgba(0,229,255,.04);border:1px solid rgba(0,229,255,.15);
          border-radius:8px;padding:.6rem .9rem;margin-bottom:.85rem;
          font-family:var(--fm);font-size:.75rem;display:flex;align-items:center;gap:.6rem">
          <span class="pill p-ok" style="font-size:.6rem">Required</span>
          <span style="color:var(--accent)">mail</span>
          <span style="color:var(--muted)">— User email address (always watched)</span>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:.5rem;margin-bottom:.5rem">
          <span class="muted" style="font-size:.63rem;font-family:var(--fm)">Attribute Name</span>
          <span class="muted" style="font-size:.63rem;font-family:var(--fm)">Description (optional)</span>
          <span></span>
        </div>
        <div id="watched-attrs-{name}">
          {watched_rows}
        </div>
        <button type="button" class="btn btn-sm btn-secondary" style="margin-top:.5rem"
          onclick="addWatchedRow('{name}')">&#xFF0B; Add Attribute</button>
      </div>
    </div>

    <button type="submit" id="float-save-saml-form-{name}" class="float-save" title="Unsaved changes">
      &#x1F4BE; Save Changes
    </button>
  </form>
</div>
<script>
var watchers_{name} = {len(custom_watched)};
(function(){{
  var fid='saml-form-{name}';
  function markDirty(formId){{
    var btn=document.getElementById('float-save-'+formId);
    if(btn) btn.classList.add('visible');
  }}
  window.markDirty=markDirty;
  document.addEventListener('DOMContentLoaded',function(){{
    var form=document.getElementById(fid);
    if(!form) return;
    // Listen on all inputs/selects/textareas inside this form
    form.querySelectorAll('input,select,textarea').forEach(function(el){{
      el.addEventListener('input',function(){{ markDirty(fid); }});
      el.addEventListener('change',function(){{ markDirty(fid); }});
    }});
  }});
}})();
function ajaxToggleIdp(name, enabled, el){{
  el.closest('.toggle-row').classList.add('toggle-saving');
  fetch('/admin/idp/toggle',{{method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{name:name,enabled:enabled}})
  }}).then(r=>r.json()).then(d=>{{
    el.closest('.toggle-row').classList.remove('toggle-saving');
    if(!d.ok){{ el.checked=!enabled; alert('Could not save: '+(d.error||'unknown')); }}
  }}).catch(()=>{{ el.closest('.toggle-row').classList.remove('toggle-saving'); el.checked=!enabled; }});
}}
function addWatchedRow(idp){{
  var max=16, container=document.getElementById('watched-attrs-'+idp);
  for(var i=0;i<max;i++){{
    var row=document.getElementById('wattr-row-'+idp+'-'+i);
    if(row && row.style.display==='none'){{ row.style.display=''; return; }}
  }}
}}
function removeWatchedRow(idp,idx){{
  var row=document.getElementById('wattr-row-'+idp+'-'+idx);
  if(row){{
    row.querySelectorAll('input').forEach(function(inp){{inp.value='';}});
    row.style.display='none';
  }}
}}
</script>"""

def _new_idp_form_html(tab):
    display = "" if tab == "__new__" else "display:none"
    return f"""
<div id="tab-__new__" style="{display}">
  <form method="post">
    <input type="hidden" name="_action" value="create_custom">
    <div class="cfg-form-hd">
      <div class="cfg-form-hd-left">
        <span style="font-size:1.4rem">🔷</span>
        <div>
          <div class="cfg-heading">Add Custom SAML IdP</div>
          <div class="cfg-subhead">Configure any SAML 2.0 Identity Provider</div>
        </div>
      </div>
      <div class="cfg-form-hd-right">
        <button type="submit" class="btn btn-primary">Create IdP</button>
      </div>
    </div>

    <div class="card" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">IdP Identity</span></div>
      <div class="card-body">
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>Display Name *</label>
            <input type="text" name="new_idp_label" placeholder="e.g. Azure AD, PingFederate" required>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Internal ID *</label>
            <input type="text" name="new_idp_name" placeholder="e.g. azure (lowercase, no spaces)" required>
            <div class="form-hint">Used internally — letters, numbers, _ and - only</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Identity Provider Details</span></div>
      <div class="card-body">
        <div class="form-group">
          <label>IdP Entity ID / Issuer URL</label>
          <input type="text" name="entity_id" placeholder="https://sts.windows.net/...">
        </div>
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>SSO URL</label>
            <input type="text" name="sso_url">
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>SLO URL (Optional)</label>
            <input type="text" name="slo_url">
          </div>
        </div>
        <div class="form-group" style="margin-top:1rem">
          <label>X.509 Certificate</label>
          <textarea name="x509_cert" style="min-height:120px;font-family:var(--fm)"
            placeholder="Paste certificate"></textarea>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">SP Settings</span></div>
      <div class="card-body">
        <div class="form-group">
          <label>SP Entity ID</label>
          <input type="text" name="sp_entity" value="http://localhost:{PORT}/saml/metadata">
        </div>
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>ACS URL</label>
            <input type="text" name="sp_acs" value="http://localhost:{PORT}/saml/acs">
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>SLO URL</label>
            <input type="text" name="sp_slo" value="http://localhost:{PORT}/saml/slo">
          </div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Attribute Mapping</span>
        <span class="pill p-info">Map SP fields → IdP attributes</span>
      </div>
      <div class="card-body">
        <p class="hint-text" style="margin-bottom:.9rem">Map what this SP expects to the actual attribute names your IdP sends.</p>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem">
          {''.join(f"""<div style="border:1px solid var(--border2);border-radius:8px;padding:.85rem">
            <div class="section-label" style="margin-bottom:.5rem">&lt;{label}&gt;</div>
            <input type="text" name="map_{key}" placeholder="e.g. {default}"
              style="font-size:.78rem">
          </div>""" for key,label,default in [
            ("username","Username","Username"),
            ("email","Email Address","Email"),
            ("display_name","Display Name","DisplayName"),
            ("first_name","First Name","FirstName"),
            ("last_name","Last Name","LastName"),
          ])}
        </div>
      </div>
    </div>

  </form>
</div>"""

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — USER MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/users", methods=["GET","POST"])
@admin_required
def admin_users():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            username = request.form.get("username","")
            email    = request.form.get("email","")
            password = request.form.get("password","")
            role     = request.form.get("role","user")
            ok, result = create_user(username, email, password, role)
            if ok:
                uid = result
                # Save custom attributes
                attr_keys = request.form.getlist("attr_key")
                attr_vals = request.form.getlist("attr_val")
                attrs = {k.strip(): v for k, v in zip(attr_keys, attr_vals) if k.strip()}
                if attrs:
                    set_user_attrs(uid, attrs)
                flash(f"User '{username}' created.", "success")
            else:
                flash(result, "danger")
        elif action == "delete":
            uid = request.form.get("uid","")
            u   = _db_one("SELECT username FROM users WHERE id=?", (uid,))
            if u and u["username"] == get_admin_session().get("admin_user"):
                flash("You cannot delete your own account.", "danger")
            else:
                delete_user(uid)
                flash("User deleted.", "success")
        elif action == "edit_attrs":
            uid       = request.form.get("uid","")
            attr_keys = request.form.getlist("attr_key")
            attr_vals = request.form.getlist("attr_val")
            attrs = {k.strip(): v for k, v in zip(attr_keys, attr_vals) if k.strip()}
            set_user_attrs(uid, attrs)
            flash("User attributes updated.", "success")
        return redirect(url_for("admin_users"))

    users = list_users()

    def _user_row(u):
        uid       = u["id"]
        uname     = u["username"]
        email     = u.get("email") or "—"
        role_pill = '<span class="pill p-warn">admin</span>' if u["role"]=="admin" else '<span class="pill p-info">user</span>'
        created   = _fmt_ts(u.get("created",""))[:10]
        user_attrs = get_user_attrs(uid)
        attr_count = len(user_attrs)
        attrs_edit_rows = "".join(
            f"""<div class="attr-row">
              <input type="text" name="attr_key" value="{a['key']}" placeholder="Attribute" style="font-size:.75rem">
              <input type="text" name="attr_val" value="{a['value']}" placeholder="Value" style="font-size:.75rem">
              <button type="button" class="btn btn-sm btn-danger" onclick="this.closest('.attr-row').remove()">✕</button>
            </div>"""
            for a in user_attrs
        )
        # Add one blank row if no attrs
        if not user_attrs:
            attrs_edit_rows = """<div class="attr-row">
              <input type="text" name="attr_key" placeholder="Attribute" style="font-size:.75rem">
              <input type="text" name="attr_val" placeholder="Value" style="font-size:.75rem">
              <button type="button" class="btn btn-sm btn-danger" onclick="this.closest('.attr-row').remove()">✕</button>
            </div>"""

        return f"""<tr>
          <td class="mono">{uname}</td>
          <td class="muted">{email}</td>
          <td>{role_pill}</td>
          <td class="muted">{created}</td>
          <td>
            <span class="pill p-gray" style="cursor:pointer" onclick="toggleAttrEdit('{uid}')"
              title="Edit attributes">{attr_count} attr{"s" if attr_count!=1 else ""}</span>
          </td>
          <td>
            <form method="post" style="display:inline"
              onsubmit="return confirm('Delete user {uname}?')">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="uid" value="{uid}">
              <button type="submit" class="btn btn-sm btn-danger">Delete</button>
            </form>
          </td>
        </tr>
        <tr id="attr-edit-{uid}" style="display:none">
          <td colspan="6" style="padding:.75rem 1rem 1rem;background:rgba(0,229,255,.02)">
            <form method="post">
              <input type="hidden" name="action" value="edit_attrs">
              <input type="hidden" name="uid" value="{uid}">
              <div style="font-family:var(--fm);font-size:.68rem;color:var(--muted);
                text-transform:uppercase;letter-spacing:.08em;margin-bottom:.5rem">
                Custom Attributes for {uname}
              </div>
              <div id="attrs-container-{uid}">
                {attrs_edit_rows}
              </div>
              <div style="display:flex;gap:.5rem;margin-top:.5rem">
                <button type="button" class="btn btn-sm btn-secondary"
                  onclick="addAttrRow('{uid}')">＋ Add Attribute</button>
                <button type="submit" class="btn btn-sm btn-primary">Save Attributes</button>
              </div>
            </form>
          </td>
        </tr>"""

    rows = "".join(_user_row(u) for u in users)

    body = f"""
<div class="page-hd"><h1>User Management</h1>
  <p>Create local user accounts and manage custom attributes.</p>
</div>
<div class="g2">
  <div id="add-user-form" class="card">
    <div class="card-hd"><span class="card-title">Create New User</span></div>
    <div class="card-body">
      <form method="post">
        <input type="hidden" name="action" value="create">
        <div class="form-group"><label>Username *</label>
          <input type="text" name="username" placeholder="johndoe" required></div>
        <div class="form-group"><label>Email</label>
          <input type="text" name="email" placeholder="john@company.com"></div>
        <div class="form-group"><label>Password *</label>
          <input type="password" name="password" required></div>
        <div class="form-group"><label>Role</label>
          <select name="role">
            <option value="user" selected>user — login + app page access</option>
            <option value="admin">admin — full admin panel access</option>
          </select>
        </div>

        <div style="border-top:1px solid var(--border);padding-top:1rem;margin-top:.25rem">
          <div style="font-family:var(--fm);font-size:.68rem;color:var(--muted);
            text-transform:uppercase;letter-spacing:.08em;margin-bottom:.6rem">
            Custom Attributes (optional)
          </div>
          <div style="font-size:.76rem;color:var(--muted);margin-bottom:.6rem">
            These attributes appear on the user's welcome page after local login.
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:.5rem;margin-bottom:.35rem">
            <span class="muted" style="font-size:.63rem;font-family:var(--fm)">Attribute</span>
            <span class="muted" style="font-size:.63rem;font-family:var(--fm)">Value</span>
            <span></span>
          </div>
          <div id="new-user-attrs">
            <div class="attr-row">
              <input type="text" name="attr_key" placeholder="e.g. department" style="font-size:.78rem">
              <input type="text" name="attr_val" placeholder="e.g. Engineering" style="font-size:.78rem">
              <button type="button" class="btn btn-sm btn-danger"
                onclick="this.closest('.attr-row').remove()">✕</button>
            </div>
          </div>
          <button type="button" class="btn btn-sm btn-secondary" style="margin-top:.4rem;margin-bottom:.75rem"
            onclick="addNewUserAttr()">＋ Add Attribute</button>
        </div>

        <button type="submit" class="btn btn-primary">Create User</button>
      </form>
    </div>
  </div>
  <div>
    <div class="card">
      <div class="card-hd"><span class="card-title">Role Permissions</span></div>
      <div class="card-body" style="font-size:.83rem">
        <div style="border-left:3px solid var(--accent);padding:.65rem 1rem;
          background:rgba(0,229,255,.04);border-radius:0 8px 8px 0;margin-bottom:.65rem">
          <strong style="color:var(--accent)">user</strong>
          <div style="color:var(--muted);font-size:.76rem;margin-top:.3rem">
            ✓ Login Page &amp; local/SAML auth<br>✓ App page after login
          </div>
        </div>
        <div style="border-left:3px solid var(--warning);padding:.65rem 1rem;
          background:rgba(245,158,11,.04);border-radius:0 8px 8px 0">
          <strong style="color:var(--warning)">admin</strong>
          <div style="color:var(--muted);font-size:.76rem;margin-top:.3rem">
            ✓ Everything above<br>✓ Admin panel, IdP config, users, logs
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<div id="users-table" class="card">
  <div class="card-hd">
    <span class="card-title">All Users ({len(users)})</span>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Created</th><th>Attributes</th><th>Actions</th></tr></thead>
      <tbody>
        {rows or '<tr><td colspan="6" class="muted" style="text-align:center;padding:2rem">No users yet.</td></tr>'}
      </tbody>
    </table>
  </div>
</div>
<script>
function toggleAttrEdit(uid){{
  var row=document.getElementById('attr-edit-'+uid);
  if(row) row.style.display=row.style.display==='none'?'':'none';
}}
function addAttrRow(uid){{
  var c=document.getElementById('attrs-container-'+uid);
  if(!c) return;
  var d=document.createElement('div'); d.className='attr-row';
  d.innerHTML='<input type="text" name="attr_key" placeholder="Attribute" style="font-size:.75rem">'+
    '<input type="text" name="attr_val" placeholder="Value" style="font-size:.75rem">'+
    '<button type="button" class="btn btn-sm btn-danger" onclick="this.closest(\\'.attr-row\\').remove()">✕</button>';
  c.appendChild(d);
}}
function addNewUserAttr(){{
  var c=document.getElementById('new-user-attrs');
  if(!c) return;
  var d=document.createElement('div'); d.className='attr-row';
  d.innerHTML='<input type="text" name="attr_key" placeholder="e.g. department" style="font-size:.78rem">'+
    '<input type="text" name="attr_val" placeholder="e.g. Engineering" style="font-size:.78rem">'+
    '<button type="button" class="btn btn-sm btn-danger" onclick="this.closest(\\'.attr-row\\').remove()">✕</button>';
  c.appendChild(d);
}}
</script>"""

    tutorial = [
      {"sel": None,
       "title": "User Management Overview",
       "body": "Manage local user accounts for testing username/password (non-SAML) authentication. These accounts are entirely separate from your IdP — they let you test the app page without a live SAML connection."},
      {"sel": "#users-table",
       "title": "User List",
       "body": "All local accounts appear here. The <em>Attributes</em> badge shows how many custom attributes a user has — click it to expand an inline editor. The Delete button permanently removes the user and all their attributes."},
      {"sel": "#add-user-form",
       "title": "Create a User",
       "body": "Fill in a username, optional email, password, and role, then click <strong>Create User</strong>. The <em>user</em> role gives login-only access; the <em>admin</em> role unlocks the full admin panel."},
      {"sel": "#new-user-attrs",
       "title": "Custom Attributes",
       "body": "These key-value pairs are stored with the user and appear on their welcome page after a successful local login — simulating the attribute payload a SAML assertion would normally carry. Use them to test attribute-driven logic without a live IdP."},
    ]
    return _admin_page("User Management","users",body,tutorial)

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — LOGS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/logs", methods=["GET","POST"])
@admin_required
def admin_logs():
    if request.method == "POST":
        clear_auth_logs()
        flash("All logs cleared.", "success")
        return redirect(url_for("admin_logs"))

    dbg    = is_debug()
    events = get_auth_logs(800)
    groups = group_logs(events)

    # All IdPs for filter dropdown
    all_idp_names = sorted({g["summary"]["idp"] for g in groups} - {"—"})
    all_users     = sorted({g["summary"]["username"] for g in groups} - {"—"})
    all_ips       = sorted({g["summary"]["ip"] for g in groups} - {"—"})

    def _protocol_of_step(step_name):
        sn = step_name or ""
        if sn.startswith("OIDC"):  return "oidc"
        if sn.startswith("Local"): return "local"
        return "saml"

    def _pill_idp(n, protocol=""):
        clr = "p-info" if n=="okta" else "p-purple" if n=="duo" else "p-gray"
        if protocol == "oidc":
            pb = '<span class="pill p-warn" style="font-size:.55rem;margin-left:.25rem">OIDC</span>'
        elif protocol == "saml":
            pb = '<span class="pill p-info" style="font-size:.55rem;margin-left:.25rem">SAML</span>'
        elif protocol == "local":
            pb = '<span class="pill p-gray" style="font-size:.55rem;margin-left:.25rem">LOCAL</span>'
        else:
            pb = ""
        return '<span class="pill ' + clr + '">' + n + '</span>' + pb

    groups_html = ""
    for g in groups:
        s = g["summary"]
        sid = g["session_id"].replace('"','').replace("'","")
        ts_disp = _fmt_ts(s["ts"])
        res_cls = "p-ok" if s["success"] else "p-err"
        res_lbl = "✓ Success" if s["success"] else "✗ Fail"
        err_txt = f'<span style="color:var(--danger);font-size:.68rem"> — {s["error"][:80]}</span>' if s.get("error") else ""
        all_snames = [st.get("step","") for st in g["steps"]]
        if any(n.startswith("OIDC") for n in all_snames):
            g_protocol = "oidc"
        elif any(n.startswith("Local") for n in all_snames):
            g_protocol = "local"
        else:
            g_protocol = "saml"

        # Sort steps: step-number first (Step 1, Step 2…), then timestamp
        def _step_sort_key(st):
            sn = st.get("step", "") or ""
            # Extract leading integer from "Step N" or "OIDC Step N" or "Local…"
            m = re.search(r"(?:OIDC\s+)?Step\s+(\d+)", sn, re.IGNORECASE)
            num = int(m.group(1)) if m else 999
            # Logout/SLO/Admin events go last
            if any(k in sn for k in ("Logout", "SLO", "Admin", "admin")):
                num = 900
            return (num, st.get("ts", ""))
        g["steps"].sort(key=_step_sort_key)
        steps_html = ""
        for st in g["steps"]:
            st_ok = st.get("success")
            st_pill = f'<span class="pill {"p-ok" if st_ok else "p-err"}" style="font-size:.6rem">{"✓" if st_ok else "✗"}</span>'
            lvl = st.get("level","")
            lvl_badge = '<span class="pill p-debug" style="font-size:.58rem">DBG</span> ' if lvl=="debug" else ""
            st_err = f'<div style="color:var(--danger);font-size:.67rem;margin-top:.2rem">{st.get("error","")[:100]}</div>' if st.get("error") else ""
            detail = st.get("detail_json")
            detail_html = ""
            if detail:
                try:
                    pretty = json.dumps(json.loads(detail), indent=2)
                except Exception:
                    pretty = detail
                detail_html = f'<pre style="margin-top:.35rem;max-height:180px;overflow-y:auto;font-size:.68rem">{pretty}</pre>'
            steps_html += f"""<tr>
              <td class="muted" style="white-space:nowrap">{_fmt_ts(st.get("ts",""))}</td>
              <td style="font-family:var(--fm);font-size:.7rem">{lvl_badge}{st.get("step","")}</td>
              <td>{_pill_idp(st.get("idp","") or "—", _protocol_of_step(st.get("step","")))}</td>
              <td>{st_pill}{st_err}{detail_html}</td>
              <td class="muted">{st.get("_display_user","—")}</td>
              <td class="muted">{st.get("ip","")}</td>
            </tr>"""

        groups_html += f"""
<div class="log-group"
  data-idp="{s['idp']}"
  data-user="{s['username']}"
  data-ip="{s['ip']}"
  data-result="{'success' if s['success'] else 'fail'}"
  data-protocol="{g_protocol}"
  data-error="{s.get('error','')}"
  data-ts="{s['ts']}"
  data-text="{s['username']} {s['idp']} {s['ip']} {g_protocol} {s.get('last_step','')} {s.get('error','')}">
  <div class="log-group-hd" onclick="toggleGroup('{sid}')">
    <span class="muted" style="font-family:var(--fm);font-size:.7rem;min-width:130px;white-space:nowrap">{ts_disp}</span>
    {_pill_idp(s['idp'], g_protocol)}
    <span class="pill {res_cls}">{res_lbl}</span>
    <span style="font-family:var(--fm);font-size:.73rem">{s['username']}</span>
    <span class="muted" style="font-family:var(--fm);font-size:.68rem">{s['ip']}</span>
    <span class="muted" style="font-size:.67rem;font-family:var(--fm)">{s['step_count']} step{"s" if s["step_count"]!=1 else ""}</span>
    {err_txt}
    <span style="margin-left:auto;color:var(--muted);font-size:.75rem">▸</span>
  </div>
  <div class="log-group-body" id="grp-{sid}">
    <table><thead><tr><th>Time</th><th>Step</th><th>IdP</th><th>Result</th><th>User</th><th>IP</th></tr></thead>
    <tbody>{steps_html}</tbody></table>
  </div>
</div>"""

    # Step reference sidebar — SAML
    def _ref_item(name, desc, url=None):
        link = f' <a href="{url}" target="_blank" style="color:var(--accent);font-size:.67rem" rel="noopener">learn more ↗</a>' if url else ""
        return (f'<div style="padding:.55rem .85rem;border-left:3px solid var(--accent);' +
                f'background:rgba(0,229,255,.03);border-radius:0 7px 7px 0;margin-bottom:.5rem">' +
                f'<div style="font-family:var(--fm);font-size:.72rem;color:var(--accent);font-weight:700">{name}</div>' +
                f'<div style="color:var(--muted);font-size:.71rem;margin-top:.15rem">{desc}{link}</div></div>')

    saml_steps = [
        ("Step 1 — SSO Initiated", "User clicks the SAML login button. The SP (this app) builds a signed <AuthnRequest> XML document containing the SP Entity ID, ACS URL, and a unique ID. This is base64-encoded and either POSTed or sent as a query string depending on the binding.", "https://developer.okta.com/docs/concepts/saml/#sp-initiated-sso"),
        ("Step 2 — Redirect to IdP", "The browser is redirected to the IdP's SSO URL carrying the encoded SAMLRequest. The IdP presents its login UI. The user authenticates with credentials, MFA, or SSO session. This step happens entirely at the IdP — the SP has no visibility into it.", "https://developer.okta.com/docs/concepts/saml/#saml-flow"),
        ("Step 3 — ACS Hit", "After successful authentication the IdP HTTP-POSTs a signed SAMLResponse back to the SP's Assertion Consumer Service (ACS) URL. The response contains a SAML Assertion with the NameID, AttributeStatements, Conditions (audience, expiry), and a digital signature. The SP must not trust anything in the response until Step 5.", "https://developer.okta.com/docs/concepts/saml/#the-sp-acs"),
        ("Step 4 — Response Parsed", "The SP base64-decodes and XML-parses the SAMLResponse. It extracts the Assertion node, NameID format and value, all AttributeStatements, NotBefore/NotOnOrAfter conditions, and the signature block. Any malformed XML or missing nodes cause an immediate failure here.", "https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language"),
        ("Step 5 — Signature Check", "The SP verifies the XML digital signature on the Assertion (and optionally the Response envelope) against the IdP's X.509 certificate stored in configuration. This step also enforces Conditions: audience restriction must match SP Entity ID, and current time must be within NotBefore/NotOnOrAfter. A failure here means the assertion cannot be trusted.", "https://www.samltool.com/validate_response.php"),
        ("Step 6 — Auth Complete", "All checks passed. The SP creates an authenticated session, stores the NameID and extracted attributes, and redirects to the RelayState destination URL (or the app home). From this point the user is logged in.", "https://developer.okta.com/docs/concepts/saml/#saml-flow"),
        ("Logout (SLO)", "Single Logout: the SP sends a LogoutRequest to the IdP's SLO endpoint (or the IdP sends one to the SP). The IdP invalidates the IdP session and notifies all SPs that participated in the SSO session. The SP clears its local session and redirects to the login page.", "https://developer.okta.com/docs/concepts/saml/#single-logout"),
    ]

    oidc_steps = [
        ("OIDC Step 1 — Login Initiated", "User clicks the OIDC login button. The SP generates a cryptographically random state token (CSRF protection) and nonce (replay protection), and optionally a PKCE code_verifier + code_challenge pair (SHA-256). These are stored in the user's session for later verification.", "https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth"),
        ("OIDC Step 2 — Redirect to IdP", "The browser is redirected to the IdP's Authorization Endpoint with: client_id, response_type=code, scope (openid profile email), redirect_uri, state, nonce, and code_challenge (if PKCE). The IdP authenticates the user with credentials/MFA. This step is entirely at the IdP — the SP only sees the redirect.", "https://developer.okta.com/docs/concepts/oauth-openid/#openid-connect"),
        ("OIDC Step 3 — Callback", "After authentication the IdP redirects the browser back to the SP's redirect_uri (callback URL) with: code (authorization code, valid ~60 seconds) and state. The SP first verifies state matches the stored value — a mismatch indicates a CSRF attack and must be rejected.", "https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse"),
        ("OIDC Step 4 — Token Exchange", "The SP makes a back-channel (server-to-server) POST to the IdP's Token Endpoint, exchanging the authorization code for tokens. The request includes: code, client_id, client_secret (or PKCE code_verifier), redirect_uri, and grant_type=authorization_code. The IdP returns: access_token, id_token (JWT), token_type, and optionally refresh_token.", "https://developer.okta.com/docs/reference/api/oidc/#token"),
        ("OIDC Step 5 — Token Validation", "The SP validates the ID token JWT: (1) decode the header to find the key ID (kid) and signing algorithm, (2) fetch the IdP's JWKS (public key set) and verify the JWT signature, (3) check exp (not expired), iat (not future-dated), nonce (matches stored value), iss (matches configured issuer), and aud (contains client_id). Optionally calls the Userinfo Endpoint with the access_token to get additional claims.", "https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation"),
        ("OIDC Step 6 — Auth Complete", "All validation passed. The SP extracts the username from preferred_username, email, or sub claims, stores all claims in the session, and redirects to the app. The id_token and access_token are stored for potential logout use.", "https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse"),
        ("Logout (OIDC RP-Initiated)", "The SP clears its local session and (if configured) redirects to the IdP's end_session_endpoint with id_token_hint and post_logout_redirect_uri. The IdP invalidates the IdP session. Unlike SAML SLO, OIDC logout does not automatically notify other RPs — each must implement its own session check.", "https://openid.net/specs/openid-connect-rpinitiated-1_0.html"),
    ]

    step_ref_saml = "".join(_ref_item(n, d, u) for n, d, u in saml_steps)
    step_ref_oidc = "".join(_ref_item(n, d, u) for n, d, u in oidc_steps)

    idp_opts  = "".join(f'<option value="{n}">{n}</option>' for n in all_idp_names)
    user_opts = "".join(f'<option value="{n}">{n}</option>' for n in all_users)
    ip_opts   = "".join(f'<option value="{n}">{n}</option>' for n in all_ips)

    body = f"""
<div class="page-hd" style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem">
  <div>
    <h1>Authentication Logs</h1>
    <p>{len(groups)} attempt{"s" if len(groups)!=1 else ""} &nbsp;·&nbsp;
      Debug logging is <strong style="color:{'var(--warning)' if dbg else 'var(--muted)'}">
      {'ON — verbose detail' if dbg else 'OFF — summary only'}</strong>
    </p>
  </div>
  <div style="display:flex;gap:.6rem;flex-wrap:wrap">
    <a href="/admin/logs/export" class="btn btn-sm btn-secondary">⬇ Export JSON</a>
    <form method="post" style="display:inline">
      <button type="submit" class="btn btn-sm btn-danger"
        onclick="return confirm('Clear all logs?')">🗑 Clear All</button>
    </form>
  </div>
</div>

{'<div class="alert alert-warning">🔍 Debug mode ON — full SAML assertion details captured below each step.</div>' if dbg else '<div class="alert alert-info">📋 Summary mode — enable Debug Logging in <a href="/admin/settings" style="color:var(--accent)">Settings</a> for full detail.</div>'}

<div style="display:grid;grid-template-columns:1fr 280px;gap:1.25rem;align-items:start">
<div>

<!-- Filters & search -->
<div id="log-filters" class="card" style="margin-bottom:1rem">
  <div class="card-body" style="padding:.85rem 1rem">
    <div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center">
      <input type="text" id="searchInput" placeholder='Search — use "quotes" for exact match'
        style="flex:2;min-width:180px;font-size:.78rem" oninput="filterLogs()">
      <select id="filterProtocol" onchange="filterLogs()" style="font-size:.78rem;flex:1;min-width:90px">
        <option value="">All Protocols</option>
        <option value="saml">SAML</option>
        <option value="oidc">OIDC</option>
        <option value="local">Local</option>
      </select>
      <select id="filterIdp" onchange="filterLogs()" style="font-size:.78rem;flex:1;min-width:100px">
        <option value="">All IdPs</option>{idp_opts}
      </select>
      <select id="filterUser" onchange="filterLogs()" style="font-size:.78rem;flex:1;min-width:100px">
        <option value="">All Users</option>{user_opts}
      </select>
      <select id="filterIp" onchange="filterLogs()" style="font-size:.78rem;flex:1;min-width:100px">
        <option value="">All IPs</option>{ip_opts}
      </select>
      <select id="filterResult" onchange="filterLogs()" style="font-size:.78rem;flex:1;min-width:100px">
        <option value="">All Results</option>
        <option value="success">Success</option>
        <option value="fail">Failed</option>
      </select>
      <button class="btn btn-sm btn-secondary" onclick="clearFilters()">✕ Clear</button>
    </div>
    <div id="filterCount" style="font-family:var(--fm);font-size:.68rem;color:var(--muted);margin-top:.5rem"></div>
  </div>
</div>

<div id="logGroups">
  {groups_html if groups else '<div class="card"><div class="card-body muted" style="text-align:center;padding:2.5rem">No log entries yet.</div></div>'}
</div>

</div>
<div>
  <div id="step-reference" class="card" style="position:sticky;top:70px">
    <div class="card-hd">
      <span class="card-title">Step Reference</span>
      <span class="hint-text" style="margin-left:auto">Select a protocol below</span>
    </div>
    <div class="ref-tab-bar">
      <button class="ref-tab active" id="ref-tab-saml" onclick="showRefTab('saml')">SAML Steps</button>
      <button class="ref-tab" id="ref-tab-oidc" onclick="showRefTab('oidc')">OIDC Steps</button>
    </div>
    <div id="ref-saml" class="ref-panel-content active">{step_ref_saml}</div>
    <div id="ref-oidc" class="ref-panel-content">{step_ref_oidc}</div>
  </div>
</div>
</div>

<script>
function toggleGroup(sid){{
  var el=document.getElementById('grp-'+sid);
  if(el) el.classList.toggle('open');
}}
function showRefTab(proto){{
  ['saml','oidc'].forEach(function(p){{
    document.getElementById('ref-'+p).classList.toggle('active', p===proto);
    document.getElementById('ref-tab-'+p).classList.toggle('active', p===proto);
  }});
}}
function filterLogs(){{
  var raw   = (document.getElementById('searchInput').value||'').trim();
  var proto = document.getElementById('filterProtocol').value;
  var idp   = document.getElementById('filterIdp').value;
  var user  = document.getElementById('filterUser').value;
  var ip    = document.getElementById('filterIp').value;
  var res   = document.getElementById('filterResult').value;
  var exactMatch = null, words = [];
  var qm = raw.match(/^"(.+)"$/);
  if(qm){{ exactMatch = qm[1].toLowerCase(); }}
  else{{ words = raw.toLowerCase().split(' ').filter(Boolean); }}
  var groups = document.querySelectorAll('.log-group');
  var visible = 0;
  groups.forEach(function(g){{
    var text   = (g.dataset.text||'').toLowerCase();
    var gIdp   = g.dataset.idp||'';
    var gProto = g.dataset.protocol||'';
    var gUser  = g.dataset.user||'';
    var gIp    = g.dataset.ip||'';
    var gRes   = g.dataset.result||'';
    var show = true;
    if(proto && gProto!==proto) show=false;
    if(idp   && gIdp!==idp)    show=false;
    if(user  && gUser!==user)  show=false;
    if(ip    && gIp!==ip)      show=false;
    if(res   && gRes!==res)    show=false;
    if(exactMatch !== null && text.indexOf(exactMatch)===-1) show=false;
    if(words.length && !words.every(function(w){{return text.indexOf(w)>=0;}})) show=false;
    g.style.display = show ? '' : 'none';
    if(show) visible++;
  }});
  var fc = document.getElementById('filterCount');
  if(fc) fc.textContent = visible < groups.length ? visible+' of '+groups.length+' attempts shown' : '';
}}
function clearFilters(){{
  document.getElementById('searchInput').value='';
  document.getElementById('filterProtocol').value='';
  document.getElementById('filterIdp').value='';
  document.getElementById('filterUser').value='';
  document.getElementById('filterIp').value='';
  document.getElementById('filterResult').value='';
  filterLogs();
}}
</script>"""

    tutorial = [
      {"sel": None,
       "title": "Authentication Logs Overview",
       "body": "Every authentication attempt — SAML, OIDC, or local — is recorded here as a collapsible group of steps. Each group is one complete session: all log entries sharing the same session ID are merged, so you see the full picture from first redirect to final session establishment or error."},
      {"sel": "#log-filters",
       "title": "Filters & Search",
       "body": "Six filters let you slice the log view instantly. <strong>Protocol</strong> (SAML / OIDC / Local) is the most useful starting point — filter to OIDC to focus on token exchange issues, or SAML to debug assertion errors. The <strong>search box</strong> matches across username, IdP, IP, step name, and error text — wrap a phrase in \"quotes\" for an exact match. The count shows how many sessions are currently visible versus total."},
      {"sel": "#logGroups",
       "title": "Authentication Groups",
       "body": "Each card is one complete login session. The header shows: timestamp, IdP name, protocol badge (SAML / OIDC / LOCAL), success/fail pill, username, source IP, and step count. Click a header to expand it into a step table. Debug mode adds extra rows with full XML assertions (SAML) or decoded JWT claims (OIDC). Steps are color-coded: green ✓ = passed, red ✗ = where the flow failed."},
      {"sel": "#step-reference",
       "title": "Step Reference — SAML & OIDC",
       "body": "Click to expand this panel, then choose SAML Steps or OIDC Steps. <br><br><strong>SAML flow</strong>: Step 1 (build AuthnRequest) → Step 2 (browser redirect to IdP, user authenticates) → Step 3 (IdP POSTs SAMLResponse to ACS) → Step 4 (XML parsed) → Step 5 (signature + conditions verified) → Step 6 (session created). The most common failure points are Step 5 (wrong cert, expired assertion, audience mismatch) and Step 3 (ACS URL not registered in IdP).<br><br><strong>OIDC flow</strong>: Step 1 (generate state/nonce/PKCE) → Step 2 (browser redirect to authorization endpoint) → Step 3 (callback with code + state check) → Step 4 (back-channel token exchange) → Step 5 (JWT signature + claims validation, optional userinfo call) → Step 6 (session created). The most common failure points are Step 3 (state mismatch = CSRF) and Step 5 (wrong issuer, expired token, missing cryptography package for signature check). Each step card links to the official spec."},
    ]
    return _admin_page("Logs","logs",body,tutorial)

@app.route("/admin/logs/export")
@admin_required
def admin_logs_export():
    events = get_auth_logs(10000)
    resp   = make_response(json.dumps(events, indent=2, default=str))
    resp.headers["Content-Type"]        = "application/json"
    resp.headers["Content-Disposition"] = 'attachment; filename="saml_testbench_logs.json"'
    return resp

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/settings", methods=["GET","POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        set_setting("debug_enabled", "1" if request.form.get("debug_enabled") else "0")
        set_setting("active_idp",    request.form.get("active_idp","okta"))
        new_port = request.form.get("port","").strip()
        if new_port.isdigit() and 1024 <= int(new_port) <= 65535:
            set_setting("port", new_port)
            flash(f"Settings saved. Port changed to {new_port} — restart the server for it to take effect.", "success")
        else:
            if new_port:
                flash("Settings saved (port ignored — must be 1024–65535).", "warning")
            else:
                flash("Settings saved.", "success")
        return redirect(url_for("admin_settings"))

    dbg      = is_debug()
    active   = get_setting("active_idp","okta")
    all_idps = list_idps()
    saved_port = get_setting("port", str(PORT))

    idp_options = "".join(
        f'<option value="{i["name"]}" {"selected" if i["name"]==active else ""}>{i.get("label") or i["name"].capitalize()}</option>'
        for i in all_idps
    )

    body = f"""
<div class="page-hd"><h1>Settings</h1>
  <p>Configure global defaults and logging behaviour.</p>
</div>
<form method="post">
  <div class="g2">
    <div>
      <div id="settings-idp-card" class="card">
        <div class="card-hd"><span class="card-title">Active Identity Provider</span></div>
        <div class="card-body">
          <div class="form-group">
            <label>Default IdP for SAML flows</label>
            <select name="active_idp">{idp_options}</select>
            <div class="form-hint">Used as default when no IdP is specified in the SAML request</div>
          </div>
        </div>
      </div>

      <div id="settings-debug-card" class="card">
        <div class="card-hd"><span class="card-title">Debug Logging</span></div>
        <div class="card-body">
          <div class="toggle-row">
            <div class="toggle-info">
              <strong>Enable Debug Logging</strong>
              <small>Log full SAML assertion content, all attributes, NameID details and signature info.</small>
            </div>
            <label class="switch">
              <input type="checkbox" name="debug_enabled" {'checked' if dbg else ''}>
              <span class="slider"></span>
            </label>
          </div>
          <div style="margin-top:1.1rem;border:1px solid var(--border);border-radius:8px;overflow:hidden">
            <div style="padding:.6rem 1rem;background:var(--bg);border-bottom:1px solid var(--border);
              font-family:var(--fm);font-size:.65rem;font-weight:700;text-transform:uppercase;
              letter-spacing:.08em;color:var(--muted)">Logging Mode Comparison</div>
            <div style="padding:.9rem 1rem;font-family:var(--fm);font-size:.74rem;color:var(--muted)">
              <strong class="pill p-gray" style="display:inline-block;margin-bottom:.35rem">Summary</strong><br>
              Step name · Success/fail · Username · Source IP · IdP · Timestamp<br><br>
              <strong class="pill p-debug" style="display:inline-block;margin-bottom:.35rem">Debug</strong><br>
              Everything above + full SAMLRequest/Response · All assertion attributes · NameID ·
              Session index · Signature algorithm
            </div>
          </div>
        </div>
      </div>
      <div id="settings-port-card" class="card">
        <div class="card-hd"><span class="card-title">Server Port</span>
          <span class="pill p-gray" style="font-size:.62rem">Restart required</span>
        </div>
        <div class="card-body">
          <div class="form-group" style="margin-bottom:.5rem">
            <label>Listening Port <span class='muted'>(currently {PORT})</span></label>
            <input type="number" name="port" value="{saved_port}" min="1024" max="65535"
              style="width:120px">
            <div class="form-hint">Change and restart to listen on a different port (e.g. 5001 for a second instance). You can also edit <code>PORT&nbsp;=&nbsp;5000</code> directly in the .py file.</div>
          </div>
        </div>
      </div>

    </div>

    <div>
      <div id="settings-sp-card" class="card">
        <div class="card-hd"><span class="card-title">SP Endpoint Reference</span></div>
        <div class="card-body" style="font-family:var(--fm);font-size:.76rem">
          {"".join(f'<div style="margin-bottom:.85rem"><div style="color:var(--muted);margin-bottom:.25rem">{label}</div><div style="color:var(--accent);background:var(--bg);padding:.45rem .7rem;border-radius:6px;word-break:break-all">{url}</div></div>' for label, url in [
            ("ACS URL (Single Sign-On URL)", f"http://localhost:{PORT}/saml/acs"),
            ("SP Entity ID / Audience URI",  f"http://localhost:{PORT}/saml/metadata"),
            ("SLO URL (Single Logout)",       f"http://localhost:{PORT}/saml/slo"),
          ])}
          <a href="/saml/metadata" target="_blank" class="btn btn-outline btn-sm">📄 View SP Metadata XML</a>
        </div>
      </div>

      <div class="card">
        <div class="card-hd"><span class="card-title">Install Location</span></div>
        <div class="card-body" style="font-size:.82rem">
          <div style="margin-bottom:.65rem">
            <div class="muted" style="font-family:var(--fm);font-size:.65rem;margin-bottom:.25rem">SCRIPT DIRECTORY</div>
            <div style="font-family:var(--fm);color:var(--accent);background:var(--bg);
              padding:.45rem .7rem;border-radius:6px;word-break:break-all;font-size:.75rem">{APP_DIR}</div>
          </div>
          <div style="margin-bottom:.85rem">
            <div class="muted" style="font-family:var(--fm);font-size:.65rem;margin-bottom:.25rem">DATABASE</div>
            <div style="font-family:var(--fm);color:var(--accent);background:var(--bg);
              padding:.45rem .7rem;border-radius:6px;word-break:break-all;font-size:.75rem">{DB_PATH}</div>
          </div>
          <button type="button" class="btn btn-sm btn-secondary" onclick="openFolder()">📁 Open Folder</button>
        </div>
      </div>
    </div>
  </div>
  <button type="submit" class="btn btn-primary">💾 Save Settings</button>
</form>

<!-- Export Settings -->
<div id="settings-export-card" style="margin-top:1.75rem">
<div class="card" style="border-color:rgba(0,229,255,.2)">
  <div class="card-hd" style="background:rgba(0,229,255,.03)">
    <span class="card-title" style="color:var(--accent)">📄 Export Settings Document</span>
  </div>
  <div class="card-body">
    <p style="font-size:.82rem;color:var(--muted);margin-bottom:1rem">
      Download a human-readable text document of every current setting — active IdP,
      debug mode, watched attributes, SP endpoints, and file paths — with a description
      of where each value is stored and how to change it. Useful for documenting your
      test environment or onboarding a new team member.
    </p>
    <a href="/admin/settings/export" class="btn btn-secondary" download>⬇ Export Settings (.txt)</a>
  </div>
</div>
</div>

<!-- Move Data -->
<div style="margin-top:1.75rem">
<div class="card" style="border-color:rgba(0,229,255,.2)">
  <div class="card-hd" style="background:rgba(0,229,255,.03)">
    <span class="card-title" style="color:var(--accent)">📦 Move / Copy Data</span>
  </div>
  <div class="card-body">
    <p style="font-size:.82rem;color:var(--muted);margin-bottom:1.1rem">
      Copy the script, database, and SAML cache to a new folder.
      Close this app and run it from the new location to use it there.
    </p>
    <div style="display:flex;gap:.65rem;align-items:flex-end;flex-wrap:wrap">
      <div style="flex:1;min-width:250px">
        <label>Destination Folder</label>
        <input type="text" id="moveDestPath"
          placeholder="C:\\Users\\me\\NewFolder or /home/me/newdir">
      </div>
      <button class="btn btn-secondary" onclick="moveData()">📋 Copy to Folder</button>
    </div>
    <div id="moveResult" style="margin-top:.75rem;font-family:var(--fm);font-size:.78rem"></div>
  </div>
</div>
</div>

<!-- Service Management -->
<div id="settings-service-card" style="margin-top:1.75rem">
<div class="card" style="border-color:rgba(0,229,255,.2)">
  <div class="card-hd" style="background:rgba(0,229,255,.03)">
    <span class="card-title" style="color:var(--accent)">&#x2699; Background Service</span>
    <span id="svc-status-pill" class="pill p-gray" style="font-size:.62rem">Checking&#x2026;</span>
  </div>
  <div class="card-body">
    <p style="font-size:.82rem;color:var(--muted);margin-bottom:1rem">
      Install SAML TestBench as a background service so it starts automatically at boot
      and runs without a terminal window.
      <strong style="color:var(--text)">Windows</strong> uses Task Scheduler,
      <strong style="color:var(--text)">Linux</strong> uses systemd,
      <strong style="color:var(--text)">macOS</strong> uses LaunchAgent.
      Root / Administrator privileges may be required.
    </p>
    <div style="display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:.85rem">
      <button class="btn btn-sm btn-secondary" onclick="svcAction('install')">&#x1F4CC; Install Service</button>
      <button class="btn btn-sm btn-secondary" onclick="svcAction('uninstall')">&#x1F5D1; Uninstall Service</button>
      <button class="btn btn-sm btn-secondary" onclick="svcAction('start')">&#x25B6; Start</button>
      <button class="btn btn-sm btn-secondary" onclick="svcAction('stop')">&#x23F9; Stop</button>
    </div>
    <div id="svc-detail" style="font-family:var(--fm);font-size:.72rem;color:var(--muted);margin-bottom:.6rem"></div>
    <div id="svc-result" style="font-size:.79rem;padding:.6rem .85rem;border-radius:8px;
      display:none;white-space:pre-wrap;word-break:break-word;line-height:1.55"></div>
  </div>
</div>
</div>
<script>
(function(){{
  function _pill(installed, running){{
    if(running)   return '<span class="pill p-ok"  style="font-size:.62rem">&#x25CF; Running</span>';
    if(installed) return '<span class="pill p-warn" style="font-size:.62rem">&#x25CF; Installed (stopped)</span>';
    return '<span class="pill p-gray" style="font-size:.62rem">&#x25CB; Not installed</span>';
  }}
  function _updateSvc(st){{
    var pill = document.getElementById('svc-status-pill');
    if(pill) {{ pill.outerHTML = _pill(st.installed, st.running)
              .replace('<span class=', '<span id="svc-status-pill" class='); }}
    var det = document.getElementById('svc-detail');
    if(det) det.textContent = (st.detail||'') + (st.platform ? '  [' + st.platform + ']' : '');
  }}
  window.svcAction = function(action){{
    var res = document.getElementById('svc-result');
    res.style.display='none'; res.textContent='';
    var btn = event.target; btn.disabled=true;
    var orig = btn.textContent; btn.textContent='&#x2026;';
    fetch('/admin/service/'+action, {{method:'POST'}})
      .then(function(r){{return r.json();}})
      .then(function(d){{
        btn.disabled=false; btn.textContent=orig;
        res.style.display='block';
        if(d.ok){{
          res.style.cssText='font-size:.79rem;padding:.6rem .85rem;border-radius:8px;display:block;white-space:pre-wrap;word-break:break-word;line-height:1.55;background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.25);color:var(--success)';
          res.textContent='\u2713 ' + (d.message||'Done.');
        }} else {{
          res.style.cssText='font-size:.79rem;padding:.6rem .85rem;border-radius:8px;display:block;white-space:pre-wrap;word-break:break-word;line-height:1.55;background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.25);color:var(--danger)';
          res.textContent='\u2717 ' + (d.error||'Unknown error.');
        }}
        if(d.status) _updateSvc(d.status);
      }}).catch(function(e){{
        btn.disabled=false; btn.textContent=orig;
        res.style.display='block';
        res.textContent='Network error: '+e;
      }});
  }};
  function svcLoad(){{
    fetch('/admin/service/status').then(function(r){{return r.json();}}).then(_updateSvc).catch(function(){{}});
  }}
  document.addEventListener('DOMContentLoaded', svcLoad);
}})();
</script>

<!-- Danger Zone -->
<div id="settings-danger" style="margin-top:1.5rem">
<div class="card" style="border-color:rgba(239,68,68,.3)">
  <div class="card-hd" style="background:rgba(239,68,68,.04);border-color:rgba(239,68,68,.25)">
    <span class="card-title" style="color:var(--danger)">⚠ Danger Zone</span>
    <span class="pill p-err" style="font-size:.62rem">Irreversible</span>
  </div>
  <div class="card-body">
    <p style="font-size:.82rem;color:var(--muted);margin-bottom:1.25rem">
      These actions are permanent and cannot be undone.</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.1rem">

      <div style="border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:1.1rem">
        <div style="font-size:.92rem;font-weight:700;margin-bottom:.45rem">🗑 Clear SAML Cache</div>
        <div style="font-size:.76rem;color:var(--muted);line-height:1.55;margin-bottom:.85rem">
          Deletes the <code style="color:var(--accent)">.saml_cache/</code> folder. All IdP settings
          files rebuild automatically on next use.
        </div>
        <form method="post" action="/admin/settings/clear-cache"
          onsubmit="return confirm('Clear SAML cache?')">
          <button type="submit" class="btn btn-sm btn-danger">Clear Cache</button>
        </form>
      </div>

      <div style="border:1px solid rgba(239,68,68,.4);border-radius:10px;padding:1.1rem;background:rgba(239,68,68,.02)">
        <div style="font-size:.92rem;font-weight:700;margin-bottom:.45rem;color:var(--danger)">☢ Factory Reset</div>
        <div style="font-size:.76rem;color:var(--muted);line-height:1.55;margin-bottom:.85rem">
          Permanently deletes <strong style="color:var(--text)">everything</strong>: users, IdP config,
          logs, settings, secret keys. Recreates <code style="color:var(--accent)">admin / admin123</code>.
          All sessions immediately invalidated.
        </div>
        <form method="post" action="/admin/settings/factory-reset" onsubmit="return doReset()">
          <input type="hidden" name="confirmed" value="yes">
          <div style="display:flex;gap:.55rem;align-items:center;flex-wrap:wrap">
            <input type="text" id="reset-word" placeholder="Type RESET to confirm"
              style="flex:1;min-width:150px;font-size:.76rem;border-color:rgba(239,68,68,.4)">
            <button type="submit" class="btn btn-sm btn-danger">Factory Reset</button>
          </div>
        </form>
        <script>
        function doReset(){{
          if((document.getElementById('reset-word').value||'').trim()!=='RESET'){{
            alert('Type RESET exactly to confirm.'); return false;
          }}
          return confirm('Permanently erase ALL data and invalidate all sessions?');
        }}
        </script>
      </div>

    </div>
  </div>
</div>
</div>

<script>
function openFolder(){{
  fetch('/admin/open-folder').then(r=>r.json()).then(d=>{{
    if(!d.ok) alert('Could not open folder: '+d.error);
  }});
}}
function moveData(){{
  var dest = document.getElementById('moveDestPath').value.trim();
  if(!dest){{ alert('Enter a destination folder path.'); return; }}
  var btn = event.target; btn.disabled=true; btn.textContent='Copying…';
  fetch('/admin/move-data',{{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{dest_path:dest}})
  }}).then(r=>r.json()).then(d=>{{
    btn.disabled=false; btn.textContent='📋 Copy to Folder';
    var el=document.getElementById('moveResult');
    if(d.ok){{
      el.innerHTML='<span style="color:var(--success)">✓ '+d.message+'</span>';
    }} else {{
      el.innerHTML='<span style="color:var(--danger)">✗ '+d.error+'</span>';
    }}
  }}).catch(e=>{{
    btn.disabled=false; btn.textContent='📋 Copy to Folder';
    document.getElementById('moveResult').innerHTML='<span style="color:var(--danger)">Error: '+e+'</span>';
  }});
}}
</script>"""

    tutorial = [
      {"sel": None,
       "title": "Settings Overview",
       "body": "This page controls the global behaviour of SAML TestBench. Changes here affect all SAML flows and authentication sessions immediately."},
      {"sel": "#settings-idp-card",
       "title": "Active Identity Provider",
       "body": "Choose which IdP is used by default for SAML flows. This is the IdP whose SSO button shows first on the login page and whose certificate is used at /saml/acs when no ?idp= parameter is present in the request."},
      {"sel": "#settings-port-card",
       "title": "Server Port",
       "body": "Change the port SAML TestBench listens on — useful when running two instances simultaneously (e.g. port 5000 and 5001 for testing two IdPs side-by-side). Save and then restart the script for the change to take effect. You can also edit PORT&nbsp;=&nbsp;5000 directly at the top of the .py file before starting."},
      {"sel": "#settings-debug-card",
       "title": "Debug Logging",
       "body": "When enabled, every SAML step logs a full <em>debug</em> entry alongside the summary entry. Debug entries include the raw SAMLRequest/Response XML, every attribute in the assertion, the NameID and session index, and the signature algorithm. Disable this to keep the log database smaller in high-volume testing."},
      {"sel": "#settings-export-card",
       "title": "Export Settings Document",
       "body": "Downloads a plain-text file that documents every current setting: what it is, its current value, and exactly where in the admin UI or database it can be changed. Hand this to a colleague or keep it with your test environment notes."},
      {"sel": "#settings-sp-card",
       "title": "SP Endpoint Reference",
       "body": "These three URLs are what you register inside your IdP's SAML application config. The ACS URL is where the IdP posts the SAMLResponse. The Entity ID identifies this SP to the IdP. Copy them exactly — a mismatch here is the most common cause of SAML errors."},
      {"sel": "#settings-service-card",
       "title": "Background Service",
       "body": "Install SAML TestBench as a system service so it starts automatically at every boot without a terminal window. Windows uses Task Scheduler (no SCM driver needed), Linux uses systemd (falls back to a user-level service if you are not root), and macOS uses a LaunchAgent. Use Install to register the service, then Start/Stop to control it from here or with standard OS tools (schtasks, systemctl, launchctl). Uninstall removes only the registration — your database and config are not affected."},
      {"sel": "#settings-danger",
       "title": "Danger Zone",
       "body": "<strong>Clear SAML Cache</strong> removes the cached IdP settings files — they rebuild automatically on next use, picking up any certificate or URL changes you've saved. <strong>Factory Reset</strong> is nuclear: it permanently wipes all users, logs, IdP configs, and settings, then recreates the default admin/admin123 account. Type RESET to confirm."},
    ]
    return _admin_page("Settings","settings",body,tutorial)

@app.route("/admin/idp/export")
@admin_required
def admin_idp_export():
    payload = export_idp_config()
    resp    = make_response(json.dumps(payload, indent=2, default=str))
    resp.headers["Content-Type"]        = "application/json"
    resp.headers["Content-Disposition"] = 'attachment; filename="idp_config_export.json"'
    return resp

@app.route("/admin/idp/import", methods=["POST"])
@admin_required
def admin_idp_import():
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"ok": False, "error": "No JSON payload received."})
    imported, skipped, err = import_idp_config(payload)
    if err:
        return jsonify({"ok": False, "error": err})
    return jsonify({"ok": True, "imported": imported, "skipped": skipped})

@app.route("/admin/settings/export")
@admin_required
def admin_settings_export():
    doc  = export_settings_doc()
    resp = make_response(doc)
    resp.headers["Content-Type"]        = "text/plain; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="saml_testbench_settings.txt"'
    return resp

@app.route("/admin/settings/clear-cache", methods=["POST"])
@admin_required
def admin_clear_cache():
    clear_saml_cache()
    flash("SAML cache cleared.", "success")
    return redirect(url_for("admin_settings"))

@app.route("/admin/settings/factory-reset", methods=["POST"])
@admin_required
def admin_factory_reset():
    if request.form.get("confirmed") != "yes":
        flash("Factory reset cancelled.", "warning")
        return redirect(url_for("admin_settings"))
    factory_reset()
    app.secret_key             = _user_secret()
    app.config["ADMIN_SECRET"] = _admin_secret()
    return _clear_admin_cookie_response(url_for("admin_login") + "?reset=1")

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — UTILITY ACTIONS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/open-folder")
@admin_required
def admin_open_folder():
    try:
        if platform.system() == "Windows":
            os.startfile(str(APP_DIR))
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", str(APP_DIR)])
        else:
            subprocess.Popen(["xdg-open", str(APP_DIR)])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/admin/launch-browser", methods=["POST"])
@admin_required
def admin_launch_browser():
    data          = request.get_json(silent=True) or {}
    browser_path  = data.get("browser_path","default")
    incognito_flag= data.get("incognito_flag","--incognito")
    use_incognito = data.get("use_incognito", True)
    target_url    = data.get("url", f"http://localhost:{PORT}/login")

    try:
        if browser_path == "default":
            webbrowser.open(target_url)
        else:
            cmd = [browser_path]
            if use_incognito and incognito_flag:
                cmd.append(incognito_flag)
            cmd.append(target_url)
            subprocess.Popen(cmd)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/admin/save-custom-browser", methods=["POST"])
@admin_required
def admin_save_custom_browser():
    data = request.get_json(silent=True) or {}
    name = data.get("name","Custom Browser")
    path = data.get("path","").strip()
    flag = data.get("flag","--incognito")
    if not path:
        return jsonify({"ok": False, "error": "Path is required"})
    try:
        save_custom_browser(name, path, flag)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/admin/move-data", methods=["POST"])
@admin_required
def admin_move_data():
    data = request.get_json(silent=True) or {}
    dest_str = data.get("dest_path","").strip()
    if not dest_str:
        return jsonify({"ok": False, "error": "Destination path is required"})
    try:
        dest = Path(dest_str)
        dest.mkdir(parents=True, exist_ok=True)
        # Copy script / exe (works both frozen and .py)
        script_src = Path(sys.executable).resolve() if _FROZEN else Path(__file__).resolve()
        shutil.copy2(str(script_src), str(dest / script_src.name))
        # Copy database
        shutil.copy2(str(DB_PATH), str(dest / DB_PATH.name))
        # Copy SAML cache
        cache_dest = dest / SAML_TMP.name
        if SAML_TMP.exists():
            if cache_dest.exists():
                shutil.rmtree(str(cache_dest))
            shutil.copytree(str(SAML_TMP), str(cache_dest))
        return jsonify({
            "ok": True,
            "message": f"Copied to {dest}. Close this app and run saml_testbench.py from the new folder."
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/status")
def api_status():
    with get_db() as db:
        ec = db.execute("SELECT COUNT(*) FROM auth_log").fetchone()[0]
    return jsonify({
        "ok": True, "saml": SAML_OK,
        "active_idp": get_setting("active_idp"),
        "debug": is_debug(),
        "events": ec,
        "auth":  bool(session.get("auth_ok")),
        "admin": bool(get_admin_session().get("admin_user")),
    })

@app.route("/api/browsers")
@admin_required
def api_browsers():
    return jsonify(detect_browsers())

# ─────────────────────────────────────────────────────────────────────────────
# USER-FACING ROUTES
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def root():
    if session.get("auth_ok"):
        return redirect(url_for("app_page"))
    return redirect(url_for("user_login_page"))

@app.route("/login", methods=["GET","POST"])
def user_login_page():
    if session.get("auth_ok"):
        return redirect(url_for("app_page"))

    error = ""
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        u = get_user_by_username(username)

        if u and _check_pw(u["pw_hash"], password):
            session.permanent  = True
            session["auth_ok"]   = True
            session["username"]  = u["username"]
            session["user_role"] = u["role"]
            session["login_idp"] = "local"
            # Load custom attributes
            user_attrs = get_user_attrs(u["id"])
            session["attrs"] = {a["key"]: a["value"] for a in user_attrs}
            log_step("Local Auth","local_login","local",True,username=u["username"])
            log_step("Local Auth","local_login","local",True,
                     username=u["username"],level="debug",
                     detail={"method":"local","username":u["username"],
                             "email":u.get("email",""),"role":u["role"],"ip":request.remote_addr})
            return redirect(url_for("app_page"))

        error = "Invalid username or password."
        log_step("Local Auth","local_login_fail","local",False,username=username,error=error)

    all_idps = list_idps()
    saml_btns = ""
    for idp in all_idps:
        if idp.get("enabled") and idp.get("sso_url"):
            n = idp["name"]
            lbl = idp.get("label") or n.capitalize()
            icon = _idp_icon(n)
            cls = " duo" if n == "duo" else ""
            saml_btns += f'<a href="/saml/login?idp={n}" class="saml-btn{cls}">{icon} Continue with {lbl} SSO</a>'

    oidc_btns = ""
    for ocfg in list_oidc_configs():
        if ocfg.get("enabled"):
            n = ocfg["name"]
            lbl = ocfg.get("label") or n.capitalize()
            icon = _oidc_icon(n)
            cls = " duo" if n == "duo" else ""
            oidc_btns += f'<a href="/oidc/login?idp={n}" class="saml-btn{cls}">{icon} Continue with {lbl} OIDC</a>'

    if saml_btns:
        saml_btns = '<div class="login-sep">or sign in with</div>' + saml_btns
    if oidc_btns:
        oidc_btns = '<div class="login-sep">' + ('or also via' if saml_btns else 'or sign in with') + '</div>' + oidc_btns

    body = f"""
<div class="login-wrap"><div class="login-box">
  <div class="login-header">
    <div style="font-size:2.2rem;margin-bottom:.65rem;filter:drop-shadow(0 0 14px rgba(0,229,255,.45))">⬡</div>
    <h1>Welcome Back</h1><p>Sign in to access the application</p>
  </div>
  <div class="login-body">
    {'<div class="alert alert-danger">'+error+'</div>' if error else ''}
    {''.join(f'<div class="alert alert-{c}">{m}</div>' for c,m in get_flashed_messages(with_categories=True))}
    <form method="post">
      <div class="form-group"><label>Username</label>
        <input type="text" name="username" autofocus autocomplete="username" placeholder="Enter your username"></div>
      <div class="form-group"><label>Password</label>
        <input type="password" name="password" autocomplete="current-password" placeholder="Enter your password"></div>
      <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center">Sign In</button>
    </form>
    {saml_btns}
    {oidc_btns}
  </div>
  <div style="padding:.7rem 2rem;border-top:1px solid var(--border);
    font-size:.7rem;color:var(--muted);text-align:center">
    Admin? <a href="/admin" style="color:var(--accent)">Admin Panel →</a>
  </div>
</div></div>"""
    return _plain_page("Login", body)

@app.route("/app")
@login_required
def app_page():
    username = session.get("username","User")
    idp      = session.get("login_idp","local")
    # For SAML logins show the full assertion; for local logins fall back to custom attrs
    display_attrs = session.get("all_attrs") or session.get("attrs", {})

    attr_rows = ""
    if display_attrs:
        for k, v in display_attrs.items():
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            attr_rows += f"""<div class="welcome-info-row">
              <span class="welcome-info-label">{k}</span>
              <span class="welcome-info-value">{v}</span>
            </div>"""

    info_block = f"""<div class="welcome-info">
      <div class="welcome-info-row">
        <span class="welcome-info-label">Authenticated As</span>
        <span class="welcome-info-value">{username}</span>
      </div>
      <div class="welcome-info-row">
        <span class="welcome-info-label">Authentication Method</span>
        <span class="welcome-info-value">{idp.upper()}</span>
      </div>
      {attr_rows}
    </div>"""

    body = f"""
<div class="welcome-wrap">
  <div class="welcome-card">
    <span class="welcome-checkmark">✅</span>
    <div class="welcome-title">Welcome to the<br><span class="highlight">Successful Login Page</span></div>
    <div class="welcome-subtitle">You have successfully authenticated.</div>
    {info_block}
    <div class="welcome-actions">
      <a href="/logout" class="btn btn-danger">🚪 Sign Out</a>
    </div>
  </div>
</div>"""
    return _plain_page("Welcome", body)

@app.route("/logout")
def user_logout():
    idp      = session.get("login_idp","local")
    protocol = session.get("login_protocol","saml")
    user     = session.get("username")
    sid      = session.get("saml_flow_id") or session.get("oidc_flow_id")

    # OIDC logout
    if protocol == "oidc":
        oidc_cfg = get_oidc_config(idp)
        end_ep   = oidc_cfg.get("end_session_endpoint","")
        id_token = session.get("oidc_id_token","")
        log_step("Logout","oidc_logout",idp,True,username=user,session_id=sid)
        session.clear()
        if end_ep:
            from urllib.parse import urlencode
            params = {}
            if id_token: params["id_token_hint"] = id_token
            post_logout = oidc_cfg.get("logout_redirect_uri","") or url_for("user_login_page",_external=True)
            if post_logout: params["post_logout_redirect_uri"] = post_logout
            return redirect(end_ep + ("?" + urlencode(params) if params else ""))
        flash("You have been logged out.", "success")
        return redirect(url_for("user_login_page"))

    if idp in ("okta","duo") and SAML_OK and protocol != "oidc":
        try:
            auth    = init_saml(idp)
            slo_url = auth.logout(
                name_id=session.get("saml_nameid"),
                session_index=session.get("saml_session_idx"),
                name_id_format=session.get("saml_nameid_fmt"),
            )
            log_step("Logout (SLO)","saml_slo_sent",idp,True,username=user,session_id=sid)
            session.clear()
            return redirect(slo_url)
        except Exception as e:
            log_step("Logout (SLO)","saml_slo_fail",idp,False,username=user,error=str(e),session_id=sid)
    log_step("Logout","local_logout",idp,True,username=user,session_id=sid)
    session.clear()
    return redirect(url_for("user_login_page"))



# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — OIDC CONFIG
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/oidc", methods=["GET","POST"])
@admin_required
def admin_oidc():
    if request.method == "POST":
        action = request.form.get("_action","save")
        name   = request.form.get("oidc_name","okta")

        if action == "set_active":
            set_setting("active_oidc", name)
            flash(f"{get_oidc_config(name).get('label',name)} set as active OIDC IdP.", "success")
            return redirect(f"/admin/oidc?tab={name}")

        if action == "clone":
            src_cfg  = get_oidc_config(name)
            all_oidcs = list_oidc_configs()
            if len(all_oidcs) >= 8:
                flash("Maximum of 8 OIDC configurations reached. Delete one before cloning.", "danger")
                return redirect(f"/admin/oidc?tab={name}")
            base = re.sub(r"_clone\d*$", "", name)
            new_name = base + "_clone"
            ctr = 2
            while get_oidc_config(new_name):
                new_name = f"{base}_clone{ctr}"; ctr += 1
            new_lbl = (src_cfg.get("label") or name.capitalize()) + " (Clone)"
            save_oidc_config(new_name, {**{k:v for k,v in src_cfg.items()
                                           if k not in ("name","rowid")},
                                         "label": new_lbl, "enabled": False, "is_custom": True})
            for w in get_oidc_watched_attrs(name):
                with get_db() as db:
                    db.execute("INSERT OR IGNORE INTO oidc_watched_attrs VALUES (?,?,?,?,?)",
                               (new_name, w["attr_name"], w.get("description",""),
                                w.get("required",0), w.get("sort_order",99)))
                    db.commit()
            flash(f"Cloned '{src_cfg.get('label',name)}' to '{new_lbl}'.", "success")
            return redirect(f"/admin/oidc?tab={new_name}")

        if action == "delete_custom":
            lbl = get_oidc_config(name).get("label", name)
            delete_custom_oidc(name)
            flash(f"Custom OIDC provider '{lbl}' deleted.", "success")
            return redirect("/admin/oidc")

        if action == "add_custom":
            new_name = re.sub(r"[^a-z0-9_-]","", request.form.get("new_oidc_name","").lower().strip())[:30]
            if not new_name:
                flash("Provider internal name is required.", "danger")
                return redirect("/admin/oidc?tab=__new__")
            if get_oidc_config(new_name):
                flash(f"A provider named '{new_name}' already exists.", "danger")
                return redirect("/admin/oidc?tab=__new__")
            save_oidc_config(new_name, {
                "label":    request.form.get("new_oidc_label", new_name.capitalize()),
                "is_custom": True,
                "scopes":   "openid profile email",
                "redirect_uri": f"http://localhost:{PORT}/oidc/callback",
                "use_pkce": True,
            })
            _save_oidc_watched_from_form(new_name, request)
            # Seed required claims
            for i,(a,d,r) in enumerate([("sub","Subject",1),("email","Email",1)]):
                with get_db() as db:
                    db.execute("INSERT OR IGNORE INTO oidc_watched_attrs VALUES (?,?,?,?,?)",
                               (new_name,a,d,r,i))
                    db.commit()
            flash(f"Custom OIDC provider '{request.form.get('new_oidc_label',new_name)}' created.", "success")
            return redirect(f"/admin/oidc?tab={new_name}")

        # Default: save existing — auto-set enabled based on required fields
        oidc_client_id = request.form.get("client_id","").strip()
        oidc_auth_ep   = request.form.get("authorization_endpoint","").strip()
        oidc_tok_ep    = request.form.get("token_endpoint","").strip()
        oidc_missing_fields = []
        if not oidc_client_id: oidc_missing_fields.append("Client ID")
        if not oidc_auth_ep:   oidc_missing_fields.append("Authorization Endpoint")
        if not oidc_tok_ep:    oidc_missing_fields.append("Token Endpoint")
        oidc_auto_enabled = len(oidc_missing_fields) == 0
        save_oidc_config(name, {
            "discovery_url":            request.form.get("discovery_url","").strip(),
            "client_id":                oidc_client_id,
            "client_secret":            request.form.get("client_secret",""),
            "authorization_endpoint":   oidc_auth_ep,
            "token_endpoint":           oidc_tok_ep,
            "userinfo_endpoint":        request.form.get("userinfo_endpoint","").strip(),
            "jwks_uri":                 request.form.get("jwks_uri","").strip(),
            "issuer":                   request.form.get("issuer","").strip(),
            "scopes":                   request.form.get("scopes","openid profile email"),
            "redirect_uri":             request.form.get("redirect_uri", f"http://localhost:{PORT}/oidc/callback"),
            "use_pkce":                 request.form.get("use_pkce") == "1",
            "token_endpoint_auth_method": request.form.get("token_endpoint_auth_method","client_secret_post"),
            "extra_params":             request.form.get("extra_params","{}"),
            "response_type":            request.form.get("response_type","code"),
            "claims_source":            request.form.get("claims_source","both"),
            "end_session_endpoint":     request.form.get("end_session_endpoint","").strip(),
            "logout_redirect_uri":      request.form.get("logout_redirect_uri","").strip(),
            "enabled":                  oidc_auto_enabled,
        })
        if request.form.get("set_active"):
            set_setting("active_oidc", name)
        _save_oidc_watched_from_form(name, request)
        oidc_lbl_saved = get_oidc_config(name).get("label", name)
        if oidc_missing_fields:
            missing_list = ", ".join(oidc_missing_fields)
            flash(f"{oidc_lbl_saved} saved — but the following required fields are missing and this provider has been disabled until they are filled in: {missing_list}.", "warning")
        else:
            flash(f"{oidc_lbl_saved} OIDC configuration saved — all required fields are present. Provider has been enabled on the login page.", "success")
        return redirect(f"/admin/oidc?tab={name}")

    active_oidc = get_setting("active_oidc","duo")
    tab         = request.args.get("tab", active_oidc)
    oidcs       = list_oidc_configs()

    OIDC_MAX = 8
    tabs_html = ""
    for cfg in oidcs:
        n = cfg["name"]
        lbl = cfg.get("label") or n.capitalize()
        is_active = (active_oidc == n)
        sel = tab == n
        clr = "var(--accent)" if sel else "var(--muted)"
        bdr = "var(--accent)" if sel else "transparent"
        active_badge = ' <span class="p-active pill" style="font-size:.58rem">Active</span>' if is_active else ""
        tabs_html += f'<a href="?tab={n}" class="idp-tab" style="color:{clr};border-bottom-color:{bdr}">{_oidc_icon(n)} {lbl}{active_badge}</a>'
    if len(oidcs) < OIDC_MAX:
        tabs_html += f'<a href="?tab=__new__" class="idp-tab" style="color:{"var(--accent)" if tab=="__new__" else "var(--muted)"};border-bottom-color:{"var(--accent)" if tab=="__new__" else "transparent"}">&#xFF0B; Add Custom</a>'
    else:
        tabs_html += f'<span class="idp-tab" style="color:var(--muted);cursor:default" title="Maximum of {OIDC_MAX} OIDC IdPs reached">&#xFF0B; Add Custom ({len(oidcs)}/{OIDC_MAX})</span>'

    forms_html = "".join(_oidc_form_html(cfg["name"], cfg, active_oidc, tab) for cfg in oidcs)
    forms_html += _new_oidc_form_html(tab)

    body = f"""
<div class="page-hd"><h1>OIDC Configuration</h1>
  <p>Configure OpenID Connect Identity Providers for OAuth 2.0 / OIDC authentication flows.</p>
</div>
<div id="oidc-export-row" style="display:flex;gap:.6rem;margin-bottom:1.1rem;flex-wrap:wrap;align-items:center">
  <a href="/admin/oidc/export" class="btn btn-sm btn-secondary" download>&#11015; Export OIDC Configs</a>
  <label class="btn btn-sm btn-secondary" style="cursor:pointer;margin:0">
    &#11014; Import OIDC Configs
    <input type="file" accept=".json" style="display:none" onchange="importOidcConfig(this)">
  </label>
  {'<span class="pill p-ok" style="font-size:.65rem">requests ready</span>' if OIDC_OK else '<span class="pill p-err" style="font-size:.65rem">pip install requests PyJWT[cryptography]</span>'}
  {'<span class="pill p-ok" style="font-size:.65rem">JWT sig verification ready</span>' if _JWT_CRYPTO_OK else ('<span class="pill p-warn" style="font-size:.65rem">JWT sig verification off — pip install PyJWT[cryptography]</span>' if _JWT_OK else '<span class="pill p-err" style="font-size:.65rem">no JWT (pip install PyJWT[cryptography])</span>')}
</div>
<div id="oidc-tabs" style="display:flex;gap:0;margin-bottom:1.5rem;border-bottom:1px solid var(--border);flex-wrap:wrap">
  {tabs_html}
</div>
{forms_html}
<script>
// Floating save dirty-tracking for the currently visible OIDC tab
(function(){{
  function _oidcMarkDirty(formId){{
    var btn = document.getElementById('float-save-' + formId);
    if (btn) btn.classList.add('visible');
  }}
  window.markOidcDirty = _oidcMarkDirty;
  // Attach listeners once DOM is ready
  document.addEventListener('DOMContentLoaded', function(){{
    // attach to every OIDC form on the page
    document.querySelectorAll('[id^="oidc-form-"]').forEach(function(form){{
      var fid = form.id;
      form.querySelectorAll('input,select,textarea').forEach(function(el){{
        el.addEventListener('input',  function(){{ _oidcMarkDirty(fid); }});
        el.addEventListener('change', function(){{ _oidcMarkDirty(fid); }});
      }});
    }});
  }});
}})();
function importOidcConfig(input){{
  var file=input.files[0]; if(!file)return;
  var reader=new FileReader();
  reader.onload=function(e){{
    try{{
      var payload=JSON.parse(e.target.result);
      fetch('/admin/oidc/import',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(payload)}})
        .then(r=>r.json()).then(d=>{{
          if(d.ok){{ alert('Imported '+d.imported+' provider(s).'+(d.skipped?' ('+d.skipped+' skipped)':'')); location.reload(); }}
          else alert('Import error: '+(d.error||'unknown'));
        }});
    }}catch(ex){{alert('Invalid JSON: '+ex);}}
  }};
  reader.readAsText(file);
}}
function discoverOidc(name){{
  var url=document.getElementById('discovery_url_'+name).value.trim();
  if(!url){{alert('Enter a Discovery URL first.');return;}}
  var btn=document.getElementById('discover_btn_'+name);
  btn.disabled=true; btn.textContent='Fetching…';
  fetch('/admin/oidc/discover',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{url:url}})}})
    .then(r=>r.json()).then(d=>{{
      btn.disabled=false; btn.textContent='&#x1F50D; Discover';
      if(d.error){{alert('Discovery error: '+d.error);return;}}
      var fields={{'authorization_endpoint':'authorization_endpoint','token_endpoint':'token_endpoint',
                  'userinfo_endpoint':'userinfo_endpoint','jwks_uri':'jwks_uri','issuer':'issuer',
                  'end_session_endpoint':'end_session_endpoint'}};
      for(var f in fields){{
        var el=document.getElementById(f+'_'+name);
        if(el && d[f]) el.value=d[f];
      }}
    }}).catch(e=>{{btn.disabled=false;btn.textContent='&#x1F50D; Discover';alert('Error: '+e);}});
}}
function addOidcWatchedRow(name){{
  var max=16;
  for(var i=0;i<max;i++){{
    var row=document.getElementById('owattr-row-'+name+'-'+i);
    if(row && row.style.display==='none'){{row.style.display='';return;}}
  }}
}}
function removeOidcWatchedRow(name,idx){{
  var row=document.getElementById('owattr-row-'+name+'-'+idx);
  if(row){{row.querySelectorAll('input').forEach(function(inp){{inp.value='';}});row.style.display='none';}}
}}
</script>"""

    tutorial = [
      {"sel": None,
       "title": "OIDC IdP Configuration",
       "body": "This page configures OpenID Connect identity providers — up to 8 total. OIDC is a modern alternative to SAML: it uses OAuth 2.0 Authorization Code Flow, exchanges a short-lived code for a signed JWT (ID token), and extracts user identity from standard claims. Use Clone to duplicate a config for staging vs. production, or to test different scopes."},
      {"sel": "#oidc-export-row",
       "title": "Status & Backup",
       "body": "The green pills confirm that <code>requests</code> (for HTTP) and <code>PyJWT</code> (for token signature validation) are installed. Export saves your OIDC configs as JSON (client secrets are excluded). Import restores them on a new machine."},
      {"sel": "#oidc-tabs",
       "title": "Provider Tabs",
       "body": "Each tab is one OIDC provider. The <em>Active</em> badge shows which is used by default. Add custom providers (Google, Azure AD, GitHub, Keycloak, etc.) with the + button."},
      {"sel": ".oidc-discovery-section",
       "title": "Auto-Discovery",
       "body": "Paste the provider's <code>.well-known/openid-configuration</code> URL and click <strong>Discover</strong>. This fills in all endpoints and the issuer automatically. For Okta: <code>https://your-org.okta.com/.well-known/openid-configuration</code>. For Duo: <code>https://sso-XXXX.sso.duosecurity.com/oidc/XXXX/.well-known/openid-configuration</code>."},
      {"sel": ".oidc-client-section",
       "title": "Client Credentials",
       "body": "Enter the <strong>Client ID</strong> and <strong>Client Secret</strong> from your IdP's application settings. Scopes control what claims are included in the token — <code>openid profile email</code> covers the standard set. For Okta groups, add <code>groups</code>."},
      {"sel": ".oidc-advanced-section",
       "title": "Advanced Settings",
       "body": "<strong>PKCE</strong> (enabled by default) adds a code challenge for extra security — required by some providers. <strong>Auth Method</strong> controls how the client secret is sent to the token endpoint. <strong>Extra Params</strong> is a JSON dict of additional URL params to add to the auth request (e.g. <code>{\"prompt\":\"login\"}</code> to force re-authentication)."},
      {"sel": ".oidc-watched-section",
       "title": "Watched Claims",
       "body": "<code>sub</code> and <code>email</code> are always captured. Add any other claims your provider includes (e.g. <code>groups</code>, <code>department</code>, <code>preferred_username</code>) — they'll appear on the success page and in debug logs."},
    ]
    return _admin_page("OIDC Config","oidc",body,tutorial)


def _oidc_icon(name):
    return "🔵" if name=="okta" else "🟣" if name=="duo" else "🔷"

def _save_oidc_watched_from_form(oidc_name: str, req):
    names = req.form.getlist("watched_attr_name")
    descs = req.form.getlist("watched_attr_desc")
    attrs = [{"attr_name":n,"description":d} for n,d in zip(names,descs) if n.strip()]
    save_oidc_watched_attrs(oidc_name, attrs[:16])

def _oidc_form_html(name, cfg, active_oidc, tab):
    display = "" if tab == name else "display:none"
    is_active = (active_oidc == name)
    is_custom = bool(cfg.get("is_custom"))
    lbl = cfg.get("label") or name.capitalize()
    configured = bool(cfg.get("client_id") and cfg.get("token_endpoint"))
    icon = _oidc_icon(name)

    watched = get_oidc_watched_attrs(name)
    custom_watched = [w for w in watched if not w.get("required")]
    required_watched = [w for w in watched if w.get("required")]

    watched_rows = ""
    for i in range(16):
        a = custom_watched[i] if i < len(custom_watched) else {}
        hide = "" if i < len(custom_watched) else ('style="display:none"' if i > 0 else "")
        watched_rows += f"""<div class="attr-row" id="owattr-row-{name}-{i}" {hide}>
          <input type="text" name="watched_attr_name" value="{a.get('attr_name','')}"
            placeholder="Claim name (e.g. groups)" style="font-size:.78rem">
          <input type="text" name="watched_attr_desc" value="{a.get('description','')}"
            placeholder="Description (optional)" style="font-size:.78rem">
          <button type="button" class="btn btn-sm btn-danger"
            onclick="removeOidcWatchedRow('{name}',{i})">&#x2715;</button>
        </div>"""

    req_claims_html = "".join(
        f'<div style="background:rgba(0,229,255,.04);border:1px solid rgba(0,229,255,.15);'
        f'border-radius:8px;padding:.5rem .9rem;margin-bottom:.4rem;font-family:var(--fm);'
        f'font-size:.75rem;display:flex;align-items:center;gap:.6rem">'
        f'<span class="pill p-ok" style="font-size:.6rem">Required</span>'
        f'<span style="color:var(--accent)">{w["attr_name"]}</span>'
        f'<span style="color:var(--muted)">— {w.get("description","")}</span></div>'
        for w in required_watched
    )

    delete_btn = ""
    if is_custom:
        delete_btn = f"""
    <form method="post" style="display:inline;margin-left:.5rem"
      onsubmit="return confirm('Delete OIDC provider {lbl}?')">
      <input type="hidden" name="oidc_name" value="{name}">
      <input type="hidden" name="_action" value="delete_custom">
      <button type="submit" class="btn btn-sm btn-danger">&#x1F5D1; Delete</button>
    </form>"""

    extra_params_pretty = ""
    try:
        ep = json.loads(cfg.get("extra_params") or "{}")
        extra_params_pretty = json.dumps(ep, indent=2) if ep else "{}"
    except Exception:
        extra_params_pretty = cfg.get("extra_params","{}") or "{}"

    # Required field check for OIDC
    oidc_missing = []
    if not cfg.get("client_id"):               oidc_missing.append("Client ID")
    if not cfg.get("authorization_endpoint"):  oidc_missing.append("Authorization Endpoint")
    if not cfg.get("token_endpoint"):          oidc_missing.append("Token Endpoint")
    oidc_all_filled = not oidc_missing
    enabled_val = bool(cfg.get("enabled")) if cfg.get("client_id") else False
    if oidc_all_filled and not cfg.get("client_secret") == "" and cfg.get("client_id"):
        enabled_val = bool(cfg.get("enabled"))

    oidc_missing_banner = ""
    if oidc_missing:
        oidc_items = "".join(f"<li><strong>{m}</strong></li>" for m in oidc_missing)
        oidc_missing_banner = (f'<div class="alert alert-warning" style="margin-bottom:1rem">' +
            f'<strong>&#x26A0; Configuration Incomplete</strong> — The following required fields are missing.' +
            f'They are highlighted in red below.<ul style="margin:.5rem 0 0 1.2rem;padding:0">{oidc_items}</ul></div>')

    def _oreq(val):
        return ' style="border-color:var(--danger);box-shadow:0 0 0 2px rgba(239,68,68,.18)"' if not val else ""

    oidc_delete_inline = ""
    if is_custom:
        oidc_delete_inline = (f'<form method="post" style="display:inline-flex"'
            f' onsubmit="return confirm(\'Delete OIDC provider {lbl}?\');">'
            f'<input type="hidden" name="oidc_name" value="{name}">'
            f'<input type="hidden" name="_action" value="delete_custom">'
            f'<button type="submit" class="btn btn-sm btn-danger" style="flex-shrink:0">&#x1F5D1; Delete</button>'
            f'</form>')

    return f"""
<div id="otab-{name}" style="{display}">
  <form method="post" id="oidc-form-{name}" onchange="markOidcDirty('oidc-form-{name}')">
    <input type="hidden" name="oidc_name" value="{{name}}">
    {{oidc_missing_banner}}

    <!-- ── "Register these in your IdP" pinned top bar ── -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;margin-bottom:1rem;
      background:rgba(0,229,255,.04);border:1.5px solid rgba(0,229,255,.22);
      border-radius:10px;padding:.9rem 1.1rem">
      <div>
        <div style="font-size:.62rem;font-weight:700;text-transform:uppercase;
          letter-spacing:.09em;color:var(--accent);margin-bottom:.5rem">
          &#x1F4CB; Register these in {{lbl}}
        </div>
        <div style="display:flex;flex-direction:column;gap:.35rem">
          <div class="qs-row">
            <div class="qs-label" style="min-width:160px">Redirect URI (Callback)</div>
            <div class="qs-val" id="top-oidc-cb-{{name}}">http://localhost:{{PORT}}/oidc/callback</div>
            <button type="button" class="btn btn-sm btn-outline qs-copy"
              onclick="qsCopy('top-oidc-cb-{{name}}',this)" title="Copy">&#x2398;</button>
          </div>
          <div style="font-size:.7rem;color:var(--muted);margin-top:.1rem">
            App type: <strong style="color:var(--text)">Web</strong> &nbsp;·&nbsp;
            Grant: <strong style="color:var(--text)">Authorization Code</strong>
          </div>
        </div>
      </div>
      <div>
        <div style="font-size:.62rem;font-weight:700;text-transform:uppercase;
          letter-spacing:.09em;color:var(--muted);margin-bottom:.5rem">
          &#x1F4E5; Required from {{lbl}}
        </div>
        <div style="display:flex;flex-direction:column;gap:.3rem;font-size:.75rem">
          <div style="display:flex;align-items:center;gap:.55rem;padding:.3rem .5rem;
            border-radius:6px;background:{{"rgba(34,197,94,.06)" if cfg.get("client_id") else "rgba(239,68,68,.07)"}}">
            <span style="font-size:.85rem">{{"&#x2713;" if cfg.get("client_id") else "&#x25CB;"}}</span>
            <span style="color:{{"var(--success)" if cfg.get("client_id") else "var(--danger)"}}">Client ID</span>
            {{'<span class="pill p-ok" style="font-size:.6rem;margin-left:auto">Set</span>' if cfg.get("client_id") else '<span class="pill p-err" style="font-size:.6rem;margin-left:auto">Missing</span>'}}
          </div>
          <div style="display:flex;align-items:center;gap:.55rem;padding:.3rem .5rem;
            border-radius:6px;background:{{"rgba(34,197,94,.06)" if cfg.get("client_secret") else "rgba(245,158,11,.07)"}}">
            <span style="font-size:.85rem">{{"&#x2713;" if cfg.get("client_secret") else "&#x25CB;"}}</span>
            <span style="color:{{"var(--success)" if cfg.get("client_secret") else "var(--warning)"}}">Client Secret</span>
            {{'<span class="pill p-ok" style="font-size:.6rem;margin-left:auto">Set</span>' if cfg.get("client_secret") else '<span class="pill p-warn" style="font-size:.6rem;margin-left:auto">Optional</span>'}}
          </div>
          <div style="display:flex;align-items:center;gap:.55rem;padding:.3rem .5rem;
            border-radius:6px;background:{{"rgba(34,197,94,.06)" if (cfg.get("authorization_endpoint") or cfg.get("discovery_url")) else "rgba(239,68,68,.07)"}}">
            <span style="font-size:.85rem">{{"&#x2713;" if (cfg.get("authorization_endpoint") or cfg.get("discovery_url")) else "&#x25CB;"}}</span>
            <span style="color:{{"var(--success)" if (cfg.get("authorization_endpoint") or cfg.get("discovery_url")) else "var(--danger)"}}">Discovery URL <em>or</em> Endpoints</span>
            {{'<span class="pill p-ok" style="font-size:.6rem;margin-left:auto">Set</span>' if (cfg.get("authorization_endpoint") or cfg.get("discovery_url")) else '<span class="pill p-err" style="font-size:.6rem;margin-left:auto">Missing</span>'}}
          </div>
          <div style="display:flex;align-items:center;gap:.55rem;padding:.3rem .5rem;
            border-radius:6px;background:rgba(245,158,11,.05);color:var(--muted)">
            <span>&#x25CB;</span><span>Token Endpoint (auto from Discovery)</span>
          </div>
        </div>
      </div>
    </div>

    <div class="cfg-form-hd">
      <div class="cfg-form-hd-left">
        <span style="font-size:1.4rem">{icon}</span>
        <div>
          <div class="cfg-heading">{lbl} OIDC Configuration</div>
          <div class="cfg-subhead">{'Authorization Code Flow — ready' if oidc_all_filled else f'{len(oidc_missing)} required field(s) missing'}</div>
        </div>
      </div>
      <div class="cfg-form-hd-right">
        <div class="toggle-row" style="margin:0;padding:.45rem .75rem">
          <div class="toggle-info">
            <strong class="body-text">Show on Login Page</strong>
            <small class="hint-text">{'Ready to enable' if oidc_all_filled else 'Fill required fields first'}</small>
          </div>
          <label class="switch" style="margin-left:.75rem">
            <input type="checkbox" name="enabled" value="1" {'checked' if enabled_val else ''}
              onchange="ajaxToggleOidc('{name}', this.checked, this)">
            <span class="slider"></span>
          </label>
        </div>
        {'<span class="pill p-active">&#x25CF; Active OIDC</span>' if is_active else
         '<button type="submit" name="set_active" value="1" class="btn btn-sm btn-secondary">Set as Active</button>'}
        <button type="submit" name="_action" value="clone" class="btn btn-sm btn-secondary" title="Duplicate this configuration">&#x2398; Clone</button>
        {oidc_delete_inline}
        <button type="submit" class="btn btn-primary">&#x1F4BE; Save Configuration</button>
      </div>
    </div>

    <!-- OIDC Quick Setup reference card -->
    <div class="card" style="margin-bottom:1rem;border-color:rgba(0,229,255,.25);background:rgba(0,229,255,.02)">
      <div class="card-hd" style="border-color:rgba(0,229,255,.2)">
        <span class="card-title" style="color:var(--accent)">&#x26A1; Quick Setup Reference</span>
        <span class="pill p-info" style="font-size:.62rem">What goes where</span>
      </div>
      <div class="card-body" style="display:grid;grid-template-columns:1fr 1fr;gap:1.25rem">
        <!-- LEFT: register in IdP -->
        <div>
          <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
            color:var(--muted);margin-bottom:.65rem">Register these in {lbl}</div>
          <div style="display:flex;flex-direction:column;gap:.5rem">
            <div class="qs-row">
              <div class="qs-label">Redirect URI (Callback URL)</div>
              <div class="qs-val" id="qs-oidc-cb-{name}">http://localhost:{PORT}/oidc/callback</div>
              <button type="button" class="btn btn-sm btn-outline qs-copy"
                onclick="qsCopy('qs-oidc-cb-{name}',this)" title="Copy">&#x2398;</button>
            </div>
            <div class="qs-row">
              <div class="qs-label">Sign-in Redirect URI <span class="muted">(Okta term)</span></div>
              <div class="qs-val" id="qs-oidc-cb2-{name}">http://localhost:{PORT}/oidc/callback</div>
              <button type="button" class="btn btn-sm btn-outline qs-copy"
                onclick="qsCopy('qs-oidc-cb2-{name}',this)" title="Copy">&#x2398;</button>
            </div>
            <div style="font-size:.7rem;color:var(--muted);margin-top:.25rem">
              App type: <strong style="color:var(--text)">Web application</strong> &nbsp;·&nbsp;
              Grant type: <strong style="color:var(--text)">Authorization Code</strong>
            </div>
          </div>
        </div>
        <!-- RIGHT: what you need from IdP -->
        <div>
          <div style="font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
            color:var(--muted);margin-bottom:.65rem">What you need from {lbl}</div>
          <div style="display:flex;flex-direction:column;gap:.45rem">
            <div class="qs-need {'qs-ok' if cfg.get('client_id') else 'qs-miss'}">
              <span class="qs-dot">{'&#x2713;' if cfg.get('client_id') else '&#x25CB;'}</span>
              <span class="qs-field">Client ID</span>
              {'<span class="qs-pill">Set</span>' if cfg.get('client_id') else '<span class="qs-pill qs-pill-miss">Missing</span>'}
            </div>
            <div class="qs-need {'qs-ok' if cfg.get('client_secret') else 'qs-miss'}">
              <span class="qs-dot">{'&#x2713;' if cfg.get('client_secret') else '&#x25CB;'}</span>
              <span class="qs-field">Client Secret</span>
              {'<span class="qs-pill">Set</span>' if cfg.get('client_secret') else '<span class="qs-pill qs-pill-miss">Missing</span>'}
            </div>
            <div class="qs-need {'qs-ok' if (cfg.get('authorization_endpoint') or cfg.get('discovery_url')) else 'qs-miss'}">
              <span class="qs-dot">{'&#x2713;' if (cfg.get('authorization_endpoint') or cfg.get('discovery_url')) else '&#x25CB;'}</span>
              <span class="qs-field">Discovery URL <em>or</em> Endpoints</span>
              {'<span class="qs-pill">Set</span>' if (cfg.get('authorization_endpoint') or cfg.get('discovery_url')) else '<span class="qs-pill qs-pill-miss">Missing</span>'}
            </div>
            <div class="qs-need qs-opt">
              <span class="qs-dot" style="color:var(--accent)">&#x2605;</span>
              <span class="qs-field">Use <strong>Discover</strong> button above to auto-fill all endpoints</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Discovery -->
    <div class="card oidc-discovery-section" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Auto-Discovery</span>
        <span class="pill p-info">Fills in all endpoints automatically</span>
      </div>
      <div class="card-body">
        <div class="form-group" style="margin-bottom:.5rem">
          <label>OpenID Connect Discovery URL</label>
          <div style="display:flex;gap:.5rem">
            <input type="text" id="discovery_url_{name}" name="discovery_url"
              value="{cfg.get('discovery_url','')}"
              placeholder="https://your-org.{name}.com/.well-known/openid-configuration"
              style="flex:1">
            <button type="button" id="discover_btn_{name}" class="btn btn-secondary"
              onclick="discoverOidc('{name}')">&#x1F50D; Discover</button>
          </div>
          <div class="form-hint">
            Okta: <code>https://&#x7B;domain&#x7D;/.well-known/openid-configuration</code> &nbsp;|&nbsp;
            Duo: <code>https://sso-&#x7B;XXXX&#x7D;.sso.duosecurity.com/oidc/&#x7B;XXXX&#x7D;/.well-known/openid-configuration</code>
          </div>
        </div>
      </div>
    </div>

    <!-- Client credentials -->
    <div class="card oidc-client-section" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Client Credentials &amp; Scopes</span></div>
      <div class="card-body">
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>Client ID {'<span style="color:var(--danger)">*</span>' if not cfg.get('client_id') else ""}</label>
            <input type="text" name="client_id" value="{cfg.get('client_id','')}"{_oreq(cfg.get('client_id'))}
              placeholder="0oa2abcdef12345678" autocomplete="off">
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Client Secret</label>
            <input type="password" name="client_secret" value="{cfg.get('client_secret','')}"
              placeholder="&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;&#x2022;" autocomplete="new-password">
            <div class="form-hint">Stored locally. Not included in config exports.</div>
          </div>
        </div>
        <div class="form-group" style="margin-top:1rem">
          <label>Scopes (space-separated)</label>
          <input type="text" name="scopes" value="{cfg.get('scopes','openid profile email')}"
            placeholder="openid profile email groups">
          <div class="form-hint">
            Always include <code>openid</code>. Add <code>groups</code> for Okta group claims,
            <code>offline_access</code> for refresh tokens.
          </div>
        </div>
        <div class="form-row" style="margin-top:.75rem">
          <div class="form-group" style="margin-bottom:0">
            <label>Redirect URI (Callback)</label>
            <input type="text" name="redirect_uri"
              value="{cfg.get('redirect_uri', f'http://localhost:{PORT}/oidc/callback')}">
            <div class="form-hint">Register this exact URL in your IdP application settings.</div>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Claims Source</label>
            <select name="claims_source">
              <option value="both" {'selected' if cfg.get('claims_source','both')=='both' else ''}>ID token + Userinfo (both)</option>
              <option value="id_token" {'selected' if cfg.get('claims_source')=='id_token' else ''}>ID token only</option>
              <option value="userinfo" {'selected' if cfg.get('claims_source')=='userinfo' else ''}>Userinfo endpoint only</option>
            </select>
          </div>
        </div>
      </div>
    </div>

    <!-- Endpoints (auto-filled by discovery or manual) -->
    <div class="card oidc-endpoints-section" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Endpoints</span>
        <span class="pill p-gray" style="font-size:.62rem">Auto-filled by Discovery or enter manually</span>
      </div>
      <div class="card-body">
        <div class="form-group">
          <label>Issuer</label>
          <input type="text" id="issuer_{name}" name="issuer" value="{cfg.get('issuer','')}"
            placeholder="https://your-org.{name}.com">
        </div>
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>Authorization Endpoint {'<span style="color:var(--danger)">*</span>' if not cfg.get('authorization_endpoint') else ""}</label>
            <input type="text" id="authorization_endpoint_{name}" name="authorization_endpoint"
              value="{cfg.get('authorization_endpoint','')}"{_oreq(cfg.get('authorization_endpoint'))}
              placeholder="https://…/oauth2/v1/authorize">
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Token Endpoint {'<span style="color:var(--danger)">*</span>' if not cfg.get('token_endpoint') else ""}</label>
            <input type="text" id="token_endpoint_{name}" name="token_endpoint"
              value="{cfg.get('token_endpoint','')}"{_oreq(cfg.get('token_endpoint'))}
              placeholder="https://…/oauth2/v1/token">
          </div>
        </div>
        <div class="form-row" style="margin-top:.75rem">
          <div class="form-group" style="margin-bottom:0">
            <label>Userinfo Endpoint</label>
            <input type="text" id="userinfo_endpoint_{name}" name="userinfo_endpoint"
              value="{cfg.get('userinfo_endpoint','')}"
              placeholder="https://…/oauth2/v1/userinfo">
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>JWKS URI</label>
            <input type="text" id="jwks_uri_{name}" name="jwks_uri"
              value="{cfg.get('jwks_uri','')}"
              placeholder="https://…/oauth2/v1/keys">
          </div>
        </div>
        <div class="form-row" style="margin-top:.75rem">
          <div class="form-group" style="margin-bottom:0">
            <label>End-Session Endpoint <span class="muted">(optional)</span></label>
            <input type="text" id="end_session_endpoint_{name}" name="end_session_endpoint"
              value="{cfg.get('end_session_endpoint','')}"
              placeholder="https://…/oauth2/v1/logout">
            <div class="form-hint">Used for IdP logout redirect after local session clear</div>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Post-Logout Redirect URI <span class="muted">(optional)</span></label>
            <input type="text" name="logout_redirect_uri"
              value="{cfg.get('logout_redirect_uri','')}"
              placeholder="http://localhost:{PORT}/login">
          </div>
        </div>
      </div>
    </div>

    <!-- Advanced -->
    <div class="card oidc-advanced-section" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Advanced Settings</span></div>
      <div class="card-body">
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>Token Endpoint Auth Method</label>
            <select name="token_endpoint_auth_method">
              <option value="client_secret_post" {'selected' if cfg.get('token_endpoint_auth_method','client_secret_post')=='client_secret_post' else ''}>client_secret_post (default)</option>
              <option value="client_secret_basic" {'selected' if cfg.get('token_endpoint_auth_method')=='client_secret_basic' else ''}>client_secret_basic (HTTP Basic Auth)</option>
              <option value="none" {'selected' if cfg.get('token_endpoint_auth_method')=='none' else ''}>none (PKCE-only, public client)</option>
            </select>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Response Type</label>
            <select name="response_type">
              <option value="code" {'selected' if cfg.get('response_type','code')=='code' else ''}>code (Authorization Code Flow)</option>
              <option value="code token" {'selected' if cfg.get('response_type')=='code token' else ''}>code token (Hybrid)</option>
            </select>
          </div>
        </div>
        <div class="toggle-row" style="margin-top:1rem">
          <div class="toggle-info">
            <strong>Use PKCE</strong>
            <small>Proof Key for Code Exchange — required by some providers, always recommended. Uses SHA-256 code challenge.</small>
          </div>
          <label class="switch">
            <input type="checkbox" name="use_pkce" value="1" {'checked' if cfg.get('use_pkce',1) else ''}>
            <span class="slider"></span>
          </label>
        </div>
        <div class="form-group" style="margin-top:1rem">
          <label>Extra Authorization Parameters <span class="muted">(JSON)</span></label>
          <textarea name="extra_params" style="min-height:80px;font-family:var(--fm);font-size:.75rem"
            placeholder='{{"prompt":"login","hd":"company.com"}}'>{extra_params_pretty}</textarea>
          <div class="form-hint">
            Added to the authorization URL. Examples: <code>{{"prompt":"login"}}</code> to force re-auth,
            <code>{{"hd":"company.com"}}</code> for Google Workspace domain hint,
            <code>{{"acr_values":"..."}}</code> for Duo step-up auth.
          </div>
        </div>
      </div>
    </div>

    <!-- Watched claims -->
    <div class="card oidc-watched-section" style="margin-bottom:1rem">
      <div class="card-hd">
        <span class="card-title">Watched Claims</span>
        <span class="pill p-gray" style="font-size:.62rem">Up to 16 custom + required claims</span>
      </div>
      <div class="card-body">
        <p class="hint-text" style=";margin-bottom:.85rem">
          Claims extracted from the ID token and/or userinfo response.
          Required claims are always captured. Add extras based on what your provider includes.</p>
        {req_claims_html}
        <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:.5rem;margin-bottom:.5rem;margin-top:.75rem">
          <span class="muted" style="font-size:.63rem;font-family:var(--fm)">Claim Name</span>
          <span class="muted" style="font-size:.63rem;font-family:var(--fm)">Description (optional)</span>
          <span></span>
        </div>
        <div id="oidc-watched-{name}">
          {watched_rows}
        </div>
        <button type="button" class="btn btn-sm btn-secondary" style="margin-top:.5rem"
          onclick="addOidcWatchedRow('{name}')">&#xFF0B; Add Claim</button>
      </div>
    </div>

    <button type="submit" id="float-save-oidc-form-{name}" class="float-save" title="Unsaved changes">
      &#x1F4BE; Save Changes
    </button>
  </form>
</div>"""


def _new_oidc_form_html(tab):
    display = "" if tab == "__new__" else "display:none"
    return f"""
<div id="otab-__new__" style="{display}">
  <form method="post">
    <input type="hidden" name="_action" value="add_custom">
    <div class="cfg-form-hd">
      <div class="cfg-form-hd-left">
        <span style="font-size:1.4rem">🔷</span>
        <div>
          <div class="cfg-heading">Add Custom OIDC Provider</div>
          <div class="cfg-subhead">Google, Azure AD, GitHub, Keycloak, Auth0, PingFederate…</div>
        </div>
      </div>
      <div class="cfg-form-hd-right">
        <button type="submit" class="btn btn-primary">Create Provider</button>
      </div>
    </div>
    <div class="card" style="margin-bottom:1rem">
      <div class="card-hd"><span class="card-title">Provider Identity</span></div>
      <div class="card-body">
        <div class="form-row">
          <div class="form-group" style="margin-bottom:0">
            <label>Internal Name <span class="muted">(lowercase, no spaces)</span></label>
            <input type="text" name="new_oidc_name" placeholder="google" pattern="[a-z0-9_-]+"
              style="font-family:var(--fm)" required>
            <div class="form-hint">Used in URLs: /oidc/login?idp=google</div>
          </div>
          <div class="form-group" style="margin-bottom:0">
            <label>Display Label</label>
            <input type="text" name="new_oidc_label" placeholder="Google">
          </div>
        </div>
        <p class="hint-text" style="margin-top:.75rem">
          After creating, open its tab to configure client credentials, discovery URL, and settings.
        </p>
      </div>
    </div>
  </form>
</div>"""


@app.route("/admin/oidc/discover", methods=["POST"])
@admin_required
def admin_oidc_discover():
    data = request.get_json(silent=True) or {}
    url  = data.get("url","").strip()
    if not url:
        return jsonify({"error":"No URL provided"})
    doc, err = oidc_fetch_discovery(url)
    if err:
        return jsonify({"error": err})
    return jsonify(doc)

@app.route("/admin/oidc/export")
@admin_required
def admin_oidc_export():
    payload = export_oidc_config()
    resp    = make_response(json.dumps(payload, indent=2))
    resp.headers["Content-Type"]        = "application/json"
    resp.headers["Content-Disposition"] = 'attachment; filename="oidc_config_export.json"'
    return resp

@app.route("/admin/oidc/import", methods=["POST"])
@admin_required
def admin_oidc_import():
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"ok":False,"error":"No JSON payload"})
    imported, skipped, err = import_oidc_config(payload)
    if err:
        return jsonify({"ok":False,"error":err})
    return jsonify({"ok":True,"imported":imported,"skipped":skipped})



# ─────────────────────────────────────────────────────────────────────────────
# BOOKMARKS — stored as JSON array in settings table
# ─────────────────────────────────────────────────────────────────────────────
def _get_bookmarks():
    import json as _j
    raw = get_setting("bookmarks","[]")
    try:
        bms = _j.loads(raw)
        return bms if isinstance(bms, list) else []
    except Exception:
        return []

def _save_bookmarks(bms):
    import json as _j
    set_setting("bookmarks", _j.dumps(bms[:40]))

@app.route("/admin/bookmarks", methods=["GET"])
@admin_required
def admin_bookmarks_list():
    return jsonify({"ok": True, "bookmarks": _get_bookmarks()})

@app.route("/admin/bookmarks/add", methods=["POST"])
@admin_required
def admin_bookmarks_add():
    import json as _j
    data  = request.get_json(silent=True) or {}
    label = (data.get("label") or "").strip()[:80]
    url   = (data.get("url")   or "").strip()[:500]
    if not url:
        return jsonify({"ok": False, "error": "URL is required"})
    if not label:
        label = url[:60]
    bms = _get_bookmarks()
    bms.append({"label": label, "url": url})
    _save_bookmarks(bms)
    return jsonify({"ok": True, "bookmarks": bms})

@app.route("/admin/bookmarks/delete", methods=["POST"])
@admin_required
def admin_bookmarks_delete():
    data = request.get_json(silent=True) or {}
    idx  = data.get("index", -1)
    bms  = _get_bookmarks()
    if 0 <= idx < len(bms):
        bms.pop(idx)
        _save_bookmarks(bms)
    return jsonify({"ok": True, "bookmarks": bms})


# ─────────────────────────────────────────────────────────────────────────────
# AJAX TOGGLE ROUTES — save enabled state without full form submit
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/idp/toggle", methods=["POST"])
@admin_required
def admin_idp_toggle():
    data = request.get_json(silent=True) or {}
    name    = data.get("name","")
    enabled = bool(data.get("enabled"))
    cfg = get_idp(name)
    if not cfg:
        return jsonify({"ok":False,"error":f"IdP '{name}' not found"})
    save_idp(name, {**cfg, "enabled": enabled})
    return jsonify({"ok":True,"name":name,"enabled":enabled})

@app.route("/admin/oidc/toggle", methods=["POST"])
@admin_required
def admin_oidc_toggle():
    data = request.get_json(silent=True) or {}
    name    = data.get("name","")
    enabled = bool(data.get("enabled"))
    cfg = get_oidc_config(name)
    if not cfg:
        return jsonify({"ok":False,"error":f"OIDC provider '{name}' not found"})
    save_oidc_config(name, {**{k:v for k,v in cfg.items() if k != "rowid"},
                             "enabled": enabled})
    return jsonify({"ok":True,"name":name,"enabled":enabled})

# ─────────────────────────────────────────────────────────────────────────────
# OIDC USER-FACING ROUTES
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/oidc/login")
def oidc_login():
    name = request.args.get("idp", get_setting("active_oidc","duo"))
    cfg  = get_oidc_config(name)
    sid  = str(uuid.uuid4())[:8]
    session["oidc_flow_id"] = sid

    if not OIDC_OK:
        flash("OIDC requires: pip install requests PyJWT[cryptography]", "danger")
        return redirect(url_for("user_login_page"))
    if not cfg.get("client_id") or not cfg.get("authorization_endpoint"):
        flash(f"OIDC provider '{name}' is not fully configured. Set it up in Admin → OIDC Config.", "danger")
        return redirect(url_for("user_login_page"))

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    session["oidc_state"]   = state
    session["oidc_nonce"]   = nonce
    session["oidc_idp"]     = name

    log_step("OIDC Step 1 — Login Initiated","oidc_init",name,True,session_id=sid)
    log_step("OIDC Step 1 — Login Initiated","oidc_init",name,True,session_id=sid,level="debug",
             detail={"idp":name,"client_id":cfg.get("client_id",""),
                     "scopes":cfg.get("scopes",""),
                     "pkce":bool(cfg.get("use_pkce",1)),
                     "user_agent":request.headers.get("User-Agent","")})

    code_challenge = None
    if cfg.get("use_pkce",1):
        verifier, code_challenge = oidc_pkce_pair()
        session["oidc_pkce_verifier"] = verifier

    auth_url = oidc_build_auth_url(cfg, state, nonce, code_challenge)
    log_step("OIDC Step 2 — Redirect to IdP","oidc_redirect",name,True,session_id=sid)
    log_step("OIDC Step 2 — Redirect to IdP","oidc_redirect",name,True,session_id=sid,level="debug",
             detail={"authorization_endpoint":cfg.get("authorization_endpoint",""),
                     "redirect_url":auth_url[:300]})
    return redirect(auth_url)


@app.route("/oidc/callback")
def oidc_callback():
    error_param = request.args.get("error","")
    name = session.get("oidc_idp", get_setting("active_oidc","duo"))
    sid  = session.get("oidc_flow_id", str(uuid.uuid4())[:8])

    if error_param:
        desc = request.args.get("error_description", error_param)
        log_step("OIDC Step 3 — Callback","oidc_callback_error",name,False,
                 error=desc,session_id=sid)
        flash(f"OIDC error from IdP: {desc}", "danger")
        return redirect(url_for("user_login_page"))

    code  = request.args.get("code","")
    state = request.args.get("state","")
    if not code:
        flash("OIDC callback missing authorization code.", "danger")
        return redirect(url_for("user_login_page"))

    # Validate state
    expected_state = session.get("oidc_state","")
    if state != expected_state:
        log_step("OIDC Step 3 — Callback","oidc_state_mismatch",name,False,
                 error="State parameter mismatch",session_id=sid)
        flash("OIDC state mismatch — possible CSRF attack. Please try again.", "danger")
        return redirect(url_for("user_login_page"))

    log_step("OIDC Step 3 — Callback","oidc_callback",name,True,session_id=sid)
    log_step("OIDC Step 3 — Callback","oidc_callback",name,True,session_id=sid,level="debug",
             detail={"code_present":bool(code),"state_ok":True,"idp":name})

    cfg = get_oidc_config(name)
    if not cfg:
        flash(f"Unknown OIDC provider '{name}'.", "danger")
        return redirect(url_for("user_login_page"))

    # Token exchange
    verifier = session.pop("oidc_pkce_verifier", None)
    nonce    = session.get("oidc_nonce","")
    tokens, err = oidc_exchange_code(cfg, code, verifier)
    if err:
        log_step("OIDC Step 4 — Token Exchange","oidc_token_error",name,False,
                 error=err,session_id=sid)
        flash(f"Token exchange failed: {err}", "danger")
        return redirect(url_for("user_login_page"))

    log_step("OIDC Step 4 — Token Exchange","oidc_token_ok",name,True,session_id=sid)

    id_token     = tokens.get("id_token","")
    access_token = tokens.get("access_token","")

    # Validate ID token
    claims, err = oidc_decode_id_token(cfg, id_token, nonce)
    if err:
        log_step("OIDC Step 5 — Token Validation","oidc_token_invalid",name,False,
                 error=err,session_id=sid)
        flash(f"ID token validation failed: {err}", "danger")
        return redirect(url_for("user_login_page"))
    log_step("OIDC Step 5 — Token Validation","oidc_token_valid",name,True,session_id=sid,
             detail={"sig_verified":not claims.get("_signature_not_verified",False),
                     "issuer":claims.get("iss",""),"sub":claims.get("sub","")} if is_debug() else None)

    # Userinfo claims merge
    claims_source = cfg.get("claims_source","both")
    userinfo = {}
    if access_token and claims_source in ("userinfo","both"):
        userinfo, ui_err = oidc_get_userinfo(cfg, access_token)
        if ui_err and is_debug():
            log_step("OIDC Step 5 — Token Validation","oidc_userinfo_error",name,False,
                     error=ui_err,session_id=sid,level="debug")
    all_claims = {**claims, **userinfo}

    # Filter to watched claims
    watched_names = {w["attr_name"] for w in get_oidc_watched_attrs(name)}
    watched_claims = {k:v for k,v in all_claims.items() if k in watched_names}

    username = oidc_extract_username(all_claims)

    log_step("OIDC Step 6 — Auth Complete","oidc_success",name,True,
             username=username,session_id=sid)
    log_step("OIDC Step 6 — Auth Complete","oidc_success",name,True,
             username=username,session_id=sid,level="debug",
             detail={"username":username,"sub":all_claims.get("sub",""),
                     "email":all_claims.get("email",""),
                     "all_claims":{k:v for k,v in all_claims.items()
                                   if not k.startswith("_")},
                     "watched_claims":watched_claims,
                     "sig_verified":not all_claims.get("_signature_not_verified",False)})

    session.permanent          = True
    session["auth_ok"]         = True
    session["username"]        = username
    session["login_idp"]       = name
    session["login_protocol"]  = "oidc"
    session["attrs"]           = watched_claims
    session["all_attrs"]       = {k:v for k,v in all_claims.items() if not k.startswith("_")}
    session["oidc_id_token"]   = id_token
    session["oidc_access_token"] = access_token
    session["oidc_sub"]        = all_claims.get("sub","")

    return redirect(url_for("app_page"))


# ─────────────────────────────────────────────────────────────────────────────
# SAML ROUTES
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/saml/login")
def saml_login():
    idp = request.args.get("idp", get_setting("active_idp","okta"))
    sid = str(uuid.uuid4())[:8]
    session["saml_flow_id"] = sid

    log_step("Step 1 — SSO Initiated","saml_init",idp,True,session_id=sid)
    log_step("Step 1 — SSO Initiated","saml_init",idp,True,session_id=sid,level="debug",
             detail={"idp":idp,"user_agent":request.headers.get("User-Agent",""),
                     "initiated_from":request.referrer or "direct","client_ip":request.remote_addr})
    try:
        auth    = init_saml(idp)
        cfg     = get_idp(idp)
        sso_url = auth.login(return_to=url_for("app_page", _external=True))
        log_step("Step 2 — Redirect to IdP","saml_redirect",idp,True,session_id=sid)
        log_step("Step 2 — Redirect to IdP","saml_redirect",idp,True,session_id=sid,level="debug",
                 detail={"sso_url":cfg.get("sso_url",""),"sp_entity_id":cfg.get("sp_entity",""),
                         "acs_url":cfg.get("sp_acs",""),"redirect_target":sso_url[:200]})
        return redirect(sso_url)
    except Exception as e:
        log_step("Step 2 — Redirect to IdP","saml_redirect_fail",idp,False,error=str(e),session_id=sid)
        flash(f"SAML configuration error: {e}", "danger")
        return redirect(url_for("user_login_page"))

@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    idp = get_setting("active_idp","okta")
    sid = session.get("saml_flow_id", str(uuid.uuid4())[:8])

    log_step("Step 3 — ACS Hit","acs_received",idp,True,session_id=sid)
    raw_response = request.form.get("SAMLResponse","")
    decoded_xml  = ""
    if raw_response and is_debug():
        try:
            decoded_xml = base64.b64decode(raw_response).decode("utf-8", errors="replace")
        except Exception:
            decoded_xml = "(could not decode)"
    log_step("Step 3 — ACS Hit","acs_received",idp,True,session_id=sid,level="debug",
             detail={"relay_state":request.form.get("RelayState",""),
                     "response_size_bytes":len(raw_response),
                     "saml_response_xml":decoded_xml[:3000] if decoded_xml else "(debug off)"})
    try:
        auth = init_saml(idp)
        log_step("Step 4 — Response Parsed","acs_parsed",idp,True,session_id=sid)
        auth.process_response()

        errors = auth.get_errors()
        if errors:
            err_reason = auth.get_last_error_reason() or ", ".join(errors)
            log_step("Step 5 — Signature Check","acs_sig_fail",idp,False,
                     error=err_reason,session_id=sid)
            log_step("Step 5 — Signature Check","acs_sig_fail",idp,False,
                     error=err_reason,session_id=sid,level="debug",
                     detail={"errors":errors,"last_error_reason":err_reason,
                             "response_excerpt":decoded_xml[:800]})
            flash(f"SAML validation failed: {err_reason}", "danger")
            return redirect(url_for("user_login_page"))

        if not auth.is_authenticated():
            log_step("Step 5 — Signature Check","acs_not_authed",idp,False,
                     error="IdP returned unauthenticated response",session_id=sid)
            flash("Authentication was not confirmed by the IdP.", "danger")
            return redirect(url_for("user_login_page"))

        log_step("Step 5 — Signature Check","acs_sig_ok",idp,True,session_id=sid)

        nameid      = auth.get_nameid()
        nameid_fmt  = auth.get_nameid_format()
        attrs       = auth.get_attributes()
        session_idx = auth.get_session_index()
        attrs_clean = {k: list(v) for k, v in attrs.items()}

        # Apply attribute mapping if custom IdP
        idp_cfg = get_idp(idp)
        mapping = {}
        try:
            mapping = json.loads(idp_cfg.get("attr_mapping") or "{}")
        except Exception:
            pass
        if mapping:
            mapped_attrs = {}
            for sp_key, idp_attr in mapping.items():
                if idp_attr in attrs_clean:
                    mapped_attrs[sp_key] = attrs_clean[idp_attr]
            attrs_clean.update(mapped_attrs)

        # Filter to watched attrs + log them
        watched = {w["attr_name"] for w in get_watched_attrs(idp)}
        attrs_watched = {k: v for k, v in attrs_clean.items() if k in watched}

        log_step("Step 6 — Auth Complete","acs_success",idp,True,
                 username=nameid,session_id=sid)
        log_step("Step 6 — Auth Complete","acs_success",idp,True,
                 username=nameid,session_id=sid,level="debug",
                 detail={"nameid":nameid,"nameid_format":nameid_fmt,
                         "session_index":session_idx,
                         "all_attributes":attrs_clean,
                         "watched_attributes":attrs_watched,
                         "attribute_count":len(attrs_clean)})

        session.permanent         = True
        session["auth_ok"]        = True
        session["username"]       = nameid
        session["login_idp"]      = idp
        session["login_protocol"] = "saml"
        session["attrs"]          = attrs_watched
        session["all_attrs"]      = attrs_clean   # full assertion attrs for welcome page
        session["saml_nameid"]    = nameid
        session["saml_nameid_fmt"]= nameid_fmt
        session["saml_session_idx"]= session_idx

        relay = request.form.get("RelayState","")
        dest  = _safe_redirect_url(relay, url_for("app_page", _external=True))
        return redirect(dest)

    except Exception as e:
        log_step("Step 4 — Response Parsed","acs_parse_error",idp,False,
                 error=str(e),session_id=sid)
        flash(f"Error processing SAML response: {e}", "danger")
        return redirect(url_for("user_login_page"))

@app.route("/saml/slo", methods=["GET","POST"])
def saml_slo():
    idp = get_setting("active_idp","okta")
    try:
        auth   = init_saml(idp)
        url    = auth.process_slo(delete_session_cb=lambda: session.clear())
        errors = auth.get_errors()
        if errors:
            flash(f"SLO error: {auth.get_last_error_reason()}", "danger")
            return redirect(url_for("user_login_page"))
        if url:
            return redirect(url)
    except Exception as e:
        session.clear()
        log_step("Logout (SLO Response)","saml_slo_response_error",idp,False,error=str(e))
    flash("You have been logged out.", "success")
    return redirect(url_for("user_login_page"))

@app.route("/saml/metadata")
def saml_metadata():
    idp = request.args.get("idp", get_setting("active_idp","okta"))
    try:
        auth     = init_saml(idp)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errs     = settings.validate_metadata(metadata)
        if errs:
            return f"Metadata error: {', '.join(errs)}", 500
        resp = make_response(metadata)
        resp.headers["Content-Type"] = "application/xml"
        return resp
    except Exception as e:
        return f"Error generating metadata: {e}", 500

# ═══════════════════════════════════════════════════════════════
# PHASE 9 — LAUNCH
# ═══════════════════════════════════════════════════════════════
def _wait_for_server(timeout=10):
    import urllib.request
    for _ in range(timeout * 5):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/status", timeout=1)
            return True
        except Exception:
            time.sleep(0.2)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# SERVICE MANAGEMENT  (Windows Task Scheduler / Linux systemd / macOS launchd)
# ─────────────────────────────────────────────────────────────────────────────
_SVC_TASK_NAME  = "SAMLTestBench"
_SVC_UNIT_NAME  = "saml-testbench"
_SVC_PLIST_NAME = "com.samltestbench.app"
_SVC_DISPLAY    = "SAML TestBench"


def _svc_exe() -> Path:
    return Path(sys.executable).resolve()


def _svc_status() -> dict:
    plat = platform.system()
    try:
        if plat == "Windows":
            r = subprocess.run(
                ["schtasks", "/query", "/tn", _SVC_TASK_NAME, "/fo", "LIST"],
                capture_output=True, text=True, timeout=8
            )
            installed = (r.returncode == 0)
            running   = installed and "Running" in r.stdout
            return {"installed": installed, "running": running,
                    "platform": "windows", "detail": "Task Scheduler task"}

        elif plat == "Linux":
            for scope in [[], ["--user"]]:
                r = subprocess.run(
                    ["systemctl"] + scope + ["is-active", _SVC_UNIT_NAME],
                    capture_output=True, text=True, timeout=5
                )
                if r.stdout.strip() == "active":
                    label = "system" if not scope else "user (--user)"
                    return {"installed": True, "running": True,
                            "platform": "linux", "detail": label}
            sys_f = Path("/etc/systemd/system/") / (_SVC_UNIT_NAME + ".service")
            usr_f = Path.home() / ".config/systemd/user" / (_SVC_UNIT_NAME + ".service")
            installed = sys_f.exists() or usr_f.exists()
            return {"installed": installed, "running": False,
                    "platform": "linux", "detail": "systemd unit (stopped)"}

        elif plat == "Darwin":
            plist = Path.home() / "Library/LaunchAgents" / (_SVC_PLIST_NAME + ".plist")
            if not plist.exists():
                return {"installed": False, "running": False,
                        "platform": "darwin", "detail": "LaunchAgent not found"}
            r = subprocess.run(["launchctl", "list", _SVC_PLIST_NAME],
                               capture_output=True, text=True, timeout=5)
            running = (r.returncode == 0) and "PID" in r.stdout
            return {"installed": True, "running": running,
                    "platform": "darwin", "detail": "LaunchAgent"}
    except Exception:
        pass
    return {"installed": False, "running": False, "platform": plat.lower(), "detail": "unknown"}


def _svc_install() -> str:
    plat = platform.system()
    exe  = _svc_exe()

    if plat == "Windows":
        r = subprocess.run(
            ["schtasks", "/create", "/f",
             "/tn", _SVC_TASK_NAME,
             "/tr", '"{}"'.format(exe),
             "/sc", "ONSTART",
             "/ru", "SYSTEM", "/rl", "HIGHEST",
             "/delay", "0000:30"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or r.stdout.strip())
        lines = [
            "Task Scheduler task '{}' created.".format(_SVC_TASK_NAME),
            "SAML TestBench will start automatically at every system boot.",
            "To start now:  schtasks /run /tn {}".format(_SVC_TASK_NAME),
            "To check:      schtasks /query /tn {} /fo LIST".format(_SVC_TASK_NAME),
        ]
        return "\n".join(lines)

    elif plat == "Linux":
        unit_lines = [
            "[Unit]",
            "Description=" + _SVC_DISPLAY,
            "Documentation=https://github.com/samltestbench",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=simple",
            "ExecStart=" + str(exe),
            "Restart=always",
            "RestartSec=10",
            "WorkingDirectory=" + str(exe.parent),
            "StandardOutput=journal",
            "StandardError=journal",
            "SyslogIdentifier=saml-testbench",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
        ]
        unit = "\n".join(unit_lines) + "\n"
        sys_path = Path("/etc/systemd/system") / (_SVC_UNIT_NAME + ".service")
        usr_path = Path.home() / ".config/systemd/user" / (_SVC_UNIT_NAME + ".service")
        try:
            sys_path.write_text(unit)
            subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=10)
            subprocess.run(["systemctl", "enable", _SVC_UNIT_NAME], check=True, timeout=10)
            lines = [
                "systemd service '{}' installed system-wide.".format(_SVC_UNIT_NAME),
                "To start now:  sudo systemctl start {}".format(_SVC_UNIT_NAME),
                "Status:        sudo systemctl status {}".format(_SVC_UNIT_NAME),
            ]
            return "\n".join(lines)
        except (PermissionError, subprocess.CalledProcessError):
            usr_path.parent.mkdir(parents=True, exist_ok=True)
            usr_path.write_text(unit)
            subprocess.run(["systemctl", "--user", "daemon-reload"], timeout=10)
            subprocess.run(["systemctl", "--user", "enable", _SVC_UNIT_NAME], timeout=10)
            try:
                import getpass as _gp
                subprocess.run(["loginctl", "enable-linger", _gp.getuser()], timeout=5)
            except Exception:
                pass
            lines = [
                "User systemd service installed at:",
                str(usr_path),
                "To start now:  systemctl --user start {}".format(_SVC_UNIT_NAME),
                "Status:        systemctl --user status {}".format(_SVC_UNIT_NAME),
                "Note: 'loginctl enable-linger $USER' lets it survive logout.",
            ]
            return "\n".join(lines)

    elif plat == "Darwin":
        plist_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"',
            '  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
            '<plist version="1.0">',
            '<dict>',
            '  <key>Label</key><string>{}</string>'.format(_SVC_PLIST_NAME),
            '  <key>ProgramArguments</key>',
            '  <array><string>{}</string></array>'.format(exe),
            '  <key>RunAtLoad</key><true/>',
            '  <key>KeepAlive</key><true/>',
            '  <key>WorkingDirectory</key><string>{}</string>'.format(exe.parent),
            '  <key>StandardOutPath</key><string>{}/saml_testbench.log</string>'.format(exe.parent),
            '  <key>StandardErrorPath</key><string>{}/saml_testbench_err.log</string>'.format(exe.parent),
            '</dict>',
            '</plist>',
        ]
        agents = Path.home() / "Library/LaunchAgents"
        agents.mkdir(parents=True, exist_ok=True)
        plist_path = agents / (_SVC_PLIST_NAME + ".plist")
        plist_path.write_text("\n".join(plist_lines) + "\n")
        subprocess.run(["launchctl", "load", "-w", str(plist_path)], timeout=10)
        lines = [
            "LaunchAgent installed at:",
            str(plist_path),
            "SAML TestBench will start at login and restart if it crashes.",
        ]
        return "\n".join(lines)

    raise NotImplementedError("Service install not supported on {}".format(plat))


def _svc_uninstall() -> str:
    plat = platform.system()
    msgs = []
    if plat == "Windows":
        subprocess.run(["schtasks", "/end", "/tn", _SVC_TASK_NAME],
                       capture_output=True, timeout=8)
        r = subprocess.run(["schtasks", "/delete", "/f", "/tn", _SVC_TASK_NAME],
                           capture_output=True, text=True, timeout=8)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "Task not found.")
        msgs.append("Task Scheduler task '{}' removed.".format(_SVC_TASK_NAME))
    elif plat == "Linux":
        for scope in [[], ["--user"]]:
            subprocess.run(["systemctl"] + scope + ["stop",    _SVC_UNIT_NAME],
                           capture_output=True, timeout=10)
            subprocess.run(["systemctl"] + scope + ["disable", _SVC_UNIT_NAME],
                           capture_output=True, timeout=10)
        for p in [
            Path("/etc/systemd/system") / (_SVC_UNIT_NAME + ".service"),
            Path.home() / ".config/systemd/user" / (_SVC_UNIT_NAME + ".service"),
        ]:
            if p.exists():
                try:
                    p.unlink()
                    msgs.append("Removed {}".format(p))
                except PermissionError:
                    msgs.append("Could not remove {} (try as root)".format(p))
        subprocess.run(["systemctl",         "daemon-reload"], capture_output=True, timeout=10)
        subprocess.run(["systemctl", "--user","daemon-reload"], capture_output=True, timeout=10)
        if not msgs:
            msgs.append("No service files found.")
    elif plat == "Darwin":
        plist_path = Path.home() / "Library/LaunchAgents" / (_SVC_PLIST_NAME + ".plist")
        if plist_path.exists():
            subprocess.run(["launchctl", "unload", "-w", str(plist_path)],
                           capture_output=True, timeout=10)
            plist_path.unlink()
            msgs.append("LaunchAgent removed: {}".format(plist_path))
        else:
            msgs.append("No LaunchAgent found.")
    else:
        raise NotImplementedError("Service uninstall not supported on {}".format(plat))
    return "\n".join(msgs)


def _svc_start() -> str:
    plat = platform.system()
    if plat == "Windows":
        r = subprocess.run(["schtasks", "/run", "/tn", _SVC_TASK_NAME],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())
        return "Task started."
    elif plat == "Linux":
        for scope in [[], ["--user"]]:
            r = subprocess.run(["systemctl"] + scope + ["start", _SVC_UNIT_NAME],
                               capture_output=True, timeout=10)
            if r.returncode == 0:
                return "Service started."
        raise RuntimeError("Could not start service (try as root for system service).")
    elif plat == "Darwin":
        subprocess.run(["launchctl", "start", _SVC_PLIST_NAME], check=True, timeout=10)
        return "LaunchAgent started."
    raise NotImplementedError(platform.system())


def _svc_stop() -> str:
    plat = platform.system()
    if plat == "Windows":
        r = subprocess.run(["schtasks", "/end", "/tn", _SVC_TASK_NAME],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())
        return "Task ended."
    elif plat == "Linux":
        for scope in [[], ["--user"]]:
            r = subprocess.run(["systemctl"] + scope + ["stop", _SVC_UNIT_NAME],
                               capture_output=True, timeout=10)
            if r.returncode == 0:
                return "Service stopped."
        raise RuntimeError("Could not stop service.")
    elif plat == "Darwin":
        subprocess.run(["launchctl", "stop", _SVC_PLIST_NAME], check=True, timeout=10)
        return "LaunchAgent stopped."
    raise NotImplementedError(platform.system())


# ── Service API routes ────────────────────────────────────────────────────────
@app.route("/admin/service/status")
@admin_required
def admin_svc_status():
    return jsonify(_svc_status())

@app.route("/admin/service/install", methods=["POST"])
@admin_required
def admin_svc_install():
    try:
        msg = _svc_install()
        return jsonify({"ok": True,  "message": msg, "status": _svc_status()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "status": _svc_status()})

@app.route("/admin/service/uninstall", methods=["POST"])
@admin_required
def admin_svc_uninstall():
    try:
        msg = _svc_uninstall()
        return jsonify({"ok": True,  "message": msg, "status": _svc_status()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "status": _svc_status()})

@app.route("/admin/service/start", methods=["POST"])
@admin_required
def admin_svc_start():
    try:
        msg = _svc_start()
        return jsonify({"ok": True,  "message": msg, "status": _svc_status()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "status": _svc_status()})

@app.route("/admin/service/stop", methods=["POST"])
@admin_required
def admin_svc_stop():
    try:
        msg = _svc_stop()
        return jsonify({"ok": True,  "message": msg, "status": _svc_status()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "status": _svc_status()})

def main():
    global PORT
    init_db()
    # Load port from DB (set via Admin → Settings, takes effect on restart)
    _db_port = get_setting("port", "")
    if _db_port and _db_port.isdigit() and 1024 <= int(_db_port) <= 65535:
        PORT = int(_db_port)

    app.secret_key             = _user_secret()
    app.config["ADMIN_SECRET"] = _admin_secret()
    app.config["SESSION_COOKIE_NAME"]     = "saml_user_session"
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    import logging as _logging
    _logging.getLogger("werkzeug").setLevel(_logging.ERROR)

    print(f"\n{'═'*56}")
    print(f"  ⬡  SAML TestBench  —  http://localhost:{PORT}")
    print(f"{'─'*56}")
    print(f"  Admin Panel  :  http://localhost:{PORT}/admin")
    print(f"  Login Page   :  http://localhost:{PORT}/login")
    print(f"  SP Metadata  :  http://localhost:{PORT}/saml/metadata")
    print(f"  OIDC Callback:  http://localhost:{PORT}/oidc/callback")
    print(f"{'─'*56}")
    print(f"  Script       :  {APP_DIR}")
    print(f"  Database     :  {DB_PATH.name}")
    print(f"  SAML Cache   :  {SAML_TMP.name}/")
    print(f"  Timezone     :  {datetime.now().astimezone().strftime('%Z %z')}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'═'*56}\n")

    flask_thread = threading.Thread(
        target=lambda: app.run(
            host="127.0.0.1", port=PORT,
            debug=False, use_reloader=False, threaded=True
        ),
        daemon=True
    )
    flask_thread.start()

    if _wait_for_server():
        webbrowser.open(f"http://127.0.0.1:{PORT}/admin")
    else:
        print(f"⚠  Server did not start on port {PORT}. Is it already in use?")

    try:
        while flask_thread.is_alive():
            flask_thread.join(timeout=1)
    except KeyboardInterrupt:
        print("\n\n⬡  SAML TestBench stopped. Goodbye!\n")
        sys.exit(0)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        prog="saml_testbench",
        description="SAML TestBench — SAML/OIDC testing server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  saml_testbench                    # start server, open browser\n"
            "  saml_testbench --install-service  # register as auto-start service\n"
            "  saml_testbench --uninstall-service\n"
            "  saml_testbench --status\n"
            "  saml_testbench --no-browser\n"
            "  saml_testbench --port 8080\n"
        )
    )
    ap.add_argument("--install-service",   action="store_true", help="Register as auto-start background service")
    ap.add_argument("--uninstall-service", action="store_true", help="Remove background service registration")
    ap.add_argument("--start-service",     action="store_true", help="Start the installed service")
    ap.add_argument("--stop-service",      action="store_true", help="Stop the running service")
    ap.add_argument("--status",            action="store_true", help="Print service status and exit")
    ap.add_argument("--no-browser",        action="store_true", help="Start server without opening browser")
    ap.add_argument("--port",              type=int, default=PORT, metavar="PORT", help="Port to listen on (default: 5000)")
    args = ap.parse_args()

    if args.port != PORT:
        PORT = args.port

    if args.install_service:
        print(_svc_install()); sys.exit(0)
    elif args.uninstall_service:
        print(_svc_uninstall()); sys.exit(0)
    elif args.start_service:
        print(_svc_start()); sys.exit(0)
    elif args.stop_service:
        print(_svc_stop()); sys.exit(0)
    elif args.status:
        st = _svc_status()
        print("Platform : {}".format(st["platform"]))
        print("Installed: {}".format(st["installed"]))
        print("Running  : {}".format(st["running"]))
        print("Detail   : {}".format(st["detail"]))
        sys.exit(0)
    else:
        if args.no_browser:
            import webbrowser as _wb_mod
            _wb_mod.open = lambda *a, **k: None
        main()
