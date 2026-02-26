# ⬡ SAML TestBench

A single-file Python tool for testing **SAML 2.0** and **OpenID Connect (OIDC)** authentication flows against real Identity Providers such as Okta and Duo. It runs a local web application that acts as a Service Provider (SP), logs every authentication step, and provides a full admin panel — no cloud deployment needed.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![macOS](https://img.shields.io/badge/macOS-supported-brightgreen)
![Windows](https://img.shields.io/badge/Windows-supported-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Default Admin Credentials](#default-admin-credentials)
- [Configuring SAML](#configuring-saml)
- [Configuring OIDC](#configuring-oidc)
- [Changing the Port](#changing-the-port)
- [Running Multiple Instances](#running-multiple-instances)
- [Enabling Debug Logging](#enabling-debug-logging)
- [Authentication Logs](#authentication-logs)
- [User Management](#user-management)
- [Settings and Data Management](#settings-and-data-management)
- [Troubleshooting](#troubleshooting)

---

## What it does

- **Hosts a SAML SP** at `http://localhost:5000` — complete with metadata XML, ACS, and SLO endpoints
- **Hosts an OIDC client** — Authorization Code flow with PKCE, auto-discovery, and JWT verification
- **Logs every step** of both SAML and OIDC flows with a collapsible card per session showing exactly where a flow succeeded or failed
- **Multi-IdP** — configure up to 8 SAML IdPs and 8 OIDC providers simultaneously, each on its own tab
- **Local user accounts** — create test users with custom attributes, independent of the IdP
- **Single file** — the entire application is `saml_testbench.py`; dependencies install automatically on first run

---

## Requirements

### Python

Python **3.8 or newer**. Download from [python.org](https://www.python.org/downloads/).

```bash
python3 --version   # macOS / Linux
python --version    # Windows
```

### Python packages (auto-installed on first run)

| Package | Purpose |
|---|---|
| `flask >= 3.0` | Web framework |
| `python3-saml >= 1.16` | SAML 2.0 library |
| `requests >= 2.31` | HTTP client for OIDC token exchange |
| `PyJWT[cryptography] >= 2.8` | JWT validation for OIDC ID tokens |

### Platform notes

**macOS** — `python3-saml` requires `libxmlsec1`. Install it before first run:
```bash
brew install libxmlsec1
```

**Windows** — If the auto-install fails for `python3-saml`, install the C library dependencies manually:
```powershell
pip install lxml xmlsec
pip install python3-saml
```

---

## Quick Start

**1. Download the script**

```bash
git clone https://github.com/your-org/saml-testbench.git
cd saml-testbench
```

**2. Run**

macOS / Linux:
```bash
python3 saml_testbench.py
```

Windows:
```powershell
python saml_testbench.py
```

On first run, dependencies install automatically, a SQLite database is created (`saml_testbench.db`) in the same folder as the script, and the browser opens to `http://localhost:5000/admin`.

**3. Stop**

Press `Ctrl+C` in the terminal.

---

## Default Admin Credentials

```
URL:       http://localhost:5000/admin
Username:  admin
Password:  admin123
```

> **Change this password immediately** after first login. Go to **Admin → Users**, click the `admin` account, and set a new password.

The admin panel (`/admin`) is separate from the end-user login page (`/login`). Admin accounts have full access to IdP configuration, logs, and settings.

---

## Configuring SAML

Go to **Admin → IdP Config** and select the **Okta** or **Duo** tab (or click **+ Add Custom** for any other provider).

### What your IdP needs from you

Register these SP values in your IdP's SAML application. Copy buttons are provided on the form.

| Field in IdP | Value |
|---|---|
| ACS URL / Single Sign-On URL | `http://localhost:5000/saml/acs` |
| SP Entity ID / Audience URI | `http://localhost:5000/saml/metadata` |
| SLO URL *(optional)* | `http://localhost:5000/saml/slo` |
| SP Metadata XML | View/download at `http://localhost:5000/saml/metadata` |

> If you changed the port, replace `5000` with your port in all the above URLs.

### What you need from your IdP

These values come from your IdP's SAML application settings page.

| Field | Where to find it |
|---|---|
| **IdP Entity ID / Issuer URL** | Okta: *Sign On* tab → *Identity Provider Issuer*. Duo: SAML Metadata → `entityID` attribute |
| **SSO URL** | Okta: *Sign On* tab → *Identity Provider Single Sign-On URL*. Duo: SAML Metadata → `SingleSignOnService Location` |
| **X.509 Signing Certificate** | Okta: *Sign On* tab → download certificate. Duo: SAML Metadata → `<X509Certificate>` |
| **SLO URL** *(optional)* | Only needed for Single Logout. Leave blank if not supported |

**Tip:** If your IdP provides a SAML Metadata XML file, click **Import from IdP XML Metadata** — Entity ID, SSO URL, SLO URL, and the certificate all fill in automatically.

### Saving

Click **Save Configuration**. If all three required fields are filled (Entity ID, SSO URL, X.509 certificate), the IdP is automatically enabled on the login page. A banner lists any missing fields, which are also highlighted in red on the form.

---

## Configuring OIDC

Go to **Admin → OIDC Config** and select a provider tab.

### What your IdP needs from you

| Field in IdP | Value |
|---|---|
| Redirect URI / Callback URL | `http://localhost:5000/oidc/callback` |
| Application Type | Web application |
| Grant Type | Authorization Code |

### What you need from your IdP

| Field | Notes |
|---|---|
| **Client ID** | From the IdP's application settings |
| **Client Secret** | From the IdP's application settings *(not required for PKCE-only flows)* |
| **Discovery URL** | Paste this and click **Discover** to auto-fill all endpoints |

#### Discovery URL examples

| Provider | Discovery URL |
|---|---|
| Okta | `https://{your-domain}/.well-known/openid-configuration` |
| Okta (custom auth server) | `https://{your-domain}/oauth2/{serverId}/.well-known/openid-configuration` |
| Duo | `https://sso-{XXXX}.sso.duosecurity.com/oidc/{XXXX}/.well-known/openid-configuration` |
| Azure AD | `https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration` |
| Google | `https://accounts.google.com/.well-known/openid-configuration` |
| Keycloak | `https://{host}/realms/{realm}/.well-known/openid-configuration` |

If discovery is unavailable, fill in the endpoints manually (Authorization, Token, Userinfo, JWKS URI).

---

## Changing the Port

### Option 1 — Edit the script (takes effect immediately on next start)

Open `saml_testbench.py` and change the `PORT` constant near the top:

```python
# ─── Port: change this number OR use Admin → Settings → Port ────
PORT = 5000   # ← change to your desired port, e.g. 8080
```

### Option 2 — Admin panel (persisted in the database, takes effect on restart)

1. Go to **Admin → Settings**
2. Find the **Port** field
3. Enter a number between `1024` and `65535`
4. Click **Save Settings**
5. Restart the script

> **After changing the port,** update all SP URLs registered in your IdP (ACS URL, Entity ID, Redirect URI) to use the new port.

---

## Running Multiple Instances

You can run several instances simultaneously — for example, one for a staging IdP and one for production, or separate environments per team member.

Each instance requires:
- A **different port**
- A **separate working directory** (so the databases do not conflict)

```bash
# Instance 1 — staging (port 5000)
cd ~/saml-testbench-staging
python3 saml_testbench.py

# Instance 2 — production (port 5001)
cd ~/saml-testbench-prod
# Edit saml_testbench.py and set PORT = 5001
python3 saml_testbench.py
```

Each instance has its own `saml_testbench.db`, its own admin account, and its own IdP configurations. Register the correct SP URLs — including the correct port — in each IdP.

---

## Enabling Debug Logging

Debug mode captures the full content of every SAML assertion and OIDC token, useful for diagnosing attribute mapping issues or signature failures.

1. Go to **Admin → Settings**
2. Toggle **Enable Debug Logging** on
3. Click **Save Settings**

### What debug entries add

- Full raw SAMLRequest and SAMLResponse XML (base64-decoded)
- Every attribute in the SAML assertion
- NameID, NameID format, and session index
- Signature and digest algorithm details
- For OIDC: full decoded ID token claims and userinfo payload

Debug entries appear in **Admin → Logs** with a yellow `DBG` badge. They are stored alongside normal entries and expand with the rest of the log group.

> Disable debug logging in high-volume testing to keep the database small.

---

## Authentication Logs

Go to **Admin → Logs** to see every authentication attempt. Each card is one complete login session.

### SAML flow steps (in order)

| Step | What happens |
|---|---|
| Step 1 — SSO Initiated | SP builds the signed `<AuthnRequest>` XML |
| Step 2 — Redirect to IdP | Browser sent to the IdP's SSO URL |
| Step 3 — ACS Hit | IdP POSTs the `<SAMLResponse>` to the ACS endpoint |
| Step 4 — Response Parsed | XML decoded, Assertion extracted |
| Step 5 — Signature Check | Certificate verified, conditions checked (audience, expiry) |
| Step 6 — Auth Complete | Session created, user logged in |
| Logout (SLO) | Single Logout initiated (appears last) |

### OIDC flow steps (in order)

| Step | What happens |
|---|---|
| OIDC Step 1 — Login Initiated | State, nonce, PKCE challenge generated |
| OIDC Step 2 — Redirect to IdP | Browser sent to the authorization endpoint |
| OIDC Step 3 — Callback Received | Authorization code returned, state verified |
| OIDC Step 4 — Token Exchange | Code exchanged for ID token and access token |
| OIDC Step 5 — Token Validated | JWT signature and claims verified |
| OIDC Step 6 — Auth Complete | Session created, user logged in |

### Filters

| Filter | Description |
|---|---|
| Protocol | SAML, OIDC, or Local |
| IdP | Filter by provider name |
| User | Filter by username |
| IP | Filter by source IP address |
| Result | Success or Failed |
| Search box | Free-text across all fields; wrap in `"quotes"` for exact match |

Click **Export Logs (JSON)** to download all entries.

---

## User Management

Go to **Admin → Users** to create local accounts for testing username/password authentication without a live IdP.

**Roles:**

| Role | Access |
|---|---|
| `user` | Login page and app page only |
| `admin` | Full admin panel |

**Custom attributes** — assign key-value pairs to any user. These appear on the welcome page after login, simulating the attribute payload a SAML assertion would carry.

---

## Settings and Data Management

Go to **Admin → Settings**.

| Setting | Description |
|---|---|
| Active Identity Provider | Default IdP used when no `?idp=` parameter is in the request |
| Port | Change the listening port — requires restart |
| Debug Logging | Enable/disable verbose assertion logging |
| Export Settings | Download a plain-text document of all current settings |
| Move / Copy Data | Copy script, database, and SAML cache to a new folder |
| Clear SAML Cache | Remove cached IdP settings files — rebuilt automatically on next use |
| Factory Reset | Permanently erase all data and recreate `admin / admin123` |

### Backing up IdP configs

Before updating the script, export your configurations:
- **SAML:** Admin → IdP Config → **Export IdP Configs**
- **OIDC:** Admin → OIDC Config → **Export OIDC Configs**

To restore, use the **Import** buttons on the same pages.

---

## Troubleshooting

### Packages fail to install on first run

Ensure you have internet access and a working `pip`, then install manually:
```bash
pip install flask "python3-saml>=1.16" requests "PyJWT[cryptography]"
```

On macOS, if `python3-saml` fails:
```bash
brew install libxmlsec1
pip install python3-saml
```

### Port already in use

Change the port (see [Changing the Port](#changing-the-port)), or find what is using port 5000:

macOS / Linux:
```bash
lsof -i :5000
```

Windows:
```powershell
netstat -ano | findstr :5000
```

### SAML signature fails (Step 5)

- Verify the X.509 certificate in the IdP config matches what the IdP is currently using
- Check the SP Entity ID matches what you registered in the IdP exactly
- Ensure the machine clock is accurate — SAML assertions are time-sensitive
- Enable debug logging and inspect the raw `SAMLResponse` XML for `NotBefore` / `NotOnOrAfter` timestamps

### OIDC token exchange fails (Step 4)

- Verify the Redirect URI registered in the IdP matches exactly: `http://localhost:{port}/oidc/callback`
- Use the **Discover** button to auto-fill endpoints from the discovery URL
- Check whether the IdP requires `client_secret_basic` instead of `client_secret_post` (OIDC Config → Advanced Settings)

### Browser does not open automatically

Navigate manually to `http://localhost:5000/admin`. If the page does not load, check the terminal for startup errors.

### Reset a broken database

Stop the server and delete the database file, then restart:
```bash
rm saml_testbench.db
python3 saml_testbench.py
```

Or use **Admin → Settings → Danger Zone → Factory Reset** to reset without deleting the file.
