# FraudMesh security notes (v3 application security)

Scope: v3 phases 6.3 (sessions and cookies), 8 (behavioural telemetry), 12 (SQL injection / XSS / platform controls)
and 14 (encryption and hashing), plus the optional Firebase boundary. PostgreSQL and FraudMesh's own JWT + Argon2id
authentication are the primary system. Everything marked "off by default" changes nothing until it is configured.

## 1. Sessions, tokens and cookies (phase 6.3)

| Item | Behaviour |
|---|---|
| Session store | `auth_sessions` + `auth_refresh_tokens` (migration `0004_auth_sessions`, code in `api/sessions.py`). Replaces the in-memory refresh dict, so sessions survive restarts and work across API processes. |
| Refresh token | 256-bit `secrets.token_urlsafe(32)`, stored only as SHA-256 (a fast unkeyed hash is enough for a high-entropy random value). Single use. |
| Rotation | `/v1/auth/refresh` marks the presented token used and issues a new one in the same transaction (row lock: two concurrent refreshes cannot both succeed). |
| Reuse detection | A used token presented again more than 10 s after its rotation revokes the whole session (the token family) and writes `SESSION_REUSE_DETECTED` to the audit log. Within 10 s (two tabs racing on one cookie) it is refused without revoking; the racer receives nothing usable. The console's refresh is single-flight (`web/src/lib/api.ts`) so it never races itself. |
| Expiry | Idle: 8 h since the last refresh (`REFRESH_TTL_S`, unchanged). Absolute: `FM_SESSION_MAX_AGE_S` (default 24 h) since sign-in. Access tokens: 15 min (unchanged). |
| `sid` claim | Every access token carries its session id; tokens without `sid` are rejected. `current_user` and the WebSocket check that the session is live (cached `FM_SESSION_CHECK_TTL_S`, default 5 s; revocation in the same process is immediate, other processes see it within the TTL). Open WebSockets re-check every 30 s. |
| Logout | Revokes the token's session (and the cookie's session) server-side; the access token stops working immediately. |
| Revoke all | `POST /v1/auth/sessions/revoke-all` (self), `POST /v1/auth/users/{user_id}/sessions/revoke` (admin). Audited as `SESSIONS_REVOKED`. `GET /v1/auth/sessions` lists the caller's live sessions (no secrets). |
| Privilege change | If a user's role or queues differ from the session's at refresh time, the old session is revoked and a new one (new `sid`) is issued (`SESSION_ROTATED`). Code that changes roles should call `sessions.on_privilege_change(user_id)` to revoke at once. |
| Cookie | `fm_refresh`: HttpOnly, SameSite=Strict, Path=/v1/auth, Secure when `FM_TLS=1`. |
| CSRF | `/refresh` and `/login` (login CSRF): a browser request (one carrying Origin, Referer or Sec-Fetch-Site) must come from `CORS_ORIGINS` / `CORS_ORIGIN_REGEX` / the API's own origin and carry `X-FM-CSRF: 1`. The custom header forces a CORS preflight, which only allowed origins pass. Requests with none of those headers are not browsers and cannot carry a victim's cookie. The console sends the header on every request. |

### Design only (not implemented): WebAuthn / passkeys and device-bound sessions

Nothing below is built or claimed; it is the intended interface.

- Passkeys for analysts: tables `webauthn_credentials(credential_id PK, user_id, public_key_cose, sign_count, aaguid,
  transports, created_at, last_used_at)`; routes `POST /v1/auth/webauthn/register/options|verify` (bearer, re-auth within
  5 min) and `POST /v1/auth/webauthn/login/options|verify` (public, rate-limited like login). Challenges: 32 random bytes,
  stored hashed with a 2 min TTL, single use. RP ID = the console host; `userVerification: "required"`. A successful
  assertion calls `sessions.create_session(..., provider="webauthn")`, so revocation and `sid` checks are unchanged.
  Library candidate: `webauthn` (py_webauthn). Step-up for lead/admin actions could require a fresh assertion.
- Device-bound session credentials (DBSC-style): at sign-in the browser generates a non-exportable key pair
  (WebCrypto, `extractable: false`, kept in IndexedDB) and registers the public key on the session
  (`auth_sessions.device_public_key`). `/refresh` then also requires a signature over a server nonce, so a stolen
  refresh cookie alone is useless. Interface: `sessions.bind_device_key(sid, jwk)`, `sessions.verify_device_proof(sid,
  nonce, signature)`; refresh refuses when the session is bound and the proof is missing or invalid.

## 2. Behavioural telemetry (phase 8, bank demo)

`bank-demo/src/lib/telemetry.ts` collects only the contract 1.1.0 fields:

- `Context`: `session_id` (per-tab random id from `crypto.getRandomValues`, sessionStorage), `browser_timezone` (Intl),
  `locale`, `platform`, `webgl_renderer` (only when `WEBGL_debug_renderer_info` exists, else omitted), `screen`.
- `Telemetry`: pointer type; keystroke interval mean/std (time between key presses only, rounded to 10 ms, gaps over
  5 s ignored; key values are never read; password and OTP fields are excluded); `paste_in_sensitive_field` (a flag, only
  for fields marked `data-telemetry="sensitive"`: payee account and amount; the clipboard is never read); dwell on the
  payee and transfer screens; screen-resolution change count; `remote_access_demo` / `active_call_demo`, which are
  simulated demo toggles in the identity bar with a visible disclosure.

Server side, the request is validated by the contract models (`extra="forbid"`, ranges and lengths) before anything is
signed or stored: unknown fields, out-of-range numbers, wrong types and oversized strings get 422, bodies over 64 KB get
413 (`tests/api/test_v3_appsec_telemetry.py`). The engine stores `session_id` only as a `ses:` token.

## 3. Injection and XSS (phase 12)

- SQL: every query uses bound parameters. f-string SQL exists only for identifiers that are module constants:
  `api/demo_baseline.py` (`SCHEMA`, `TABLES`, `SERIAL_COLUMNS`), `api/store_pg.py` merge table list, `api/stepup.py`
  `_COLS`, `api/queries.py` WHERE fragments chosen by code (values bound), `api/db/session.py` `SET ROLE fm_app`,
  migrations, `tests/`. `tests/api/test_v3_appsec_injection.py` asserts the identifiers are plain constants naming real
  tables and runs SQL/XSS metacharacters through login, case filters, cursor, case-id paths, sms-inbox, step-up pending,
  ask, feedback note, manual reason and payee nickname.
- Least privilege: the API runs as `fm_app` (SET ROLE on every pooled connection). It has no UPDATE/DELETE/TRUNCATE on
  `audit_log` (0002) and, from 0004, no TRUNCATE on any table. Truncation (tests, demo reset, demo baseline) uses the
  owner role through `admin_engine()`, which request handlers never use outside the admin-only demo routes.
- XSS: the React apps render untrusted strings as text children only. `scripts/check_frontend_xss.py` (run by
  `tests/api/test_v3_appsec_static.py`) fails on `dangerouslySetInnerHTML`, `innerHTML`/`outerHTML` assignment,
  `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, string timers, `srcdoc`, `javascript:` URLs and
  `href`/`src` bound to an expression. Cytoscape draws labels on a canvas; Recharts tooltips render through React.
  Stored payloads round-trip as JSON strings and the API never answers `text/html`.
- CSP: `deploy/nginx-spa.conf` allows scripts from `'self'` only (no inline, no remote), `object-src 'none'`,
  `frame-ancestors 'none'`; `'unsafe-inline'` is for styles only (React `style` attributes). The API sends
  `default-src 'self'` (PRD §9.7, asserted verbatim by an existing test) plus nosniff, `X-Frame-Options: DENY`,
  `no-store`; `/docs` (demo mode only) has its own CSP for Swagger UI.
- Errors: unhandled exceptions become `{"error": {"code": "INTERNAL_ERROR"}}` with no stack trace; validation errors name
  the field, not its value.
- Secrets: `scripts/check_secrets.py` (run by the static test) scans git-tracked files for private keys, service-account
  JSON, cloud/API tokens, JWT literals, hard-coded secret assignments and tracked files under `data/`.

## 4. Encryption and hashing (phase 14)

Hashing is not encryption. A hash cannot be reversed but a guessable input can be confirmed by hashing guesses;
encryption is reversible with the key.

| Data | Protection |
|---|---|
| Passwords | Argon2id (`argon2-cffi` defaults), constant-work check for unknown e-mails. |
| Phone numbers, accounts, devices, IPs, customers, sessions | HMAC-SHA256 tokens with `TOKEN_KEY` (`engine/common/tokenize.py`). Keyed because these identifiers are low-entropy: a plain hash of a phone number is reversed by enumerating numbers. |
| OTP codes | Keyed hash (`api/stepup.py`). |
| Refresh tokens | SHA-256 of a 256-bit random value. |
| Audit chain | SHA-256 hash chain (`api/audit.py`), verified by `/v1/audit/verify`. |
| `feedback.note`, manual-action reason (`decisions.data.override_reason`) | AES-256-GCM via `api/crypto_box.py` when keys are configured (off by default: plaintext as before). |
| Factor ids for seeded customers | `api/seeding.py` now derives them with SHA-256 instead of MD5 (not a security use; ids of newly seeded rows change). No MD5/SHA-1 remains in `api/`, `scripts/`, `engine/` (tested). |

`api/crypto_box.py`: `FM_DATA_KEYS` = JSON `{kid: 64 hex}`, `FM_DATA_KEY_ACTIVE` = kid for new writes. Format
`fmenc:v1:<kid>:<base64url(nonce || ciphertext || tag)>`, 96-bit random nonce, associated data
`fraudmesh/v1|table|column|row id`, so a ciphertext moved to another row or column fails. Rotation: add a kid, switch
the active kid; old values still decrypt; `reencrypt()` moves a value to the active key; remove a kid only after
re-encrypting. A broken key configuration fails closed (error, nothing written in plaintext). Values without the
prefix are treated as legacy plaintext, so enabling encryption needs no migration.

Audit decision: with encryption on, `FEEDBACK` and `MANUAL_ACTION` audit rows store `note_sha256` / `reason_sha256`
instead of the text (`crypto_box.redact_audit`, applied in `api/audit.append_audit`). The hash chain covers the digest,
so it stays verifiable and append-only, and the plaintext exists only encrypted. Caveat: a short reason can be confirmed
by hashing guesses; the digest proves integrity, not secrecy. With encryption off, audit rows keep the plaintext as before.

## 5. Optional Firebase boundary (unconnected)

`api/firebase_boundary.py`. Nothing is connected: no project, no credentials, no `firebase-admin` dependency; tests use
a fake verifier and a fake Firestore client.

- `FM_AUTH_PROVIDER=local` (default) | `firebase`. In firebase mode `POST /v1/auth/firebase {"id_token"}` is mounted and
  password login returns 403. The verified token must have `email_verified: true`, an `fm_role` custom claim, and an
  e-mail that already exists in `users`; the role is the lower of the two. FraudMesh then issues its own session and
  access token, so every other control is unchanged.
- `verify_firebase_id_token()` imports `firebase-admin` lazily and only with `FM_FIREBASE_PROJECT_ID`; otherwise it raises
  `FirebaseNotConfigured`. Credentials come from Application Default Credentials outside the repository; never commit a
  service-account key (the secret scan fails on one).
- `FirestoreAuditMirror` / `sync_audit_mirror()` copy committed `audit_log` rows (with hash-chain fields) to Firestore
  for off-site retention. `FM_AUDIT_MIRROR=firestore` selects it; the default is a no-op. Nothing schedules the sync yet;
  Postgres remains the system of record.

## 6. Environment variables added in v3 appsec

`FM_SESSION_MAX_AGE_S` (86400), `FM_SESSION_CHECK_TTL_S` (5), `FM_DATA_KEYS`, `FM_DATA_KEY_ACTIVE`, `FM_AUTH_PROVIDER`
(local), `FM_FIREBASE_PROJECT_ID`, `FM_AUDIT_MIRROR` (off). All optional; not added to the frozen `.env.example`.
