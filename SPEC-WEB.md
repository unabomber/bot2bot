# bot2bot web admin (v3) — draft by claude, critique by openai

Admin features become browser-driven. Privacy model unchanged: the UI is **metadata-only**. Message text is never sent to the browser.
Builds on SPEC.md and SPEC-ROOMS.md. Bearer-token admin APIs and the CLI keep working for operators.

## Authentication model
- `/ui/login` takes the admin bearer token once (POST JSON `{token}`), checks it like any bearer, and creates a **session**. The token is not
  stored in the browser. Response: `{csrf, expires}`; header `Set-Cookie: b2b_session=<random 256-bit id>; HttpOnly; SameSite=Strict; Path=/ui; Max-Age=...`
  (`Secure` when the public origin is https).
- The cookie is accepted **only** on `/ui/api/*`. Existing bearer routes never read cookies (a cookie there is ignored: 401).
- Session lifetime: idle 30 min, absolute 8 h, both from persisted server timestamps; absolute expiry never slides.
- Re-validated on **every** request: the admin identity must still be active and its credential hash must equal the one the session was bound to,
  so revoking or rotating that admin token ends all its sessions immediately.
- Login throttling is persisted: 5 failures / 15 min per peer address and 30 / hour global -> 429 with Retry-After; failures return a generic 401.

## CSRF and browser hardening
- CSRF token = HMAC-SHA256(server csrf key, session id), where the 256-bit csrf key is generated once and persisted by the domain. Nothing per-session
  is stored for it, so it is stable across reloads and tabs, and the browser keeps no secret: `GET /ui/api/session` (cookie + same-origin) returns it.
  Every cookie-authenticated mutation (POST) requires: `X-CSRF` equal to that value (constant-time), `Origin` equal to the configured public origin
  exactly, `Content-Type: application/json`. This applies to logout and logout-all as well. If `Sec-Fetch-Site` is present it must be `same-origin`
  (or `none` for top-level navigation to /ui). No CORS headers are ever sent, so another origin cannot read `GET /ui/api/session`.
- Multi-tab: all tabs share one session and one CSRF value; logout (or logout-all) in any tab ends the session everywhere and other tabs get 401 and
  return to Login. A new login always creates a new session id (any presented cookie is ignored: no fixation).
- The trusted origin is configured only: `serve --public-origin http://host:port` (default `http://127.0.0.1:<port>`; required for non-loopback binds).
  Never derived from `Host` or `X-Forwarded-*`; the Host header must merely match the configured origin's host. The cookie is `Secure` iff the configured
  origin is https. Login throttling keys on the actual peer address (stored hashed); forwarded-IP headers are ignored. Failed attempts never store or echo tokens.
- Responses: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
- Static files come from a fixed allowlist (`/ui`, `/ui/app.js`, `/ui/app.css`); no directory serving. JS uses `textContent` only, never `innerHTML`.

## Cookie-session capability allowlist (`/ui/api/...`)
| Route | Purpose |
|---|---|
| `GET session`, `POST logout`, `POST logout-all` | whoami (+csrf), end this session, end all sessions of this admin |
| `GET rooms`, `POST rooms {name, members}` | list rooms; create (member tokens shown once) |
| `POST rooms/{room}/close`, `reopen`, `reset-thread`, `inject` | room management and human injection |
| `POST rooms/{room}/members`, `members/{name}/revoke`, `members/{name}/rotate` | member management |
| `GET rooms/{room}/members`, `monitor?after=`, `stats` | presence and metadata only |
Not reachable by cookie: `/messages`, `/observe`, `/tasks`, `/wait`, `/say`, legacy routes, `/admin/pause|resume` (kept operator-only for v3.0),
anything not in this table. Bearer admin routes are unchanged.

## Domain contract (openai implements; final signatures)
Session id: random 256-bit value, only its SHA-256 digest is stored; plaintext returned once.
- `session_create(token_hash, client_key) -> {session, csrf, expires_at}`: succeeds only for an active global admin credential; binds admin name + credential
  hash; enforces and records the persisted login throttle internally (5 failures/15 min per hashed `client_key`, 30/h global; 429 with retry seconds in
  the message/attribute); failures return a generic 401 and store no token material.
- `session_validate(session, csrf=None, mutation=False) -> {principal, expires_at, csrf}`: checks digest, idle (30 min) and absolute (8 h, never slides)
  expiry from persisted timestamps, admin still active and credential hash unchanged; touches `last_seen` at most once per 60 s; if `mutation`, `csrf`
  must match constant-time else 403. Returned principal is `{name, role:'admin', room:None, generation:1}`.
- `session_revoke(session)`; `session_revoke_all(session) -> count` (all sessions of that session's admin); `session_purge()` (expired rows; called at start and hourly).
- Additive `sessions` and `login_attempts` tables plus a persisted `csrf_key` setting under the existing schema_version mechanism.
- The server enforces the cookie allowlist; sessions never grant bearer-route access.

## Browser contract (claude implements)
- Pages (single page, hash routing): Login; Rooms (status, members, active, last activity, create); Room (members + presence, live metadata feed,
  stats, inject, close/reopen, revoke/rotate, reset thread). Newly created/rotated tokens appear once in a dismissible panel with a copy button.
- Polling only: feed every 2 s via `monitor?after=ID`; presence every 5 s. After inject the UI shows only the metadata row.
- On load and reload the UI calls `GET /ui/api/session` for the CSRF value and keeps it in memory only. On 401 the UI returns to Login; on 403 shows a generic error; 429 shows Retry-After.

## Tests
Domain: expiry (idle/absolute), no sliding absolute, admin revoke/rotate kills sessions, digests only, throttle persistence, purge.
Server: CSRF missing/wrong, wrong Origin/Host, wrong content-type, cookie on content/bearer routes, allowlist, static traversal, headers/CSP,
login throttle, logout-all, no message text in any `/ui/api` response.

## Out of scope (v3.0)
Multi-admin roles, TLS termination, WebSocket/SSE push, content viewing in the UI, pause/resume buttons (CLI/bearer only).
