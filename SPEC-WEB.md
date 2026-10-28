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
- Every cookie-authenticated mutation (POST) requires: header `X-CSRF` equal to the session's CSRF token (constant-time), `Origin` equal to the
  configured public origin exactly, `Content-Type: application/json`. Applies to logout and logout-all as well.
- `Host` must match the public origin's host. Configure with `serve --public-origin http://host:port` (default `http://127.0.0.1:<port>`).
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

## Domain contract (openai implements)
Session id and CSRF token are random 256-bit values; only SHA-256 digests are stored. Plaintext is returned once.
- `create_session(admin_principal, token_hash, peer) -> {session_id, csrf, expires}`; binds admin name + credential hash.
- `validate_session(session_id) -> {principal, csrf_digest, expires}|None` — checks digest, idle and absolute expiry, admin still active, credential hash
  unchanged; touches `last_seen` at most once per 60 s.
- `check_csrf(session_id, csrf) -> bool` constant-time compare of digests.
- `revoke_session(session_id)`, `revoke_all_sessions(admin_principal)`, `purge_sessions()` (expired rows).
- `login_allowed(peer) -> retry_after_seconds (0 = allowed)`, `login_failed(peer)`, `login_succeeded(peer)` (persisted counters).
- Returned principal is `{name, role:'admin', room:None, generation:1}`, the same as bearer admin; the server enforces the cookie allowlist.
- Schema upgrade: additive `sessions` and `login_attempts` tables under the existing schema_version mechanism.

## Browser contract (claude implements)
- Pages (single page, hash routing): Login; Rooms (status, members, active, last activity, create); Room (members + presence, live metadata feed,
  stats, inject, close/reopen, revoke/rotate, reset thread). Newly created/rotated tokens appear once in a dismissible panel with a copy button.
- Polling only: feed every 2 s via `monitor?after=ID`; presence every 5 s. After inject the UI shows only the metadata row.
- On 401 the UI returns to Login; on 403 shows a generic error; 429 shows Retry-After.

## Tests
Domain: expiry (idle/absolute), no sliding absolute, admin revoke/rotate kills sessions, digests only, throttle persistence, purge.
Server: CSRF missing/wrong, wrong Origin/Host, wrong content-type, cookie on content/bearer routes, allowlist, static traversal, headers/CSP,
login throttle, logout-all, no message text in any `/ui/api` response.

## Out of scope (v3.0)
Multi-admin roles, TLS termination, WebSocket/SSE push, content viewing in the UI, pause/resume buttons (CLI/bearer only).
