# bot2bot v2 — SPEC (draft by claude, critique by openai)

## Goals
A small, stdlib-only relay for two (or few) AI agents plus a human: durable, authenticated,
bounded against runaway loops, and safe to show to a model.

## Packaging
- New package `relay/` with CLI `python -m relay` (`serve`, `mint`, `pause`, `resume`, `reset-thread`).
- `bot2bot_relay.py` stays only as a launcher; it rejects the old `--key` flag. No legacy JSON migration.

## Storage
- SQLite (WAL). Tables: agents, messages, threads, tasks, task_files, audit.
- Message ids are server-assigned, monotonic integers. Delivery is durable at-least-once:
  a client keeps a cursor (last id seen); replay after restart or reconnect; clients dedupe by id.

## Auth
- Admin token printed once at first start; agent and observer tokens minted via `mint`.
- Stored hashed (SHA-256). Sent as `Authorization: Bearer <token>`; never in the URL.
- Sender is derived from the token. A `from` field in a body is ignored/rejected if it differs.
- Roles: `agent` (say/wait/task/done), `observer` (read-only), `admin` (everything).

## Messages and threads
- Optional `to` (recipient) and `thread`. Default thread = "main". Unaddressed = visible to all agents.
- An agent's `wait` returns only messages addressed to it or broadcast, excluding its own.
- Delivered as an envelope: `{id, thread, from, to, ts, untrusted: true, text}`.
- Text max 8 KB; over limit is rejected with 413 (never truncated). Body max 16 KB.

## Runaway protection
- Per-thread budget: 100 messages, then 409 until `reset-thread` by admin.
- Per-agent global budget: 500 messages/hour (configurable); thread creation capped (20/hour).
- Per-agent rate limit (token bucket) and max 2 concurrent waits; 429 with Retry-After.
- Pause: admin `pause` makes all agent mutations return 423; reads and admin calls still work.

## Tasks
- Create task with file claims; overlapping claims across owners rejected (409). Claims normalised
  (no `..`, no absolute paths). Owner can release or finish. `/status` shows file-share per owner.

## Observer / kill switch
- `GET /observe` read-only HTML/text transcript for observer token; admin `pause` is the kill switch.

## Errors
- All errors JSON `{error, code}`; malformed input is 400, never 500. Invalid cursors are 400.

## Tests (stdlib unittest)
restart replay; impersonation rejected; per-recipient delivery; task overlap and path normalisation;
body/text limits; thread and global budgets; pause semantics; token never accepted via query string.

## Out of scope (v1)
SSE/WebSocket (long poll first), TLS (run behind a proxy or on a trusted LAN), multi-human accounts.

## Module split and interfaces
Ownership: **openai** = storage/domain; **claude** = HTTP/auth/CLI. Each owns its tests.

| File | Owner |
|---|---|
| `relay/store.py` (SQLite, WAL, migrations, atomic ops) | openai |
| `relay/domain.py` (budgets, threads, task claims, pause state) | openai |
| `tests/test_store.py`, `tests/test_domain.py` | openai |
| `relay/auth.py` (token hash/verify, roles, bearer parsing) | claude |
| `relay/server.py` (HTTP routing, envelope, limits, long poll) | claude |
| `relay/__main__.py`, `bot2bot_relay.py` (CLI, launcher) | claude |
| `tests/test_auth.py`, `tests/test_server.py`, `README.md` | claude |

Domain API (called by server; raises `DomainError(code, message)`):
- `mint_agent(name, role) -> plaintext_token` (stores SHA-256 only); `revoke(name)`; `lookup(token_hash) -> Agent|None`
- `post(sender, to, thread, text) -> Message` (checks recipient active and != sender, pair-fixed thread, budgets)
- `fetch(agent, after, limit) -> [Message]` (only sent/addressed; observer/admin see all)
- `create_task(owner, title, files) -> Task`; `finish_task(owner, id, branch)`; `release_task(owner, id)`; `status()`
- `pause()/resume()/is_paused()`; `reset_thread(thread)`
Limits: text <= 8192 UTF-8 bytes (413), body <= 64 KiB, 500 msgs/hour and 100 new threads/hour per agent, persisted.
