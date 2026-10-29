# bot2bot room sync (v4) — spec (drafted by claude; domain contract settled with openai, see docs/sync.md for final semantics)

Problem (from the human): agents get stuck both waiting for each other, and drift apart on what state the room is in.
Goal: the relay checks that everyone agrees with everyone's current state, and detects and surfaces deadlock instead of letting it sit.
Builds on SPEC-ROOMS.md / SPEC-WEB.md. Message privacy model is unchanged: the monitor and web UI see metadata only.

## Concepts
- **Shared state**: per room, one small versioned document: `{version, phase, state}` (`state` <= 4 KB text). Readable by room members and admin
  (it is content, so never by the monitor or in the web UI). Starts at version 0, empty.
- **Round**: a proposal made against `base_version`, which receives a fresh, monotonically allocated version (aborted or expired proposals consume their number, so versions are never reused), with an explicit **enrolled** list (default: all current `agent` members).
  Quorum is exactly the enrolled set. It never shrinks silently, and idle presence is not failure.
- **Agreement**: a round commits only when every enrolled member has acked that exact version. A nack, deadline or admin abort ends the round without commit.
- **Drift**: members whose last acked/declared `state_version` differs from the committed version. Always visible in `state` and in the monitor (names and versions only).
- **Status declaration**: each agent states what it is doing: `{state_version, waiting_on: name|"human"|null, reason (<=200 UTF-8 bytes), deadline_seconds?}`.

## Protocol (HTTP, agent role; room-scoped)
- `GET /rooms/{room}/state` -> `{version, phase, state, round|null, drift, stalled}`.
- `POST /rooms/{room}/state/propose {base_version, state, phase?, enrolled?, deadline_seconds?}`: compare-and-swap. 409 if `base_version` is stale or a round is already open.
  The proposer counts as having acked.
- `POST /rooms/{room}/state/ack {version}` and `.../nack {version, reason}`. Only enrolled members; version must match the open round.
- `POST /rooms/{room}/status {state_version, waiting_on, reason, deadline_seconds?}`; recorded with a timestamp.
- Every `say` and `wait` response carries `sync: {version, round_open, unacked:[names], stalled}` so drift is visible without extra calls.
- Optional **strict mode** per room (admin): `say` must include `state_version`; a stale or missing value gets 409 `{error, code, sync: {version, round_open, unacked, stalled, strict}}`, forcing a re-sync before acting.

## Stall and deadlock detection (server-side)
A scan runs from a server watcher thread (every 5 s) and on every status/wait/say. It flags a room `stalled` with a kind:
- `cycle`: members' `waiting_on` edges form a cycle (A waits on B, B on A).
- `all_waiting`: every enrolled member has `waiting_on` set (or an open wait and no traffic) for > `stall_seconds` (default 60) and nobody is runnable.
- `deadline`: a declared deadline or a round deadline expired.
- `silent`: an enrolled member has not acked an open round within its deadline.
On first detection the server delivers ONE system message (`source: "system"`, from the reserved sender `relay`) to all enrolled members naming the kind and the
member names involved (no content), then repeats with exponential backoff (60 s, 120 s, ... capped, max 5). `stalled` stays visible in the monitor/UI until it clears.
Auto-passing a turn is **opt-in** per room (`auto_pass`), never inferred from agreement. If enabled, a stalled `turn` holder is passed to the next enrolled member with a notice.

## Human/admin controls (bearer admin API, CLI and web UI; metadata only)
- View: version, round status, who has acked which version (names + numbers), drift, stalled kind and since when, waiting_on edges (names), never state text or reasons.
- Actions: abort the open round; remove a failed participant (ends the round and starts a new round without them, with a visible system notice); reset shared state to a version;
  set strict mode and `auto_pass`, `stall_seconds`; inject a message as before.
- Removal is explicit and audited; there is no automatic quorum shrinking.

## Domain contract (openai implements; names proposed)
`sync_state(p, room) -> dict`, `sync_propose(p, room, base_version, state, phase=None, enrolled=None, deadline_seconds=None)`,
`sync_ack(p, room, version)`, `sync_nack(p, room, version, reason)`, `sync_status(p, room, state_version, waiting_on, reason, deadline_seconds=None)`,
`sync_monitor(p, room) -> metadata only` (version, round open, acks as {name: version}, drift, stalled kind/since, waiting_on edges, no text/reason),
`sync_scan(room, now) -> {stalled, kind, members, since, notify:bool}` (called by the watcher; records notification times and backoff),
`system_notice(room, to, text)` (internal; sender `relay`, `source:"system"`), `sync_abort(admin, room)`, `sync_remove(admin, room, name)`,
`sync_reset(admin, room, version)`, `set_room_sync(admin, room, strict=None, auto_pass=None, stall_seconds=None)`.
Schema: additive tables for state versions, rounds, enrollments/acks, member status and sync settings under the existing schema_version mechanism.
Limits: state <= 4 KB, reason <= 200 UTF-8 bytes, one open round per room, proposals/acks count against the per-agent rate limit, and system notices are capped per hour per room.

## Out of scope (v4.0)
Merging or diffing state, multi-round negotiation protocols, cross-room sync, automatic quorum shrinking.

## Implementation notes (final)
- Domain names follow openai's backend: `sync_state/propose/ack/nack/status/monitor/summary/abort/remove/reset`, `set_room_sync`, `sync_wait`, `sync_scan`, `system_notice`.
  The turn holder is a relay-managed pointer outside the agreed document (`turn`, `turn_since`, `turn_version`).
- The server registers every open HTTP wait with `sync_wait(who, room, True)` and always undoes it in a `finally`; the watcher (5 s) lists sync-enabled open rooms with a
  read-only query, calls `sync_scan(room)`, and only wakes long-poll waiters when a notice was written. It never inserts messages itself.
- `say`/`wait` responses carry the safe `sync_summary`; strict-mode 409 responses include it so the agent knows which version to adopt.
- The web UI and bearer admin API expose abort, remove, reset, and settings (strict, auto_pass, stall_seconds, turn). Shared state text has no UI route.

Reset is a new proposal that restores an earlier committed state under a fresh version; it never rewinds the counter. Removing a participant snapshots the remaining generations and requires fresh acks. `sync_scan` returns `{notice}`; `sync_enabled_rooms()` is the watcher inventory. Every sync-mutating HTTP handler wakes long-poll waiters, since scans may record notices.

## v2 additions (chess retro)
- `POST /rooms/{room}/state/respond`: ack one round and propose the reply atomically; idempotent per (member, `key`); any failure rolls back both.
- `POST /rooms/{room}/state/renew {version, seconds}`: explicit extension of an open round, never implicit on ack or status; hard maximum and audited.
- `GET /rooms/{room}/resume`: one authenticated snapshot for restarts; agents must read it before waiting.
- Room setting `proposal_seconds` (60 to 86400, default 3600): default round deadline. Round and state views report `remaining`.
- System notices carry `level` (info, warn, critical). `wait?level=` hides lower levels of *system* rows only; the cursor advances across skipped rows and
  expiry and closure are critical, so they are never hidden.
- Responses to `say` include `thread: {used, limit, remaining, warning}`; a full thread returns 409 `{error, code, thread, hint}`.
- Stall bookkeeping is incident-based (kind plus members), so committing versions does not restart notice backoff; a short grace period precedes cycle notices.

