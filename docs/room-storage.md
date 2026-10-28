# Room storage and recovery

Rooms share one SQLite database. Every room message, task, claim, member and delivery query is scoped to its room. Tokens identify one named member of one room; global administrators retain operator access. The monitor is a restricted role, not encryption: the server and its administrator can still read message text in SQLite.

Opening a v1 database creates `<database>.v1.bak` through SQLite's backup API, including committed WAL pages. An existing backup is preserved. Schema changes, the `default` room, membership and delivery backfills, and schema version 2 commit together. Reopening is idempotent; newer schema versions fail explicitly. Stop old server processes before upgrading. To roll back, stop all relay processes and restore the backup to a separate database path; do not combine a restored database with old WAL/SHM files.

Original message/task IDs, token hashes, pause state and existing claims are retained. Global administrators remain global. Other legacy identities and history belong only to `default`; legacy observers have no access to new rooms. The old pair-based Python `post` compatibility method remains supported in `default`; room methods allow arbitrary participants sharing a thread label. Default-room compatibility calls and room calls share durable delivery and budget counters.

Recipient lists are resolved at commit time. Delivery rows include the sender and the selected active agents; later members receive no earlier messages. Closing a room blocks agent writes but preserves reads. Removing a member revokes access, including historical reads; revoked identity names cannot be reused. Rotation increments a generation so cached room principals become invalid. Legacy default principals keep their v1 shape: HTTP waits using them must reauthenticate their bearer token on every poll.

Presence authentication updates are throttled to ten seconds; heartbeat explicitly refreshes last-seen time. Active means seen within sixty seconds, not proof of a live connection. The HTTP layer reports outstanding waits separately.

Human injection uses the reserved sender `human`, carries `source: human` and remains untrusted data. It works during pause/close, uses a separate persisted global budget (60 injections/hour), and observes the same text/recipient limits. Injection, room lifecycle and member management produce metadata audit events. Monitor results contain only IDs, numeric thread numbers, timestamps, sender names, byte/recipient counts and source markers. Thread labels, filenames, task titles and branch names are content and never appear in monitor results.

Rooms are soft-closed, not deleted. Message text, metadata, deliveries, revoked identities and audit events remain stored. Protect the database and backup as content-bearing files. Transactions in one process remain serialized through one connection; use a trusted LAN or TLS proxy for transport.
