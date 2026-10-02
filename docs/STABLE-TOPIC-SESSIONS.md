# Stable topic sessions

Topic sessions that survive renames. A topic's session is keyed by a stable
**conversation id** held in a small sqlite registry, so renaming a topic
retitles the conversation instead of stranding the session. `/new` is the
only way to start a fresh session in a topic.

Tracking: issue #185 · PR #187.

## Why

Session keys embed the topic name (`…:zulip:stream:<stream_id>:<topic_name>`),
and Zulip topics have no ids (zulip/zulip#1191 — the subject is a shared
string; a rename rewrites it). A rename therefore looked identical to "a new
topic appeared": the old session was stranded and a fresh one started. Every
other platform retitles the thread on rename; users expect the same here.

## Design

The plugin mints a `conversation_id` (`c` + 12 hex) per topic conversation in
a persisted registry (sqlite, per bot account — same pattern as the dedupe
store). The topic name becomes display-only; sessions key on the
conversation. No gateway core changes: stream messages set
`thread_id = conversation_id`, and the core keys the session on `thread_id`
opaquely.

### Registry schema (v7)

```sql
CREATE TABLE live_holders (            -- the one live conversation per topic name
  account_id     TEXT NOT NULL,
  channel_id     INTEGER NOT NULL,
  topic_name     TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  origin_name    TEXT NOT NULL,
  anchor_message_id INTEGER,
  updated_at     REAL NOT NULL,
  PRIMARY KEY (account_id, channel_id, topic_name)
);
CREATE UNIQUE INDEX idx_live_holders_conversation
  ON live_holders (account_id, channel_id, conversation_id);

CREATE TABLE former_holders (          -- every conversation that lost a name
  account_id      TEXT NOT NULL,
  channel_id      INTEGER NOT NULL,
  conversation_id TEXT NOT NULL,
  topic_name      TEXT,                -- NULL = orphaned (no beneficiary)
  origin_name     TEXT NOT NULL,
  last_topic      TEXT,                -- last known topic name (outbound fallback)
  freed_at        REAL NOT NULL,
  PRIMARY KEY (account_id, channel_id, conversation_id)
);

CREATE TABLE session_starts (          -- per-session start labels (v6)
  account_id      TEXT NOT NULL,
  channel_id      INTEGER NOT NULL,
  conversation_id TEXT NOT NULL,
  session_id      TEXT NOT NULL,
  started_in      TEXT NOT NULL,
  recorded_at     REAL NOT NULL,
  PRIMARY KEY (account_id, channel_id, session_id)
);
```

The unique index enforces the invariant that a conversation is live under at
most one topic name. A topic's session set = its live conversation + its
former conversations; `/continue` switches between them. A session belongs to
at most one topic at any instant, and a topic has exactly one live session;
every other session in its set is preserved as a former holder.

`origin_name` (set at mint, never renamed) is where the session was created;
membership (`topic_name` on the former-holder row) is the topic whose set it
belongs to and is carried along on renames. `session_starts` records, per
gateway session, the topic name it was created in (first write wins), so the
listing can label every generation with its own start rather than the
lineage's origin.

### Routing rules

| # | Situation | Behavior |
|---|---|---|
| R1 | Message in an unmapped topic | Mint a conversation; the session links to it. |
| R2 | Full rename (`change_all`, same channel) | Re-point the conversation to the new name; the session follows. The old name keeps a NULL-membership audit row, so a recreated old name cannot adopt the session. |
| R3 | Partial move / split (`change_one`, `change_later`) | No re-point: the source topic keeps its session; the moved name resolves fresh on its first message. |
| R4 | A previously used name is re-created | Fresh conversation — reuse never adopts a previous incarnation's sessions (they were inherited by the rename beneficiary or orphaned). |
| R5 | Full rename onto a name that already has a conversation (merge) | The renamer's session takes the name; the displaced conversation becomes a former member. The topic ends up with both — nothing is broken, `/continue` switches between them. |
| R6 | In-flight reply during a rename | Resolved at send time through the current mapping: a full rename delivers it to the new name, a split leaves it in the source topic. If the conversation was orphaned mid-reply, it lands on its last known topic name — never a ghost topic named like the id. |
| R7 | `/continue <session-id>` | Switch this topic to a session from its own set (created there or inherited via full rename/merge). Gateway session ids only — lineage ids are plumbing, never shown to users. Bare `/continue` does nothing. |
| R8 | Full cross-channel move (`change_all` + `new_stream_id`) | Out of scope: the old session is freed with no successor (orphaned) and the thread starts fresh in the new channel. |
| R9 | `/topic-sessions` | List every session in the topic's set (current marked, each former lineage's newest marked last), each labeled with the topic it was created in. Read-only for bindings. |
| R10 | Topic deleted | The whole set has no beneficiary and is orphaned — unreachable by `/continue` from any topic, including a recreated same-name topic (which starts fresh, R4). Any delete event on a mapped topic triggers verification against the channel's topic list, so a partial delete never orphans a living topic (fail-open if the check is unavailable). |

Merge chains: several topics merged into one by successive renames end up as
one live session under the final name plus a former holder per earlier
conversation — all preserved and switchable via `/continue` from the merged
topic.

### Commands

- `/new` — the only way to start a fresh session in a topic (core command).
- `/continue <session-id>` — switch which session this topic talks to.
- `/topic-sessions` — list the topic's sessions.

`/continue` vs the core's `/resume`: `/continue` answers *which session does
this topic talk to?* (topic-scoped, registry-based); `/resume` answers *which
session am I talking in?* (scoped to the session key, gateway store).

### Events

The adapter subscribes to `["message", "update_message", "delete_message"]`
through the host's `_extra_event_types` opt-in (#162/#181); a persisted queue
registered with an older set is discarded and re-registered at startup.
Renames arrive as `update_message` events and are classified by
`propagate_mode` (see R2/R3/R8). Event queues deliver events in increasing id
order, and each stream message resolves its conversation inline at dispatch —
so a rename later in the same batch cannot fork an earlier message onto a
fresh conversation.

### Migration

Upgrading (or enabling the feature) re-keys existing name-keyed stream
sessions to conversation-id keys in a one-time pass and seeds the registry
with the same mapping. Transcripts are untouched — the session id does not
change, only its routing key — so current sessions survive the upgrade.
Legacy key tails are parsed shape-aware: per-user suffixes (email-shaped
trailing segment) are preserved; already-conversation-keyed heads are
recognized only when the registry knows that conversation; id-shaped names
the registry does not know are topics literally named like an id and migrate
normally; email-shaped heads (feature-off legacy keys) are left in place
rather than re-keyed under a junk topic.

The schema is versioned (`PRAGMA user_version`, currently v7): v5/v6
databases upgrade in place (`ALTER TABLE … RENAME TO`, metadata only, not a
row touched); pre-release dev shapes are rebuilt once.

### Tests

`tests/test_stable_topic_sessions.py` — 89 tests covering R1–R10 end to end:
rename continuity, label reuse, splits, in-flight rename, inheritance-scoped
`/continue` (bare no-op, foreign/orphaned rejection), cross-channel full vs
partial moves, deletion orphaning, id-shaped topic names, legacy key-tail
shapes, outbound last-known-name fallback, per-session start labels, and
migration idempotency incl. the v5→v7 / v6→v7 in-place upgrades. Full suite:
1305 cases, green.

### Known tradeoffs

- Session-key readability: dashboard/session labels show the opaque
  conversation id as the thread segment (the stream name is still shown). A
  core display hook could restore pretty names later (out of scope).
- Events arrive only for channels the bot is subscribed to — same limitation
  as message events today.
- Registry wiped manually: conversations fall back to name-keyed behavior.
- Unobserved topic deletion (missed events, e.g. the bot was offline): the
  stale mapping continues the old session instead of starting fresh; `/new`
  in the recreated topic starts a fresh session.
