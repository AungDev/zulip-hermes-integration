"""Stable conversation identity for Zulip topics (stable topic sessions).

Zulip topics have no IDs (zulip/zulip#1191): a topic is just the ``subject``
string shared by messages, and renaming bulk-rewrites it. This store mints an
opaque, stable ``conversation_id`` per conversation and tracks the mapping
``(channel_id, topic_name) -> conversation_id`` so Hermes sessions survive
topic renames.

Routing rules implemented here (see ISSUE.md in the project docs):

- R1 ``resolve``: unknown name -> mint a new conversation id (label reuse
  after a rename therefore starts a NEW conversation).
- R2 ``repoint``: full rename (``propagate_mode=change_all``) moves the
  conversation to the new name; the old name keeps only a NULL-membership
  audit row (no beneficiary — a recreated old name cannot adopt it).
- R3: partial moves (``change_one``/``change_later``, any channel) are NOT
  registry operations — the caller simply does not call this store for
  them; the source topic keeps its session and the new name resolves to a
  new conversation on its first message.
- R5 collisions: renaming onto a live name displaces the previous mapping
  into the target topic's own session set (a former member) so the renamed
  conversation takes the name.
- R7 ``rebind``: manual ``/continue <session-id>`` re-binds a topic to a
  FORMER member of its own session set (inheritance-scoped: own sessions
  plus full-rename/merge inheritance; never a session held elsewhere or
  orphaned).
- R8 ``free``: full cross-channel moves free the old mapping without a
  successor — the session set has no beneficiary and is orphaned.
- R9 ``sessions_for_topic``: the topic's session set for ``/topic-sessions``.
- R10 ``orphan_topic_sessions``: a topic deleted without rename/merge has
  no beneficiary — its whole session set is orphaned (membership NULL).

Former-session records power ``/continue`` and make label-reuse
disambiguation auditable.
"""

import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


def _session_created_at(session_id: str) -> Optional[float]:
    """Epoch seconds parsed from a gateway session id, if shaped like one.

    Gateway session ids embed their creation time (``YYYYMMDD_HHMMSS_hex``).
    Returns ``None`` for ids that do not match the shape.
    """
    try:
        date_part, time_part, _rest = str(session_id).split("_", 2)
        stamp = datetime.strptime(f"{date_part}_{time_part}", "%Y%m%d_%H%M%S")
    except (ValueError, AttributeError):
        return None
    return stamp.replace(tzinfo=timezone.utc).timestamp()


def _new_conversation_id() -> str:
    """Opaque, stable conversation token (``c`` + 12 hex chars)."""
    return "c" + uuid.uuid4().hex[:12]


class TopicConversationRegistry:
    """Persistent (channel_id, topic_name) -> conversation_id registry."""

    def __init__(self, account_id: str, data_dir: str):
        self.account_id = account_id
        self._data_dir = Path(data_dir).expanduser()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self._persistence_path(),
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        try:
            self._persistence_path().chmod(0o600)
        except OSError:
            pass

    def _persistence_path(self) -> Path:
        safe_id = "".join(c if c.isalnum() else "_" for c in self.account_id)
        return self._data_dir / f"zulip_conversations_{safe_id}.db"

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            # Schema v4: tombstone membership (topic_name) becomes nullable.
            # NULL = ORPHANED — the session set has no beneficiary (topic
            # deleted without rename, cross-channel move) and is unreachable
            # by /continue from any topic, per the inheritance model: a
            # topic only owns sessions it created or received via full
            # rename (merge). v3 added origin_name to both tables; v2 the
            # per-conversation tombstone key and the topic/session unique
            # index.
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version < 5:
                self._conn.execute("DROP TABLE IF EXISTS topic_map")
                self._conn.execute("DROP TABLE IF EXISTS tombstones")
                self._conn.execute("PRAGMA user_version = 5")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS topic_map (
                  account_id      TEXT NOT NULL,
                  channel_id      INTEGER NOT NULL,
                  topic_name      TEXT NOT NULL,
                  conversation_id TEXT NOT NULL,
                  origin_name     TEXT NOT NULL,
                  anchor_message_id INTEGER,
                  updated_at      REAL NOT NULL,
                  PRIMARY KEY (account_id, channel_id, topic_name)
                )
                """
            )
            self._conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_topic_map_conversation
                  ON topic_map (account_id, channel_id, conversation_id)
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tombstones (
                  account_id      TEXT NOT NULL,
                  channel_id      INTEGER NOT NULL,
                  conversation_id TEXT NOT NULL,
                  topic_name      TEXT,
                  origin_name     TEXT NOT NULL,
                  last_topic      TEXT,
                  freed_at        REAL NOT NULL,
                  PRIMARY KEY (account_id, channel_id, conversation_id)
                )
                """
            )
            # v6 (additive for v5): per-session start labels — the topic
            # name where each gateway session was created. The listing
            # labels every session with its own start rather than the
            # lineage's origin (which only matches until the first rename
            # between generations). Missing records fall back to the
            # lineage origin, so existing data keeps working.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_starts (
                  account_id      TEXT NOT NULL,
                  channel_id      INTEGER NOT NULL,
                  conversation_id TEXT NOT NULL,
                  session_id      TEXT NOT NULL,
                  started_in      TEXT NOT NULL,
                  recorded_at     REAL NOT NULL,
                  PRIMARY KEY (account_id, channel_id, session_id)
                )
                """
            )
            if version < 6:
                self._conn.execute("PRAGMA user_version = 6")

    # -- R1 ----------------------------------------------------------------

    def resolve(
        self,
        channel_id: int,
        topic_name: str,
        anchor_message_id: Optional[int] = None,
    ) -> str:
        """Return the conversation id for a topic name, minting one (R1).

        Label reuse after a rename starts a NEW conversation: minting
        never adopts a previous incarnation's sessions (they were
        inherited by the rename beneficiary or orphaned).
        """

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT conversation_id FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            ).fetchone()
            if row is not None:
                return str(row[0])

            conversation_id = _new_conversation_id()
            # NOTE: no tombstone purge here — none is needed. Tombstone
            # membership follows the beneficiary of a rename (or is NULL
            # for orphaned sessions), never the freed name, so a reused
            # label cannot accidentally adopt a previous lineage: under
            # the inheritance model the reused name simply starts a fresh
            # conversation (R4).
            self._conn.execute(
                "INSERT INTO topic_map"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  origin_name, anchor_message_id, updated_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    self.account_id,
                    channel_id,
                    topic_name,
                    conversation_id,
                    topic_name,
                    anchor_message_id,
                    time.time(),
                ),
            )
            logger.debug(
                "zulip conversation minted [channel=%s conv=%s]",
                channel_id,
                conversation_id,
            )
            return conversation_id

    # -- R2 / R5 -----------------------------------------------------------

    def repoint(self, channel_id: int, old_name: str, new_name: str) -> Optional[str]:
        """Full rename (R2): move the conversation to ``new_name``.

        The conversation (and its former-session set) is inherited by the
        beneficiary ``new_name``; ``old_name`` keeps only a
        NULL-membership audit row (no beneficiary — a recreated old name
        cannot adopt the session). If ``new_name`` was mapped to a
        different conversation, that mapping is displaced into the
        target's own session set (a former member, R5). Returns the
        conversation id, or None when ``old_name`` is unmapped (nothing
        to re-point).
        """

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT conversation_id, anchor_message_id, origin_name"
                " FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, old_name),
            ).fetchone()
            if row is None:
                return None
            conversation_id = str(row[0])
            anchor_message_id = row[1]
            origin_name = str(row[2])
            now = time.time()

            # Carry the topic's former sessions along with the rename:
            # tombstones tagged with the old name keep belonging to this
            # topic under its new name (origin_name is never renamed).
            self._conn.execute(
                "UPDATE tombstones SET topic_name=?"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (new_name, self.account_id, channel_id, old_name),
            )

            # Displace any live mapping under the new name (R5).
            displaced = self._conn.execute(
                "SELECT conversation_id, origin_name FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, new_name),
            ).fetchone()
            if displaced is not None and str(displaced[0]) != conversation_id:
                self._conn.execute(
                    "DELETE FROM topic_map"
                    " WHERE account_id=? AND channel_id=? AND topic_name=?",
                    (self.account_id, channel_id, new_name),
                )
                self._conn.execute(
                    "INSERT OR REPLACE INTO tombstones"
                    " (account_id, channel_id, topic_name, conversation_id,"
                    "  origin_name, last_topic, freed_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (
                        self.account_id,
                        channel_id,
                        new_name,
                        str(displaced[0]),
                        str(displaced[1]),
                        # The displaced conversation last lived at the
                        # TARGET name — where it was pushed out of — not
                        # at its birth topic (origin_name).
                        new_name,
                        now,
                    ),
                )

            # Free the old name. The conversation itself now belongs to the
            # beneficiary (the new name, by full-rename inheritance), so its
            # old-name record is kept as a NULL-membership audit row: it
            # must never become a /continue candidate for a recreated
            # old-name topic (a held session cannot be taken).
            self._conn.execute(
                "DELETE FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, old_name),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO tombstones"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  origin_name, last_topic, freed_at) VALUES (?,?,NULL,?,?,?,?)",
                (
                    self.account_id,
                    channel_id,
                    conversation_id,
                    origin_name,
                    # The rename source is this conversation's LAST known
                    # name before it moved to the beneficiary's name.
                    old_name,
                    now,
                ),
            )
            # Map the new name to the same conversation, preserving the
            # conversation's anchor message id and origin.
            self._conn.execute(
                "INSERT OR REPLACE INTO topic_map"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  origin_name, anchor_message_id, updated_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    self.account_id,
                    channel_id,
                    new_name,
                    conversation_id,
                    origin_name,
                    anchor_message_id,
                    now,
                ),
            )
            return conversation_id

    # -- R6 ----------------------------------------------------------------

    def current_name(self, channel_id: int, conversation_id: str) -> Optional[str]:
        """Current topic name for a conversation id (outbound routing, R6).

        Returns None when the id is not a known conversation (legacy
        name-keyed sessions fall back to using it verbatim).
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT topic_name FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                (self.account_id, channel_id, conversation_id),
            ).fetchone()
            return str(row[0]) if row is not None else None

    # -- R7 ----------------------------------------------------------------

    def lookup(self, channel_id: int, topic_name: str) -> Optional[str]:
        """Read-only mapping check: conversation id for a topic name, or None.

        Unlike :meth:`resolve`, never mints or writes.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT conversation_id FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            ).fetchone()
            return str(row[0]) if row is not None else None

    def last_topic_of(self, channel_id: int, conversation_id: str) -> Optional[str]:
        """The conversation's LAST known topic name (NULL when unknown).

        Read from the conversation's own tombstone row — written at every
        rebind/repoint and at orphan/free time, so it reflects the topic
        the conversation most recently lived in. Used by outbound routing
        when the conversation is no longer live (R8/R10 orphan): the
        in-flight reply lands on the topic where the conversation was last
        seen instead of materializing a ghost topic named like the id.
        """

        with self._lock:
            row = self._conn.execute(
                "SELECT last_topic FROM tombstones"
                " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                (self.account_id, channel_id, conversation_id),
            ).fetchone()
            return str(row[0]) if row is not None and row[0] is not None else None

    def has_conversation(self, channel_id: int, conversation_id: str) -> bool:
        """Whether a conversation id is known to this registry — live
        (topic_map) or recorded as a former/orphaned row (tombstones).

        Used by the upgrade migration to tell an already-migrated
        conv-keyed session key from a legacy name-keyed key whose topic
        NAME happens to match the conversation-id format.
        """

        with self._lock:
            for table in ("topic_map", "tombstones"):
                row = self._conn.execute(
                    f"SELECT 1 FROM {table}"
                    " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                    (self.account_id, channel_id, conversation_id),
                ).fetchone()
                if row is not None:
                    return True
            return False

    def rebind(self, channel_id: int, topic_name: str, conversation_id: str) -> None:
        """Manual re-bind (R7, ``/continue``): map a topic to a conversation.

        A conversation belongs to at most one topic, so a re-bind is a
        MOVE: if the conversation is live under another name in this
        channel, it departs from there (that topic keeps it as a former
        session). Any live mapping displaced at the target name becomes a
        former member of the topic's own set, and the conversation's
        former-member record here is consumed on arrival.
        """

        with self._lock, self._conn:
            now = time.time()

            # Remember the conversation's origin: from its live row, or
            # from its tombstone if it is currently detached.
            live = self._conn.execute(
                "SELECT topic_name, origin_name FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                (self.account_id, channel_id, conversation_id),
            ).fetchone()
            if live is not None:
                origin_name = str(live[1])
            else:
                trow = self._conn.execute(
                    "SELECT origin_name FROM tombstones"
                    " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                    (self.account_id, channel_id, conversation_id),
                ).fetchone()
                origin_name = str(trow[0]) if trow is not None else topic_name

            # Displace any live mapping at the target name (R5).
            displaced = self._conn.execute(
                "SELECT conversation_id, origin_name FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            ).fetchone()
            if displaced is not None and str(displaced[0]) != conversation_id:
                self._conn.execute(
                    "DELETE FROM topic_map"
                    " WHERE account_id=? AND channel_id=? AND topic_name=?",
                    (self.account_id, channel_id, topic_name),
                )
                self._conn.execute(
                    "INSERT OR REPLACE INTO tombstones"
                    " (account_id, channel_id, topic_name, conversation_id,"
                    "  origin_name, last_topic, freed_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (
                        self.account_id,
                        channel_id,
                        topic_name,
                        str(displaced[0]),
                        str(displaced[1]),
                        # The displaced conversation last lived at the
                        # TARGET name — where it was pushed out of — not
                        # at its birth topic (origin_name).
                        topic_name,
                        now,
                    ),
                )

            # Move out of any other live topic (the session belongs to
            # exactly one topic at a time). The departed topic keeps the
            # conversation as a tombstoned former session.
            other_name: Optional[str] = None
            if live is not None and str(live[0]) != topic_name:
                other_name = str(live[0])
                self._conn.execute(
                    "DELETE FROM topic_map"
                    " WHERE account_id=? AND channel_id=? AND topic_name=?"
                    "   AND conversation_id=?",
                    (self.account_id, channel_id, other_name, conversation_id),
                )

            # Consume the conversation's tombstones (it is live again).
            self._conn.execute(
                "DELETE FROM tombstones"
                " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                (self.account_id, channel_id, conversation_id),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO topic_map"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  origin_name, anchor_message_id, updated_at)"
                " VALUES (?,?,?,?,?,NULL,?)",
                (
                    self.account_id,
                    channel_id,
                    topic_name,
                    conversation_id,
                    origin_name,
                    now,
                ),
            )
            # Written after the consumption above so the move-tombstone
            # itself survives.
            if other_name is not None:
                self._conn.execute(
                    "INSERT OR REPLACE INTO tombstones"
                    " (account_id, channel_id, topic_name, conversation_id,"
                    "  origin_name, last_topic, freed_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (
                        self.account_id,
                        channel_id,
                        other_name,
                        conversation_id,
                        origin_name,
                        # Rebind moved the conversation OUT of other_name:
                        # that is its last known name.
                        other_name,
                        now,
                    ),
                )

    def sessions_for_topic(
        self, channel_id: int, topic_name: str
    ) -> Tuple[Optional[str], Optional[str], List[Tuple[str, str]]]:
        """The topic's session set for the ``/topic-sessions`` listing (read-only).

        Returns ``(current_id, current_origin, members)`` where members are
        the tombstoned former sessions of this topic,
        ``[(conversation_id, origin_name), ...]``, most recent first.
        ``origin_name`` is the topic where the session was created and is
        never renamed; ``topic_name`` tracks membership and is carried
        along on renames (R2).
        """

        with self._lock:
            row = self._conn.execute(
                "SELECT conversation_id, origin_name FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            ).fetchone()
            current = (str(row[0]), str(row[1])) if row is not None else None
            members = [
                (str(r[0]), str(r[1]))
                for r in self._conn.execute(
                    "SELECT conversation_id, origin_name FROM tombstones"
                    " WHERE account_id=? AND channel_id=? AND topic_name=?"
                    " ORDER BY freed_at DESC, rowid DESC",
                    (self.account_id, channel_id, topic_name),
                ).fetchall()
            ]
            return (
                current[0] if current else None,
                current[1] if current else None,
                members,
            )

    # -- R10 (deletion / orphaning) -----------------------------------------

    def iter_conversations(self) -> List[Tuple[int, str]]:
        """Every live conversation as ``(channel_id, conversation_id)``."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT channel_id, conversation_id FROM topic_map"
                " WHERE account_id=?",
                (self.account_id,),
            ).fetchall()
        return [(int(r[0]), str(r[1])) for r in rows]

    # -- session start labels (v6) -----------------------------------------

    def record_session_start(
        self,
        channel_id: int,
        conversation_id: str,
        session_id: str,
        started_in: Optional[str] = None,
    ) -> None:
        """Record where a gateway session started (INSERT OR IGNORE).

        First record wins — a session is never relabeled after the fact.
        ``started_in`` defaults to the derived start (see
        :meth:`derive_session_start`); nothing is written when no label
        can be determined.
        """
        if started_in is None:
            started_in = self.derive_session_start(
                channel_id, conversation_id, session_id
            )
        if not started_in:
            return
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO session_starts"
                " (account_id, channel_id, conversation_id, session_id,"
                "  started_in, recorded_at)"
                " VALUES (?,?,?,?,?,?)",
                (
                    self.account_id,
                    channel_id,
                    conversation_id,
                    session_id,
                    started_in,
                    time.time(),
                ),
            )

    def session_start(
        self, channel_id: int, session_id: str
    ) -> Optional[str]:
        """The recorded start label for a gateway session, if any."""
        with self._lock:
            row = self._conn.execute(
                "SELECT started_in FROM session_starts"
                " WHERE account_id=? AND channel_id=? AND session_id=?",
                (self.account_id, channel_id, session_id),
            ).fetchone()
        return str(row[0]) if row is not None else None

    def derive_session_start(
        self, channel_id: int, conversation_id: str, session_id: str
    ) -> Optional[str]:
        """Best-effort start label for a session with no record yet.

        The gateway session id embeds its creation time. If the session
        was created after the conversation's last mapping change
        (``updated_at`` moves only on mapping writes: mint, rename,
        merge), it must have been created under the current name;
        otherwise it predates every tracked change and the lineage origin
        is the best available label. Pre-tracking history is not
        recoverable for anyone — a one-time approximation for sessions
        minted before the labels existed.
        """
        created = _session_created_at(session_id)
        with self._lock:
            row = self._conn.execute(
                "SELECT topic_name, origin_name, updated_at FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                (self.account_id, channel_id, conversation_id),
            ).fetchone()
            if row is None:
                tomb = self._conn.execute(
                    "SELECT origin_name FROM tombstones"
                    " WHERE account_id=? AND channel_id=? AND"
                    " conversation_id=?",
                    (self.account_id, channel_id, conversation_id),
                ).fetchone()
                return str(tomb[0]) if tomb is not None else None
        topic_name, origin_name, updated_at = (
            str(row[0]),
            str(row[1]),
            float(row[2]),
        )
        if created is not None and created > updated_at:
            return topic_name
        return origin_name

    def orphan_topic_sessions(self, channel_id: int, topic_name: str) -> int:
        """Topic deleted without rename/merge (R10): no beneficiary.

        Removes the live mapping WITHOUT a successor tombstone and marks
        every former-session tombstone of this topic orphaned
        (``topic_name = NULL``). The orphaned live conversation itself is
        recorded as an orphaned row (membership NULL, origin preserved),
        so it stays auditable and the upgrade migration can still
        recognize its conv-keyed session key. Orphaned sessions are
        unreachable by ``/continue`` from any topic — including a
        recreated same-name topic, which starts a fresh lineage (R4).
        Rows are kept, never deleted. Returns the number of orphaned
        former-session rows (the conversation's own audit row excluded).
        """

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT conversation_id, origin_name FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            ).fetchone()
            self._conn.execute(
                "DELETE FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            )
            cur = self._conn.execute(
                "UPDATE tombstones SET topic_name=NULL, last_topic=?"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (topic_name, self.account_id, channel_id, topic_name),
            )
            if row is not None:
                # Audit row for the orphaned conversation itself (NULL
                # membership): keeps the conversation traceable after the
                # mapping is gone. The topic it was deleted FROM is its
                # last known name.
                self._conn.execute(
                    "INSERT OR REPLACE INTO tombstones"
                    " (account_id, channel_id, topic_name, conversation_id,"
                    "  origin_name, last_topic, freed_at) VALUES (?,?,NULL,?,?,?,?)",
                    (
                        self.account_id,
                        channel_id,
                        str(row[0]),
                        str(row[1]),
                        topic_name,
                        time.time(),
                    ),
                )
            return int(cur.rowcount or 0)

    # -- R8 ----------------------------------------------------------------

    def free(self, channel_id: int, topic_name: str) -> Optional[str]:
        """Remove a mapping (cross-channel move, R8).

        The moved topic's session set has no beneficiary — the destination
        is a different topic (same name in another channel) and sessions
        never cross channels — so the conversation is ORPHANED rather than
        tombstoned into any topic's former set: unreachable by /continue,
        retained as audit rows. Returns the conversation id, or None when
        nothing was mapped.
        """

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT conversation_id, origin_name FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            ).fetchone()
            if row is None:
                return None
            conversation_id = str(row[0])
            origin_name = str(row[1])  # birth-topic name (label only)
            # topic_name (the freed topic) IS the conversation's last
            # known name here — no extra read needed.
            self._conn.execute(
                "DELETE FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            )
            # Orphan the conversation's tombstone rows (no beneficiary).
            self._conn.execute(
                "UPDATE tombstones SET topic_name=NULL, last_topic=?"
                " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                (topic_name, self.account_id, channel_id, conversation_id),
            )
            # Audit row for the orphaned conversation itself (NULL
            # membership): keeps it traceable after the mapping is gone.
            # The topic it was freed FROM is its last known name.
            self._conn.execute(
                "INSERT OR REPLACE INTO tombstones"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  origin_name, last_topic, freed_at) VALUES (?,?,NULL,?,?,?,?)",
                (self.account_id, channel_id, conversation_id, origin_name,
                 topic_name, time.time()),
            )
            return conversation_id
