"""Stable conversation identity for Zulip topics (stable topic sessions).

Zulip topics have no IDs (zulip/zulip#1191): a topic is just the ``subject``
string shared by messages, and renaming bulk-rewrites it. This store mints an
opaque, stable ``conversation_id`` per conversation and tracks the mapping
``(channel_id, topic_name) -> conversation_id`` so Hermes sessions survive
topic renames.

Routing rules implemented here (see DESIGN.md in the project docs):

- R1 ``resolve``: unknown name -> mint a new conversation id (label reuse
  after a rename therefore starts a NEW conversation).
- R2 ``repoint``: full rename (``propagate_mode=change_all``) moves the
  conversation to the new name and frees the old name (tombstoned).
- R3: partial moves (``change_one``/``change_later``) are NOT registry
  operations — the caller simply does not call this store for them; the new
  name resolves to a new conversation on its first message.
- R5 collisions: renaming onto a live name displaces the previous mapping
  (tombstoned) so the renamed conversation takes the name.
- R7 ``rebind``: manual ``/continue`` re-binds a topic to a tombstoned
  conversation (consuming the tombstone).
- R8 ``free``: cross-channel moves free the old mapping without mapping a
  new one.

Tombstones power ``/continue`` and make label-reuse disambiguation auditable.
"""

import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


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
            # Schema v1: tombstones keyed per CONVERSATION (not per name) —
            # a name can be freed by different conversations over time
            # (merge chains, R5), and per-name keying silently overwrote
            # earlier tombstones, orphaning conversations beyond repair.
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version < 1:
                self._conn.execute("DROP TABLE IF EXISTS topic_map")
                self._conn.execute("DROP TABLE IF EXISTS tombstones")
                self._conn.execute("PRAGMA user_version = 1")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS topic_map (
                  account_id      TEXT NOT NULL,
                  channel_id      INTEGER NOT NULL,
                  topic_name      TEXT NOT NULL,
                  conversation_id TEXT NOT NULL,
                  anchor_message_id INTEGER,
                  updated_at      REAL NOT NULL,
                  PRIMARY KEY (account_id, channel_id, topic_name)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tombstones (
                  account_id      TEXT NOT NULL,
                  channel_id      INTEGER NOT NULL,
                  conversation_id TEXT NOT NULL,
                  topic_name      TEXT NOT NULL,
                  freed_at        REAL NOT NULL,
                  PRIMARY KEY (account_id, channel_id, conversation_id)
                )
                """
            )

    # -- R1 ----------------------------------------------------------------

    def resolve(
        self,
        channel_id: int,
        topic_name: str,
        anchor_message_id: Optional[int] = None,
    ) -> str:
        """Return the conversation id for a topic name, minting one (R1).

        Minting replaces any tombstone for the name: label reuse after a
        rename starts a NEW conversation.
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
            # NOTE: no tombstone purge here. A reused label keeps the old
            # conversation's tombstone so /continue (R7) can still re-bind
            # the reused name to it — an explicit human repair after R4.
            self._conn.execute(
                "INSERT INTO topic_map"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  anchor_message_id, updated_at) VALUES (?,?,?,?,?,?)",
                (
                    self.account_id,
                    channel_id,
                    topic_name,
                    conversation_id,
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

        Frees ``old_name`` (tombstoned). If ``new_name`` was mapped to a
        different conversation, that mapping is displaced (tombstoned, R5).
        Returns the conversation id, or None when ``old_name`` is unmapped
        (nothing to re-point).
        """

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT conversation_id, anchor_message_id FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, old_name),
            ).fetchone()
            if row is None:
                return None
            conversation_id = str(row[0])
            anchor_message_id = row[1]
            now = time.time()

            # Displace any live mapping under the new name (R5).
            displaced = self._conn.execute(
                "SELECT conversation_id FROM topic_map"
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
                    " (account_id, channel_id, topic_name, conversation_id, freed_at)"
                    " VALUES (?,?,?,?,?)",
                    (self.account_id, channel_id, new_name, str(displaced[0]), now),
                )

            # Free the old name, then map the new name.
            self._conn.execute(
                "DELETE FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, old_name),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO tombstones"
                " (account_id, channel_id, topic_name, conversation_id, freed_at)"
                " VALUES (?,?,?,?,?)",
                (self.account_id, channel_id, old_name, conversation_id, now),
            )
            # Map the new name to the same conversation, preserving the
            # conversation's anchor message id.
            self._conn.execute(
                "INSERT OR REPLACE INTO topic_map"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  anchor_message_id, updated_at) VALUES (?,?,?,?,?,?)",
                (
                    self.account_id,
                    channel_id,
                    new_name,
                    conversation_id,
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

    def latest_tombstone(
        self, channel_id: int, exclude_conversation: Optional[str] = None
    ) -> Optional[Tuple[str, str]]:
        """Most recently freed conversation in a channel: (id, old_name).

        ``exclude_conversation`` skips tombstones of a conversation the
        caller is already bound to. Needed for the R5 displacement case:
        the freshest tombstone there belongs to the *renaming* conversation
        (its freed old name) — a no-op candidate for ``/continue`` — while
        the displaced conversation sits right behind it.
        """
        with self._lock:
            # rowid DESC breaks same-tick freed_at ties deterministically
            # (later writes — e.g. the orig-name tombstone after a
            # displacement — sort first).
            if exclude_conversation is not None:
                row = self._conn.execute(
                    "SELECT conversation_id, topic_name FROM tombstones"
                    " WHERE account_id=? AND channel_id=? AND conversation_id != ?"
                    " ORDER BY freed_at DESC, rowid DESC LIMIT 1",
                    (self.account_id, channel_id, exclude_conversation),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT conversation_id, topic_name FROM tombstones"
                    " WHERE account_id=? AND channel_id=?"
                    " ORDER BY freed_at DESC, rowid DESC LIMIT 1",
                    (self.account_id, channel_id),
                ).fetchone()
            return (str(row[0]), str(row[1])) if row is not None else None

    def rebind(self, channel_id: int, topic_name: str, conversation_id: str) -> None:
        """Manual re-bind (R7, ``/continue``): map a topic to a conversation.

        Consumes the tombstone for this name. Any live mapping displaced by
        the re-bind is tombstoned first.
        """

        with self._lock, self._conn:
            now = time.time()
            displaced = self._conn.execute(
                "SELECT conversation_id FROM topic_map"
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
                    " (account_id, channel_id, topic_name, conversation_id, freed_at)"
                    " VALUES (?,?,?,?,?)",
                    (self.account_id, channel_id, topic_name, str(displaced[0]), now),
                )
            self._conn.execute(
                "INSERT OR REPLACE INTO topic_map"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  anchor_message_id, updated_at) VALUES (?,?,?,?,NULL,?)",
                (self.account_id, channel_id, topic_name, conversation_id, now),
            )
            self._conn.execute(
                "DELETE FROM tombstones"
                " WHERE account_id=? AND channel_id=? AND conversation_id=?",
                (self.account_id, channel_id, conversation_id),
            )

    # -- R8 ----------------------------------------------------------------

    def free(self, channel_id: int, topic_name: str) -> Optional[str]:
        """Remove a mapping, tombstoning it (cross-channel move, R8)."""

        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT conversation_id FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            ).fetchone()
            if row is None:
                return None
            conversation_id = str(row[0])
            self._conn.execute(
                "DELETE FROM topic_map"
                " WHERE account_id=? AND channel_id=? AND topic_name=?",
                (self.account_id, channel_id, topic_name),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO tombstones"
                " (account_id, channel_id, topic_name, conversation_id, freed_at)"
                " VALUES (?,?,?,?,?)",
                (self.account_id, channel_id, topic_name, conversation_id, time.time()),
            )
            return conversation_id
