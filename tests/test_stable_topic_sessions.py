"""Tests for stable topic sessions — rename-proof conversation identity.

Implements the routing rules R1-R8 from the project DESIGN.md:

- R1: unmapped topic mints a new conversation id; label reuse after a
  rename starts a NEW conversation.
- R2: full rename (change_all) re-points the conversation and frees the
  old name.
- R3: partial moves (change_one/change_later) are splits — old name keeps
  its conversation, the new name gets a new one.
- R5: renaming onto a live name displaces the previous mapping.
- R6: outbound sends resolve conversation ids to the CURRENT topic name.
- R7: /continue re-binds a topic to the most recently renamed conversation.
- R8: cross-channel moves free the mapping without mapping a new one.
"""

import shutil
from unittest.mock import AsyncMock

import pytest

import zulip.adapter as adapter_module
from tests.conftest import MockZulipClient
from zulip.conversations import TopicConversationRegistry


class RecordingTypingClient(MockZulipClient):
    """MockZulipClient that records set_typing_status calls."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._typing_calls = []

    def set_typing_status(self, request):
        self._typing_calls.append(request)
        return {"result": "success"}


@pytest.fixture
def registry(tmp_path):
    reg = TopicConversationRegistry(account_id="bot@test", data_dir=str(tmp_path))
    yield reg
    shutil.rmtree(tmp_path, ignore_errors=True)


def _stream_msg(topic: str, msg_id: int = 1, content: str = "hello") -> dict:
    return {
        "id": msg_id,
        "type": "stream",
        "stream_id": 7,
        "subject": topic,
        "display_recipient": "engineering",
        "content": content,
        "sender_email": "user@zulip.com",
        "sender_full_name": "User",
        "sender_id": 42,
    }


def _rename_event(
    orig_subject: str,
    subject: str,
    propagate_mode: str = "change_all",
    stream_id: int = 7,
    **extra,
) -> dict:
    event = {
        "id": 99,
        "type": "update_message",
        "stream_id": stream_id,
        "orig_subject": orig_subject,
        "subject": subject,
        "propagate_mode": propagate_mode,
        "message_ids": [1, 2],
    }
    event.update(extra)
    return event


@pytest.fixture
def adapter(mock_platform_config, monkeypatch, tmp_path):
    """ZulipAdapter with topic sessions on (conversation-id keyed, the only
mode) and a recording client."""
    monkeypatch.setenv("ZULIP_CHATMODE", "onmessage")
    monkeypatch.setenv("ZULIP_TOPIC_SESSIONS", "true")
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(adapter_module, "ZULIP_AVAILABLE", True)

    class MockZulipModule:
        class Client:
            def __init__(self, **kwargs):
                self._client = RecordingTypingClient(**kwargs)

            def __getattr__(self, name):
                return getattr(self._client, name)

    monkeypatch.setattr(adapter_module, "zulip", MockZulipModule())
    from zulip.adapter import ZulipAdapter

    a = ZulipAdapter(mock_platform_config)
    a.email = "bot@zulip.com"
    a.handle_message = AsyncMock()
    return a


class TestRegistryStore:
    """Store-level behavior of TopicConversationRegistry."""

    def test_resolve_mints_and_is_stable(self, registry):
        conv = registry.resolve(7, "deploys", anchor_message_id=100)
        assert conv.startswith("c")
        assert registry.resolve(7, "deploys") == conv
        assert registry.current_name(7, conv) == "deploys"

    def test_resolve_replaces_tombstone_label_reuse(self, registry):
        conv = registry.resolve(7, "deploys")
        registry.free(7, "deploys")
        # Label reuse after a free mints a NEW conversation (R4).
        conv2 = registry.resolve(7, "deploys")
        assert conv2 != conv

    def test_repoint_moves_conversation_and_frees_old_name(self, registry):
        conv = registry.resolve(7, "deploys")
        assert registry.repoint(7, "deploys", "deploys-2") == conv
        assert registry.current_name(7, conv) == "deploys-2"
        assert registry.current_name(7, "deploys") is None
        # The old name is tombstoned, not deleted.
        assert registry.latest_tombstone(7) == (conv, "deploys")

    def test_repoint_unmapped_name_is_noop(self, registry):
        assert registry.repoint(7, "ghost", "ghost-2") is None

    def test_repoint_collision_displaces_previous_mapping(self, registry):
        conv_a = registry.resolve(7, "topic-a")
        conv_b = registry.resolve(7, "topic-b")
        # Rename topic-a onto topic-b's live name (R5).
        registry.repoint(7, "topic-a", "topic-b")
        # topic-b now belongs to conv_a; conv_b is displaced (tombstoned).
        assert registry.current_name(7, conv_a) == "topic-b"
        assert registry.latest_tombstone(7) in {(conv_b, "topic-b"), (conv_a, "topic-a")}
        convs = {registry.current_name(7, conv_a), registry.current_name(7, conv_b)}
        assert None in convs  # conv_b has no name anymore

    def test_rebind_consumes_tombstone(self, registry):
        conv = registry.resolve(7, "old-name")
        registry.free(7, "old-name")
        registry.resolve(7, "fresh-name")
        registry.rebind(7, "fresh-name", conv)
        assert registry.current_name(7, conv) == "fresh-name"
        # The (fresh-name -> conv) tombstone is consumed; any tombstone left
        # is the DISPLACED conversation's, not the re-bound pairing.
        latest = registry.latest_tombstone(7)
        assert latest is None or latest[0] != conv

    def test_free_tombstones_without_mapping(self, registry):
        conv = registry.resolve(7, "deploys")
        assert registry.free(7, "deploys") == conv
        assert registry.current_name(7, conv) is None
        assert registry.latest_tombstone(7) == (conv, "deploys")
        assert registry.free(7, "deploys") is None  # idempotent

    def test_persists_across_instances(self, tmp_path):
        reg1 = TopicConversationRegistry(account_id="bot@test", data_dir=str(tmp_path))
        conv = reg1.resolve(7, "deploys")
        reg2 = TopicConversationRegistry(account_id="bot@test", data_dir=str(tmp_path))
        assert reg2.resolve(7, "deploys") == conv

    def test_accounts_are_isolated(self, tmp_path):
        reg_a = TopicConversationRegistry(account_id="a@test", data_dir=str(tmp_path))
        reg_b = TopicConversationRegistry(account_id="b@test", data_dir=str(tmp_path))
        conv_a = reg_a.resolve(7, "deploys")
        assert reg_b.resolve(7, "deploys") != conv_a


    def test_latest_tombstone_excludes_current_conversation(self, registry):
        conv_a = registry.resolve(7, "TopicA")
        conv_b = registry.resolve(7, "TopicB")
        registry.repoint(7, "TopicA", "TopicB")  # R5 collision: conv_a takes "TopicB"
        # Freshest tombstone is the renaming conversation's old name (a
        # no-op candidate for /continue in "TopicB"); excluding it surfaces
        # the DISPLACED conversation instead.
        latest = registry.latest_tombstone(7)
        assert latest == (conv_a, "TopicA")
        assert registry.latest_tombstone(7, exclude_conversation=conv_a) == (conv_b, "TopicB")


    def test_multi_merge_chain_keeps_every_tombstone(self, registry):
        # Aung's 3-way case: "Fix XY" and "Deploy XY" are merged into the
        # live "Discuss about XY" (two sequential change_all renames).
        conv_d = registry.resolve(7, "Discuss about XY")
        conv_f = registry.resolve(7, "Fix XY")
        conv_p = registry.resolve(7, "Deploy XY")
        registry.repoint(7, "Fix XY", "Discuss about XY")     # R5: conv_d displaced
        registry.repoint(7, "Deploy XY", "Discuss about XY")  # R5: conv_f displaced
        # Per-conversation tombstone keying: each merge keeps its own row
        # (per-name keying used to overwrite conv_d's tombstone here).
        assert registry.current_name(7, conv_p) == "Discuss about XY"
        assert registry.current_name(7, conv_d) is None
        assert registry.current_name(7, conv_f) is None
        assert registry.latest_tombstone(7, exclude_conversation=conv_p) == (
            conv_f, "Discuss about XY")
        # All three conversations remain tracked (recoverable via /continue).
        rows = registry._conn.execute(
            "SELECT conversation_id FROM tombstones WHERE channel_id=7"
        ).fetchall()
        assert {str(r[0]) for r in rows} == {conv_d, conv_f, conv_p}


    def test_conversation_links_to_at_most_one_topic(self, registry):
        # Aung's relation model: topic 1—N sessions over time, but a
        # session belongs to exactly ONE topic at any instant.
        import sqlite3
        conv = registry.resolve(7, "TopicA")
        with pytest.raises(sqlite3.IntegrityError):
            # Same conversation linked to a second topic name → rejected.
            registry._conn.execute(
                "INSERT INTO topic_map"
                " (account_id, channel_id, topic_name, conversation_id,"
                "  anchor_message_id, updated_at) VALUES (?,?,?,?,NULL,?)",
                (registry.account_id, 7, "TopicB", conv, 1.0),
            )
        # Different channels are independent topics (same name, own sessions).
        other_channel = registry.resolve(9, "TopicA")
        assert other_channel != conv


class TestInboundSessionIdentity:
    """Inbound messages key sessions on the conversation id (R1)."""

    @pytest.mark.asyncio
    async def test_session_key_is_conversation_id(self, adapter):
        await adapter._handle_message(_stream_msg("deploys"))
        source = adapter.handle_message.call_args[0][0].source
        assert source.thread_id.startswith("c")

    @pytest.mark.asyncio
    async def test_same_topic_same_conversation(self, adapter):
        await adapter._handle_message(_stream_msg("deploys", msg_id=1))
        first = adapter.handle_message.call_args[0][0].source.thread_id
        await adapter._handle_message(_stream_msg("deploys", msg_id=2))
        second = adapter.handle_message.call_args[0][0].source.thread_id
        assert first == second

    @pytest.mark.asyncio
    async def test_label_reuse_after_rename_gets_new_conversation(self, adapter):
        # R1/R2/R4: rename frees the old name; reusing it mints a new one.
        await adapter._handle_message(_stream_msg("Discussion about XY", msg_id=1))
        original = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(
            _rename_event("Discussion about XY", "Fix XY")
        )
        await adapter._handle_message(_stream_msg("Fix XY", msg_id=3))
        continued = adapter.handle_message.call_args[0][0].source.thread_id
        assert continued == original  # rename continues the session

        adapter._handle_topic_update(_rename_event("Fix XY", "Fix XY v2"))
        await adapter._handle_message(_stream_msg("Discussion about XY", msg_id=4))
        reused = adapter.handle_message.call_args[0][0].source.thread_id
        assert reused != original  # old label reuse = new conversation


class TestRenameEvents:
    """update_message event handling (R2/R3/R5/R8)."""

    @pytest.mark.asyncio
    async def test_change_all_repoints(self, adapter):
        await adapter._handle_message(_stream_msg("deploys", msg_id=1))
        conv = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(_rename_event("deploys", "deploys-2"))
        assert adapter._conversations.current_name(7, conv) == "deploys-2"

    @pytest.mark.asyncio
    async def test_partial_move_is_a_split(self, adapter):
        # R3: change_one/change_later do NOT re-point.
        await adapter._handle_message(_stream_msg("deploys", msg_id=1))
        conv = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(
            _rename_event("deploys", "split-out", propagate_mode="change_one")
        )
        assert adapter._conversations.current_name(7, conv) == "deploys"

    @pytest.mark.asyncio
    async def test_content_edit_ignored(self, adapter):
        await adapter._handle_message(_stream_msg("deploys", msg_id=1))
        conv = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(
            _rename_event("deploys", "deploys", propagate_mode="")
        )
        assert adapter._conversations.current_name(7, conv) == "deploys"

    @pytest.mark.asyncio
    async def test_cross_channel_move_frees(self, adapter):
        # R8: free the mapping, map nothing in the new channel.
        await adapter._handle_message(_stream_msg("deploys", msg_id=1))
        conv = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(
            _rename_event(
                "deploys", "deploys", stream_id=7, new_stream_id=9
            )
        )
        assert adapter._conversations.current_name(7, conv) is None

    @pytest.mark.asyncio
    async def test_malformed_events_never_raise(self, adapter):
        adapter._handle_topic_update({"type": "update_message"})  # no fields
        adapter._handle_topic_update(
            _rename_event("deploys", "x", stream_id="not-an-int")
        )

    @pytest.mark.asyncio
    async def test_rename_onto_live_name_displaces(self, adapter):
        # R5: renaming topic-a onto topic-b's live name displaces topic-b.
        await adapter._handle_message(_stream_msg("topic-a", msg_id=1))
        conv_a = adapter.handle_message.call_args[0][0].source.thread_id
        await adapter._handle_message(_stream_msg("topic-b", msg_id=2))
        conv_b = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(_rename_event("topic-a", "topic-b"))
        assert adapter._conversations.current_name(7, conv_a) == "topic-b"
        assert adapter._conversations.current_name(7, conv_b) is None


class TestOutboundRouting:
    """Outbound sends resolve conversation ids to the current name (R6)."""

    @pytest.mark.asyncio
    async def test_reply_after_rename_lands_in_new_topic(self, adapter):
        await adapter._handle_message(_stream_msg("TopicA", msg_id=1))
        conv = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(_rename_event("TopicA", "TopicB"))
        # In-flight reply generated under the old name:
        result = await adapter.send("7", "Task done", metadata={"thread_id": conv})
        assert result.success is True
        call = adapter.client._client._sent_messages[0]
        assert call["topic"] == "TopicB"  # new name, no ghost TopicA

    @pytest.mark.asyncio
    async def test_unknown_thread_id_used_verbatim(self, adapter):
        # Legacy name-keyed sessions (or stable mode off) keep working.
        await adapter.send("7", "legacy", metadata={"thread_id": "Legacy Topic"})
        call = adapter.client._client._sent_messages[0]
        assert call["topic"] == "Legacy Topic"

    @pytest.mark.asyncio
    async def test_typing_resolves_conversation_id(self, adapter):
        await adapter._handle_message(_stream_msg("TopicA", msg_id=1))
        conv = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(_rename_event("TopicA", "TopicB"))
        await adapter.send_typing("7", metadata={"thread_id": conv})
        call = adapter.client._client._typing_calls[-1]
        assert call["topic"] == "TopicB"


class TestContinueCommand:
    """``/continue`` re-binds a topic to the renamed conversation (R7)."""

    @pytest.mark.asyncio
    async def test_continue_rebinds_session(self, adapter):
        await adapter._handle_message(_stream_msg("old-name", msg_id=1))
        original = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(_rename_event("old-name", "new-name"))
        # Someone creates a fresh "old-name" topic and asks to continue.
        await adapter._handle_message(
            _stream_msg("old-name", msg_id=3, content="/continue")
        )
        cmd_call = adapter.client._client._sent_messages[0]
        assert "old-name" in cmd_call["content"]  # confirmation names it
        # The NEXT message in that topic continues the original session.
        await adapter._handle_message(_stream_msg("old-name", msg_id=4))
        rebound = adapter.handle_message.call_args[0][0].source.thread_id
        assert rebound == original

    @pytest.mark.asyncio
    async def test_continue_without_tombstone_replies_gracefully(self, adapter):
        await adapter._handle_message(
            _stream_msg("never-renamed", msg_id=1, content="/continue")
        )
        cmd_call = adapter.client._client._sent_messages[0]
        assert "No recently renamed conversation" in cmd_call["content"]

    @pytest.mark.asyncio
    async def test_continue_repairs_displaced_conversation_after_collision(self, adapter):
        await adapter._handle_message(_stream_msg("TopicA", msg_id=1))
        conv_a = adapter.handle_message.call_args[0][0].source.thread_id
        await adapter._handle_message(_stream_msg("TopicB", msg_id=2))
        conv_b = adapter.handle_message.call_args[0][0].source.thread_id
        # R5 collision: rename TopicA onto the live TopicB name.
        adapter._handle_topic_update(_rename_event("TopicA", "TopicB"))
        # /continue in TopicB must reach the DISPLACED conversation (conv_b),
        # not the renaming conversation's old-name tombstone (a no-op).
        await adapter._handle_message(
            _stream_msg("TopicB", msg_id=3, content="/continue")
        )
        cmd_call = adapter.client._client._sent_messages[0]
        assert "TopicB" in cmd_call["content"]  # confirmation names the tombstone
        await adapter._handle_message(_stream_msg("TopicB", msg_id=4))
        rebound = adapter.handle_message.call_args[0][0].source.thread_id
        assert rebound == conv_b  # TopicB's old session restored
        # /continue toggles back to the renaming conversation (2-way cycle).
        await adapter._handle_message(
            _stream_msg("TopicB", msg_id=5, content="/continue")
        )
        await adapter._handle_message(_stream_msg("TopicB", msg_id=6))
        toggled = adapter.handle_message.call_args[0][0].source.thread_id
        assert toggled == conv_a

    @pytest.mark.asyncio
    async def test_multi_merge_then_continue_reaches_recent_conversations(self, adapter):
        for i, name in enumerate(
            ["Discuss about XY", "Fix XY", "Deploy XY"], start=1
        ):
            await adapter._handle_message(_stream_msg(name, msg_id=i))
        conv_p = adapter.handle_message.call_args[0][0].source.thread_id
        adapter._handle_topic_update(_rename_event("Fix XY", "Discuss about XY"))
        adapter._handle_topic_update(_rename_event("Deploy XY", "Discuss about XY"))
        # Last renamer wins the name: the live session is Deploy XY's.
        await adapter._handle_message(_stream_msg("Discuss about XY", msg_id=9))
        assert adapter.handle_message.call_args[0][0].source.thread_id == conv_p
        # /continue reaches the most recent OTHER conversation (Fix XY's).
        await adapter._handle_message(
            _stream_msg("Discuss about XY", msg_id=10, content="/continue")
        )
        await adapter._handle_message(_stream_msg("Discuss about XY", msg_id=11))
        assert adapter.handle_message.call_args[0][0].source.thread_id != conv_p

