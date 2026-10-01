"""
Zulip Platform Adapter for Hermes Gateway (Plugin)

Bi-directional integration with Zulip chat platform.
Supports stream messages (with topics) and private messages.
"""

import asyncio
import json
import logging
import os
import re
import tempfile
import time
import weakref
from dataclasses import replace as _dc_replace
from collections import OrderedDict
from pathlib import Path
from typing import Optional, Any, overload

from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)

# Native exec-approval buttons (ExecApprovalPrompt + _send_exec_approval_prompt)
# first shipped in Hermes 0.21.3. Import the type defensively so the adapter
# still loads on older gateways: there the gateway never calls the hook and
# keeps using its plain-text approval prompt, instead of the whole plugin
# failing to import.
try:
    from gateway.platforms.base import ExecApprovalPrompt
except ImportError:  # pragma: no cover - gateways < 0.21.3
    ExecApprovalPrompt = Any  # type: ignore[assignment,misc]

# Processing lifecycle hooks (on_processing_start / on_processing_complete) and
# their outcome enum first shipped alongside ExecApprovalPrompt. Guarded for the
# same reason: on an older gateway the hooks are simply never called, so the
# activity trace does not run — rather than the whole plugin failing to import.
# (epic #139 / issue #158)
try:
    from gateway.platforms.base import ProcessingOutcome
except ImportError:  # pragma: no cover - gateways without lifecycle hooks
    ProcessingOutcome = None  # type: ignore[assignment,misc]

from gateway.config import Platform, PlatformConfig

# Use relative imports for internal modules so the plugin works
# regardless of how Hermes loads it (bundled, user path, etc.)
from .logger import format_zulip_log, mask_pii
from .text_utils import (
    chunk_text,
    truncate_text,
    extract_topic_directive,
    strip_onchar_prefix,
    resolve_onchar_prefixes,
    create_mention_regex,
    normalize_mention,
    strip_html_to_text,
)
from .media import upload_file_to_zulip
from .queue_manager import ZulipQueueManager
from .dedupe_store import ZulipDedupeStore
from .reactions import ReactionConfig, ReactionLifecycle
from .version import __version__, __repo__
from .commands import CommandResult, handle_command, is_command
from .conversations import TopicConversationRegistry
from .policy import PolicyEngine
from . import updater
from .probe import (
    INSECURE_HTTP_ENV,
    base_url_error,
    probe_zulip,
    _normalize_base_url,
)
from .recovery import recover_interrupted_messages
from .rate_limiter import RateLimiter
from .audit_logger import AuditLogger
from .activity_trace import ActivityTrace, TraceConfig

# Per-task session context published by the gateway (epic #139 / #159). Guarded
# like every other host symbol: on a gateway without it, tool steps simply
# cannot be attributed and are dropped rather than guessed at.
try:
    from gateway.session_context import get_session_env as _host_get_session_env
except ImportError:  # pragma: no cover - gateways without session context
    _host_get_session_env = None  # type: ignore[assignment]

# Live adapters, so the plugin-level ``post_tool_call`` callback — registered in
# ``register(ctx)``, before any adapter exists — can find the one whose trace
# owns the current work item.
_LIVE_ADAPTERS: "weakref.WeakSet[Any]" = weakref.WeakSet()


def _on_post_tool_call(**kwargs: Any) -> None:
    """Observer for finished tool calls (epic #139 / #159).

    Deliberately **synchronous**: the host dispatches this hook through the sync
    ``invoke_hook``, so an ``async def`` here would return a coroutine nobody
    awaits and silently do nothing. It only records state — the trace's own
    coalesced flush performs the I/O.
    """
    for adapter in list(_LIVE_ADAPTERS):
        try:
            adapter.record_tool_step(**kwargs)
        except Exception:
            # A trace must never interfere with the agent's tool call.
            continue


def _zulip_progress_handler(args: Any) -> str:
    """``zulip_progress`` tool handler — agent-authored trace steps (#160).

    Synchronous: the tool registry calls the handler directly and this only
    records state (the trace's own coalesced flush does the I/O). Returns a
    short acknowledgement so the model sees a result either way — a run without
    an active trace must not look like a failure.
    """
    note = ""
    if isinstance(args, dict):
        for field in ("note", "step", "message"):
            candidate = args.get(field)
            if isinstance(candidate, str) and candidate.strip():
                note = candidate.strip()
                break
    if not note:
        return "error: zulip_progress requires a non-empty 'note'"

    shown = False
    for adapter in list(_LIVE_ADAPTERS):
        try:
            if adapter.record_progress_step(note):
                shown = True
        except Exception:
            continue
    if shown:
        return "noted"
    return "no activity trace is active for this conversation; note not shown"
from .secret_guard import (
    KnownSecret,
    block_secret_leaks_enabled,
    collect_known_secrets,
    describe_leaked_secrets,
    find_leaked_secrets,
)

logger = logging.getLogger(__name__)

# Max input string length to prevent DoS via huge query strings
_MAX_INPUT_LENGTH = 10000
_MAX_JSON_OVERRIDES_BYTES = 10240  # 10KB max for ZULIP_STREAM_OVERRIDES


def _validate_string_length(value: Any, name: str, max_length: int = _MAX_INPUT_LENGTH) -> str:
    """Validate and truncate a string input to prevent DoS.

    Raises ValueError if the value is not a string or exceeds max_length.
    """
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if len(value) > max_length:
        raise ValueError(f"{name} exceeds maximum length ({len(value)} > {max_length})")
    return value

# Module-level SDK handle — updated by _import_zulip_sdk()
zulip = None  # type: ignore

# ------------------------------------------------------------------
# Performance: client + target caching (Issue #49)
# ------------------------------------------------------------------
_MAX_CLIENT_CACHE = 50
_MAX_TARGET_CACHE = 500

_client_cache: OrderedDict[str, Any] = OrderedDict()
_target_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()

# Parsed ZULIP_STREAM_OVERRIDES, keyed on the raw environment string so the
# value stays live-reloadable while a busy stream does not re-parse JSON on
# every inbound message.
_stream_overrides_cache: tuple[str, dict[str, dict[str, Any]]] = ("", {})


def _get_cached_client(site: str, email: str, api_key: str, *, _zulip_mod: Any = None) -> Any:
    """Return a cached Zulip client or create a new one.

    LRU eviction keeps the most-recently-used clients.
    """
    key = f"{site}\x00{email}\x00{api_key}"
    client = _client_cache.pop(key, None)
    if client is not None:
        _client_cache[key] = client
        return client

    _zulip = _zulip_mod or _import_zulip_sdk()
    if _zulip is None:
        raise ImportError("zulip package not installed")

    client = _zulip.Client(email=email, api_key=api_key, site=site)

    # Configure connection pooling for the client's requests session.
    # This reuses TCP connections across API calls, reducing latency.
    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        if hasattr(client, "ensure_session"):
            client.ensure_session()
        if hasattr(client, "session") and client.session is not None:
            # Pool up to 10 connections per host, with retry on transient errors
            retry_strategy = Retry(
                total=2,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(
                pool_connections=10,
                pool_maxsize=20,
                max_retries=retry_strategy,
            )
            client.session.mount("https://", adapter)
            client.session.mount("http://", adapter)
    except ImportError:
        pass  # requests not available; use default session

    if len(_client_cache) >= _MAX_CLIENT_CACHE:
        oldest = next(iter(_client_cache))
        del _client_cache[oldest]

    _client_cache[key] = client
    return client


def _get_cached_target(chat_id: str) -> dict[str, Any] | None:
    """Return cached target info or None.

    Target info: {"type": "dm", "user_ids": list[int]} |
    {"type": "stream", "stream_id": int}
    """
    info = _target_cache.get(chat_id)
    if info is not None:
        # Move to end (most-recently-used)
        del _target_cache[chat_id]
        _target_cache[chat_id] = info
    return info


def _set_cached_target(chat_id: str, info: dict[str, Any]) -> None:
    """Cache parsed target info with LRU eviction."""
    if chat_id in _target_cache:
        del _target_cache[chat_id]

    if len(_target_cache) >= _MAX_TARGET_CACHE:
        oldest = next(iter(_target_cache))
        del _target_cache[oldest]

    _target_cache[chat_id] = info


def _parse_target(chat_id: str) -> dict[str, Any]:
    """Parse chat_id into target info, using cache if available."""
    cached = _get_cached_target(chat_id)
    if cached is not None:
        return cached

    if chat_id.startswith("dm:"):
        # Session-scoped DM chat_ids include a `:session:N` suffix (e.g.
        # `dm:1032616:session:1`). Strip everything after the recipient list
        # so the send path resolves the correct target. (Issue #111)
        #
        # A group DM carries every recipient, comma-separated
        # (`dm:7,42,99`). Replying with only the sender would start a new
        # one-to-one DM instead of continuing the group conversation, so the
        # complete set is part of the address. (Issue #154)
        recipients = chat_id[3:].split(":", 1)[0]
        user_ids = [int(part) for part in recipients.split(",") if part.strip()]
        if not user_ids:
            raise ValueError("DM target must include at least one recipient")
        info = {"type": "dm", "user_ids": user_ids}
    else:
        info = {"type": "stream", "stream_id": int(chat_id)}

    _set_cached_target(chat_id, info)
    return info


def _private_recipient_ids(message: dict[str, Any]) -> list[int]:
    """Return every recipient of an incoming private message, sorted.

    Zulip represents a direct message's ``display_recipient`` as the list of
    participants, the bot included. A one-to-one DM therefore has two entries
    and a group DM has more. Preserving the complete set is what keeps a reply
    inside the original conversation instead of starting a new one-to-one DM
    with just the sender. (Issue #154)

    Older or malformed events may omit the recipient list, so fall back to the
    sender's id. That reproduces the previous behaviour for one-to-one DMs.
    """
    recipient_ids: set[int] = set()

    recipients = message.get("display_recipient")
    if isinstance(recipients, list):
        for recipient in recipients:
            if not isinstance(recipient, dict):
                continue
            try:
                recipient_ids.add(int(recipient["id"]))
            except (KeyError, TypeError, ValueError):
                continue

    if not recipient_ids:
        try:
            recipient_ids.add(int(message["sender_id"]))
        except (KeyError, TypeError, ValueError):
            pass

    return sorted(recipient_ids)


def _private_chat_id(message: dict[str, Any]) -> str:
    """Encode a private message's recipient set as the adapter chat id.

    The address has to be self-describing: replies are routed by chat id, so
    the recipient set must survive persistence and a gateway restart.
    """
    recipient_ids = _private_recipient_ids(message)
    if not recipient_ids:
        raise ValueError("Private message has no usable recipient IDs")
    return "dm:" + ",".join(str(user_id) for user_id in recipient_ids)


def _clear_caches() -> None:
    """Clear all caches. Used by tests and for resource cleanup."""
    _client_cache.clear()
    _target_cache.clear()
ZULIP_AVAILABLE = False


def _import_zulip_sdk():
    """Lazy-import the zulip SDK, bypassing plugin shadow if needed.

    Hermes adds ~/.hermes/plugins/ to sys.path, so a directory named
    'zulip' shadows the pip-installed zulip package. We temporarily
    remove the shadowed entry from sys.modules to force Python to
    re-resolve to the real SDK.
    """
    import sys

    global ZULIP_AVAILABLE, zulip
    if ZULIP_AVAILABLE and zulip is not None:
        return zulip

    # Remove any shadowed plugin entry so Python resolves the real SDK
    _shadow = sys.modules.pop("zulip", None)
    try:
        import zulip as _sdk

        zulip = _sdk
        ZULIP_AVAILABLE = True
        return _sdk
    except ImportError:
        zulip = None
        ZULIP_AVAILABLE = False
        return None
    finally:
        # Restore the shadowed plugin entry so Hermes/other imports
        # that expect the zulip package continue to work
        if _shadow is not None:
            sys.modules["zulip"] = _shadow


# Chunking defaults (overridable via env)
DEFAULT_CHUNK_LIMIT = 10000  # Hermes registry max_message_length
DEFAULT_CHUNK_MODE = "length"

# Hard cap on a single outbound message, applied before chunking. Mirrors the
# sibling OpenClaw plugin's ``maxMessageLength`` (default 20000): downstream
# consumers (e.g. memory plugins) can fail on very long content. 0 disables.
DEFAULT_MAX_MESSAGE_LENGTH = 20000


def _resolve_max_message_length() -> int:
    """Read the hard outbound message-length cap from the environment.

    ``ZULIP_MAX_MESSAGE_LENGTH`` (default 20000, ``0`` disables). Applied in
    :meth:`ZulipAdapter.send` and :func:`_standalone_send` before chunking.
    """
    raw = os.getenv("ZULIP_MAX_MESSAGE_LENGTH", "").strip()
    if not raw:
        return DEFAULT_MAX_MESSAGE_LENGTH
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_MAX_MESSAGE_LENGTH

# Timeout defaults (seconds) — Issue #62
DEFAULT_CONNECT_TIMEOUT = 30.0
DEFAULT_READ_TIMEOUT = 60.0
DEFAULT_SEND_TIMEOUT = 90.0

# --- Event polling (Issue #146) ---
#
# A /events long-poll that returns faster than this did not hold the poll, so
# the server is answering immediately and re-polling at full speed would spin
# (and, on the constrained hosts this runs on, fill the log with poll noise).
# A response at or above it was really held, meaning the server is pacing us,
# so it must gain no added delay.
POLL_FAST_RETURN_SECONDS = 2.5
POLL_BACKOFF_START = 1.0
POLL_BACKOFF_MAX = 5.0
# Zulip documents ``event_queue_longpoll_timeout_seconds`` as 1-90s, and only
# returns the field when /register asks for ``fetch_event_types: ["realm"]``.
LONGPOLL_MIN_SECONDS = 1.0
LONGPOLL_MAX_SECONDS = 90.0
# Headroom over the server's own budget, so our client-side abort can never
# pre-empt a healthy long-poll.
LONGPOLL_GRACE_SECONDS = 10.0


def _resolve_chunk_config() -> tuple[int, str]:
    """Read chunking config from environment."""
    limit_raw = os.getenv("ZULIP_TEXT_CHUNK_LIMIT", "").strip()
    limit = int(limit_raw) if limit_raw.isdigit() else DEFAULT_CHUNK_LIMIT
    mode = os.getenv("ZULIP_CHUNK_MODE", DEFAULT_CHUNK_MODE).strip()
    if mode not in ("length", "newline"):
        mode = DEFAULT_CHUNK_MODE
    return limit, mode


def _resolve_timeouts() -> tuple[float, float, float]:
    """Read timeout config from environment.

    Returns (connect_timeout, read_timeout, send_timeout) in seconds.
    """
    def _parse(val: str, default: float) -> float:
        try:
            return float(val.strip())
        except (ValueError, AttributeError):
            return default

    connect = _parse(os.getenv("ZULIP_CONNECT_TIMEOUT", ""), DEFAULT_CONNECT_TIMEOUT)
    read = _parse(os.getenv("ZULIP_READ_TIMEOUT", ""), DEFAULT_READ_TIMEOUT)
    send = _parse(os.getenv("ZULIP_SEND_TIMEOUT", ""), DEFAULT_SEND_TIMEOUT)
    return connect, read, send


def _clamp_longpoll_budget(value: Any) -> Optional[float]:
    """Clamp a server long-poll budget to Zulip's documented 1-90s window.

    Returns ``None`` when the value is missing or unusable, which leaves the
    caller's configured timeout in place rather than guessing. (Issue #146)
    """
    try:
        budget = float(value)
    except (TypeError, ValueError):
        return None
    if budget <= 0:
        return None
    return min(max(budget, LONGPOLL_MIN_SECONDS), LONGPOLL_MAX_SECONDS)


def _next_poll_backoff(elapsed: float, had_message: bool, current: float) -> float:
    """Return the delay before the next /events poll (0.0 = poll at once).

    Latency-gated (Issue #146): the question is not "were there events?" but
    "did the server hold the long-poll?". A poll that came back quickly did
    not, so the loop has to insert its own delay or it will spin as fast as
    the API answers; a poll that was genuinely held is already paced by the
    server and must not gain any latency.
    """
    if had_message or elapsed >= POLL_FAST_RETURN_SECONDS:
        return 0.0
    return min(max(current * 2, POLL_BACKOFF_START), POLL_BACKOFF_MAX)


def _resolve_streams_filter() -> set[str] | None:
    """Read stream filtering config from environment.

    Returns None if all streams are allowed (default), or a set of
    lowercase stream names to monitor.
    """
    raw = os.getenv("ZULIP_STREAMS", "").strip()
    if not raw or raw == "*":
        return None
    return {s.strip().lower() for s in raw.split(",") if s.strip()}


def _resolve_response_prefix() -> str:
    """Read outbound response prefix from environment."""
    return os.getenv("ZULIP_RESPONSE_PREFIX", "")


def _resolve_stream_overrides() -> dict[str, dict[str, Any]]:
    """Read per-stream trigger overrides from the environment.

    ``ZULIP_STREAM_OVERRIDES`` is a JSON object mapping stream name to a
    settings object, overriding ``ZULIP_CHATMODE`` for that stream::

        ZULIP_STREAM_OVERRIDES='{
          "bot lab":       {"chatmode": "onmessage"},
          "team: general": {"chatmode": "oncall"}
        }'

    Only ``chatmode`` is supported. ``requireMention`` is deliberately not
    overridable: in the current gate it is inert in every mode.

    JSON is used rather than delimited pairs because Zulip stream names may
    legitimately contain both colons and commas.

    Stream names and setting keys are both matched case-insensitively.
    Unrecognised setting keys are warned about. Malformed configuration is
    logged and ignored rather than raised.
    """
    raw = os.getenv("ZULIP_STREAM_OVERRIDES", "").strip()
    if len(raw.encode("utf-8")) > _MAX_JSON_OVERRIDES_BYTES:
        logger.warning(
            "ZULIP_STREAM_OVERRIDES exceeds max size (%d > %d bytes); ignoring overrides",
            len(raw.encode("utf-8")),
            _MAX_JSON_OVERRIDES_BYTES,
        )
        return _remember({})
    cached_raw, cached = _stream_overrides_cache
    if raw == cached_raw:
        return cached

    def _remember(value: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        global _stream_overrides_cache
        _stream_overrides_cache = (raw, value)
        return value

    if not raw:
        return _remember({})

    try:
        parsed = json.loads(raw)
    except ValueError:
        logger.warning("ZULIP_STREAM_OVERRIDES is not valid JSON; ignoring overrides")
        return _remember({})

    if not isinstance(parsed, dict):
        logger.warning(
            "ZULIP_STREAM_OVERRIDES must be a JSON object mapping stream name "
            "to a settings object; ignoring overrides"
        )
        return _remember({})

    overrides: dict[str, dict[str, Any]] = {}
    for name, settings in parsed.items():
        if not isinstance(settings, dict):
            logger.warning(
                "ZULIP_STREAM_OVERRIDES[%r] must be an object, e.g. "
                '{"chatmode": "onmessage"}; ignoring entry',
                name,
            )
            continue

        entry: dict[str, Any] = {}

        # Setting keys are matched case-insensitively
        normalised = {str(k).strip().lower(): v for k, v in settings.items()}

        # Warn about unrecognised keys
        unknown = sorted(
            k for k in normalised
            if k not in ("chatmode", "requiremention", "require_mention")
        )
        if unknown:
            logger.warning(
                "ZULIP_STREAM_OVERRIDES[%r]: ignoring unrecognised key(s) %s; "
                "the only supported key is 'chatmode'",
                name, ", ".join(unknown),
            )

        mode = normalised.get("chatmode")
        if mode is not None:
            mode = str(mode).strip().lower()
            if mode in ("onmessage", "oncall", "onchar"):
                entry["chatmode"] = mode
            else:
                logger.warning(
                    "ZULIP_STREAM_OVERRIDES[%r].chatmode=%r is not one of "
                    "onmessage/oncall/onchar; ignoring it",
                    name, mode,
                )

        if entry:
            overrides[str(name).strip().lower()] = entry

    return _remember(overrides)


@overload
def _resolve_chatmode() -> tuple[str, list[str], bool]:
    ...


@overload
def _resolve_chatmode(stream_name: str) -> tuple[str, list[str], bool]:
    ...


def _resolve_chatmode(stream_name: Optional[str] = None) -> tuple[str, list[str], bool]:
    """Read stream trigger mode config from environment.

    When ``stream_name`` is supplied, a matching entry in
    ``ZULIP_STREAM_OVERRIDES`` takes precedence over the global
    ``ZULIP_CHATMODE`` for that stream only.
    """
    mode = os.getenv("ZULIP_CHATMODE", "onmessage").strip().lower()
    if mode not in ("onmessage", "oncall", "onchar"):
        mode = "onmessage"
    prefixes = resolve_onchar_prefixes(os.getenv("ZULIP_ONCHAR_PREFIXES", ""))
    require_mention = os.getenv("ZULIP_REQUIRE_MENTION", "true").strip().lower() not in ("false", "0", "no", "off")

    if stream_name:
        override = _resolve_stream_overrides().get(stream_name.strip().lower())
        if override:
            mode = override.get("chatmode", mode)

    return mode, prefixes, require_mention


def _message_with_flags(event: dict) -> dict:
    """Return the event's message with Zulip's per-user flags attached.

    Zulip delivers flags on the *event*, as a sibling of ``message``, while its
    REST API returns them on the message itself. Downstream code should only
    have one place to look, and losing them here means losing the authoritative
    ``mentioned`` signal.

    An existing ``flags`` key on the message is left alone.
    """
    message = event.get("message") or {}
    if "flags" not in message:
        message["flags"] = event.get("flags") or []
    return message


def _metadata_topic(metadata: Any) -> Optional[str]:
    """Outbound routing topic from gateway send metadata.

    The gateway core routes replies by ``thread_id`` — the session origin's
    topic (``gateway.platforms.base._thread_metadata_for_source``) — so a reply
    generated for one topic lands there even if other topics have seen traffic
    since. ``topic`` is read too for parity with the adapter's own event
    metadata. First non-empty value wins; None when neither is set.
    """
    if not isinstance(metadata, dict):
        return None
    for key in ("thread_id", "topic"):
        value = metadata.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


# Legacy (pre-stable-sessions) zulip stream session key:
#   agent:<profile>:zulip:stream:<channel_id>:<topic_name>
# The topic is everything after the channel prefix — topic names may
# contain colons, so the tail is captured greedily.
_LEGACY_ZULIP_STREAM_KEY = re.compile(
    r"^(?P<prefix>agent:[^:]+:zulip:stream:(?P<channel>\d+):)(?P<topic>.+)$"
)

# Conversation ids minted by the registry ("c" + 12 hex chars) — used to
# recognize already-migrated (conv-keyed) session keys.
_CONVERSATION_ID_RE = re.compile(r"^c[0-9a-f]{12}$")
# Gateway session ids: <YYYYMMDD>_<HHMMSS>_<hex> (e.g. 20260928_180207_789321ca).
_GATEWAY_SESSION_ID_RE = re.compile(r"^\d{8}_\d{6}_[0-9a-f]+$")


def _split_session_key_tail(tail: str) -> tuple[str, Optional[str]]:
    """Split a legacy session-key tail into ``(head, user_suffix)``.

    The gateway appends the participant id AFTER the thread segment when
    per-user isolation applies (``group_sessions_per_user`` /
    ``thread_sessions_per_user``), and Zulip participant ids are emails —
    they contain ``@`` and never contain ``:``. So when the last
    colon-separated segment looks like an email, it is the user suffix
    and everything before it is the topic name or conversation id (topic
    names may themselves contain colons, e.g. ``Deploy: XY:user@x.com``).
    Participant ids without ``@`` (non-email shapes) are not detected —
    the Zulip adapter always uses the sender email.
    """
    head, sep, user = tail.rpartition(":")
    if sep and user and "@" in user:
        return head, user
    return tail, None


def _topic_sessions_enabled() -> bool:
    """Whether each Zulip topic should get its own conversation session.

    Off by default. When enabled, the topic is passed to ``build_source`` as
    ``thread_id``, which is what Hermes scopes session state by — so each topic
    in a stream becomes an independent conversation instead of all topics
    sharing one.

    This is opt-in because turning it on splits an existing stream's history
    into per-topic sessions, which changes what an agent remembers.
    """
    return os.getenv("ZULIP_TOPIC_SESSIONS", "").strip().lower() in ("true", "1", "yes", "on")


def _safe_delete_temp_file(file_path: str) -> None:
    """Delete a local file only if it resides under /tmp or a bot workspace.

    Prevents accidental deletion of user-owned files outside temp dirs.
    Uses stat with follow_symlinks=False to prevent TOCTOU symlink swaps.
    Errors are logged, not raised.
    """
    try:
        p = Path(file_path).resolve()
        tmp = Path(tempfile.gettempdir()).resolve()
        ws = tmp / "hermes_bot_workspace"
        if not (str(p).startswith(str(tmp)) or str(p).startswith(str(ws))):
            return
        # Atomic stat + unlink to prevent TOCTOU symlink race
        st = p.stat(follow_symlinks=False)
        if st.st_ino != p.resolve().stat().st_ino:
            logger.warning(
                "temp file cleanup skipped: symlink detected [path=%s]",
                mask_pii(file_path),
            )
            return
        p.unlink()
        logger.debug("cleaned up temp file [path=%s]", mask_pii(file_path))
    except OSError as e:
        logger.warning("temp file cleanup failed [path=%s]: %s", mask_pii(file_path), e)


class ZulipAdapter(BasePlatformAdapter):
    """Zulip platform adapter for Hermes Gateway."""

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform("zulip"))
        extra = config.extra or {}

        self.api_key = os.getenv("ZULIP_API_KEY") or extra.get("api_key", "")
        self.email = os.getenv("ZULIP_EMAIL") or extra.get("email", "")
        self.site = os.getenv("ZULIP_SITE") or extra.get("site", "")

        # Outbound secret guard (Issue #136): the platform extra is walked for
        # credential-shaped keys, and the adapter's own api_key is registered
        # explicitly — those are exactly the values a prompt-injected agent
        # would paste into the room.
        self._platform_extra = extra
        self._known_secrets_cache: Optional[list[KnownSecret]] = None
        # Populated on connect. Zulip renders mentions from the display name,
        # not the email local-part, so mention matching needs it.
        self.bot_full_name = ""

        # Validate site URL before creating client: https-only unless the
        # operator opted in, so the API key cannot leave in cleartext by
        # accident. (Issue #137)
        if self.site:
            validated = _normalize_base_url(self.site)
            if not validated:
                raise ValueError(base_url_error(self.site))
            self.site = validated
            if self.site.startswith("http://"):
                logger.warning(
                    "zulip: %s is set — the bot API key is sent unencrypted as "
                    "HTTP Basic on every request [site=%s]",
                    INSECURE_HTTP_ENV,
                    mask_pii(self.site),
                )

        _zulip = _import_zulip_sdk()
        if not _zulip:
            logger.error(
                "zulip package not installed. Run: pip install zulip"
            )
            raise ImportError(
                "zulip package not installed. Run: pip install zulip"
            )

        # Use cached client if available (avoids repeated base64 encoding + object creation)
        self.client = _get_cached_client(self.site, self.email, self.api_key, _zulip_mod=_zulip)

        # Fallback topic per stream, used only when a send carries no routing
        # metadata (e.g. TOPIC_SESSIONS off, or metadata-less callers). With
        # topic sessions on, the gateway routes replies by metadata thread_id —
        # the session's own topic — never by this cache.
        self._topic_cache: dict[str, str] = {}
        # F1: conversation ids resolved at event dispatch, keyed by message
        # id (str). Written inline by the poll loop in event-id order;
        # popped by _handle_message so a rename processed between dispatch
        # and the handler's first await cannot fork the conversation.
        self._pending_conversations: dict[str, str] = {}
        # Context-mitigation state
        self._last_topic_cache: dict[str, str] = {}      # stream_id → previous topic
        self._message_counts: dict[str, int] = {}        # chat_id → message count
        self._last_message_time: dict[str, float] = {}   # chat_id → last message epoch
        # DM session rotation: prevents context bloat in long conversations
        self._dm_session_turn_limit = int(
            os.getenv("ZULIP_DM_SESSION_TURN_LIMIT", "20").strip()
        )
        self._dm_base_message_counts: dict[str, int] = {}  # base_session_key → turn count

        # Block streaming config (Issue #49 — requires gateway-level streaming support)
        self._block_streaming = (
            os.getenv("ZULIP_BLOCK_STREAMING", "").strip().lower() in ("true", "1", "yes", "on")
        )

        self._data_dir = os.environ.get("HERMES_DATA_DIR", os.path.expanduser("~/.hermes"))

        # Timeout configuration (Issue #62)
        self._connect_timeout, self._read_timeout, self._send_timeout = _resolve_timeouts()

        # Abort budget for /events, raised once we learn the server's own
        # long-poll budget from /register. Our 60s default is shorter than
        # Zulip's 90s default, so without this we abort every idle long-poll
        # client-side. (Issue #146)
        self._events_timeout = self._read_timeout

        # Stream filtering (Issue #65) — None means all streams
        self._streams_filter = _resolve_streams_filter()

        # Response prefix (Issue #65) — prepended to every outbound message
        self._response_prefix = _resolve_response_prefix()

        # Rate limiter (per-sender, sliding window)
        self._rate_limiter = RateLimiter(
            max_per_minute=int(
                os.getenv("ZULIP_MAX_MESSAGES_PER_MINUTE", "60").strip()
            ),
        )

        # Audit logger for security events
        self._audit_logger = AuditLogger(
            data_dir=self._data_dir,
            account_id=self.email or "default",
        )

        # Persistent queue and dedupe
        self._queue_mgr = ZulipQueueManager(
            account_id=self.email or "default",
            data_dir=self._data_dir,
            register_fn=self._register_queue,
            needed_event_types_fn=self._needed_event_types,
        )
        self._dedupe = ZulipDedupeStore(
            account_id=self.email or "default",
            data_dir=self._data_dir,
            ttl_ms=300_000,
            max_size=2000,
        )
        self._dedupe.load()

        # Stable topic sessions: with topic sessions enabled, sessions key on
        # a persistent conversation id — never the topic name — so renames
        # continue the session instead of stranding it. There is no opt-out:
        # name-keyed topic sessions are not a feature (explicit /new is the
        # only way to start a fresh session in a topic).
        self._conversations: Optional[TopicConversationRegistry] = None
        if _topic_sessions_enabled():
            self._conversations = TopicConversationRegistry(
                account_id=self.email or "default",
                data_dir=self._data_dir,
            )

        # Reaction config
        self._reaction_cfg = ReactionConfig.from_env()

        # Extra Zulip event types beyond "message" that this install needs.
        # Features opt in here (e.g. reaction triggers need "reaction"); it is
        # consulted when registering the event queue and when deciding whether
        # a persisted queue can be reused. (Issue #162)
        self._extra_event_types: list = []
        if _topic_sessions_enabled():
            # Stable topic sessions need rename and topic-deletion events;
            # opt in so a persisted queue whose subscription predates this
            # set is re-registered (issue #162 machinery).
            self._extra_event_types.extend(["update_message", "delete_message"])

        # DM policy engine (Issue #48 — controls who can DM the bot)
        self._policy = PolicyEngine(data_dir=self._data_dir)

        self._listening = False
        self._event_task: Optional[asyncio.Task] = None
        self._presence_task: Optional[asyncio.Task] = None

        # Activity trace (epic #139 / #158): one bot-owned status message per
        # work item, edited in place. Disabled unless ZULIP_ACTIVITY_TRACE is set.
        self._trace_cfg = TraceConfig.from_env()
        self._traces: dict[str, ActivityTrace] = {}
        self._trace_start_tasks: dict[str, asyncio.Task] = {}
        self._trace_started: dict[str, float] = {}
        self._trace_replied: set[str] = set()
        # Aliases (host session key, chat+topic route) -> trace key, so a tool
        # callback running in another thread/task can still find its trace.
        self._trace_sessions: dict[str, str] = {}
        _LIVE_ADAPTERS.add(self)
        if self._trace_cfg.enabled and ProcessingOutcome is None:
            logger.warning(
                "ZULIP_ACTIVITY_TRACE is enabled but this gateway does not expose "
                "the processing lifecycle hooks; the trace will not run"
            )

    async def _sdk_call(self, fn, *args, timeout: float, **kwargs):
        """Wrap a synchronous SDK call in asyncio.to_thread + asyncio.wait_for.

        Provides outer-timeout protection so the gateway event loop never
        blocks indefinitely on a hung Zulip API request.
        """
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(fn, *args, **kwargs),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "zulip SDK call timed out after %.1fs [fn=%s]",
                timeout,
                getattr(fn, "__name__", repr(fn)),
            )
            raise

    @staticmethod
    def _validate_message_id(message_id: Any) -> int:
        """Validate and convert a message ID to int.

        Raises ValueError if the message ID is not a valid positive integer
        or exceeds the maximum safe value.
        Prevents path traversal, injection, and overflow via malformed IDs.
        """
        if message_id is None:
            raise ValueError("message_id is required")
        try:
            mid = int(str(message_id).strip())
        except (ValueError, TypeError):
            raise ValueError(f"Invalid message_id: {message_id}")
        if mid <= 0:
            raise ValueError(f"message_id must be positive: {message_id}")
        if mid > 2**63 - 1:
            raise ValueError(f"message_id exceeds maximum safe value: {message_id}")
        return mid

    async def _stop_typing(self, typing_params: Optional[dict]) -> None:
        """Stop typing indicator if it was started. Safe to call multiple times."""
        if typing_params is None:
            return
        params = dict(typing_params)
        params["op"] = "stop"
        try:
            await self._sdk_call(
                self.client.set_typing_status,
                params,
                timeout=self._send_timeout,
            )
        except Exception:
            pass

    def _typing_params_for_chat(
        self, chat_id: str, op: str, topic: Optional[str] = None
    ) -> Optional[dict]:
        """Map a gateway chat_id to Zulip set_typing_status params.

        DM session rotation can suffix chat ids ("dm:<id>:session:<n>"), and a
        group DM carries every recipient ("dm:<id>,<id>"); both are stripped to
        the recipient list. Streams are numeric stream ids;
        ``topic`` (the routing metadata's thread_id) wins over the per-stream
        reply cache, so typing shows in the session's own topic.
        """
        if not chat_id:
            return None
        parts = chat_id.split(":")
        if parts[0] == "dm":
            if len(parts) < 2:
                return None
            try:
                user_ids = [
                    int(part) for part in parts[1].split(",") if part.strip()
                ]
            except ValueError:
                return None
            if not user_ids:
                return None
            return {"op": op, "type": "direct", "to": user_ids}
        if chat_id.isdigit():
            resolved = (topic or "").strip() or self._topic_cache.get(chat_id, "")
            return {
                "op": op,
                "type": "stream",
                "stream_id": int(chat_id),
                "topic": resolved,
            }
        return None

    async def send_typing(self, chat_id: str, metadata: Any = None) -> None:
        """Core typing hook: the gateway calls this every ~2s while the agent
        runs (platform typing state expires after ~5s). Best-effort."""
        try:
            params = self._typing_params_for_chat(
                str(chat_id), "start", topic=self._routed_topic_for_chat(str(chat_id), metadata)
            )
            if params:
                await self._sdk_call(
                    self.client.set_typing_status,
                    params,
                    timeout=self._send_timeout,
                )
        except Exception:
            pass  # typing is best-effort

    async def stop_typing(self, chat_id: str, metadata: Any = None) -> None:
        """Core typing hook: called when the agent run finishes. Best-effort.

        Accepts ``metadata`` so the gateway base's introspecting
        ``_stop_typing_with_metadata`` forwards the run's routing metadata
        (a thread-scoped clear must not depend on the last-seen topic).
        """
        try:
            params = self._typing_params_for_chat(
                str(chat_id), "stop", topic=self._routed_topic_for_chat(str(chat_id), metadata)
            )
            if params:
                await self._sdk_call(
                    self.client.set_typing_status,
                    params,
                    timeout=self._send_timeout,
                )
        except Exception:
            pass  # typing is best-effort

    # --- activity trace lifecycle (epic #139 / #158) ---

    @staticmethod
    def _trace_key(chat_id: str, metadata: Any) -> str:
        """Session key for a trace: the chat *plus* the topic it lands in.

        Topic sessions share a chat_id across topics, so keying on chat_id alone
        would let two concurrent topics in one stream edit each other's trace.
        """
        return f"{chat_id}\x00{_metadata_topic(metadata) or ''}"

    def _trace_payload(
        self, chat_id: str, metadata: Any, content: str
    ) -> Optional[dict]:
        """Send payload for a trace message, using the *reply* routing.

        Deliberately the same resolution the reply uses (``_metadata_topic`` and
        ``_parse_target``). Issue #143 was a second, drifting topic resolution,
        and a trace that lands in the wrong topic is worse than no trace.
        """
        try:
            target = _parse_target(chat_id)
        except (TypeError, ValueError):
            return None
        if target["type"] == "dm":
            return {"type": "private", "to": target["user_ids"], "content": content}
        # Same resolution the reply path uses (_routed_topic): with stable
        # topic sessions metadata.topic is a conversation id, and a raw
        # send would materialize a ghost topic named like the id (#143 lesson:
        # no second, drifting resolution).
        topic = (
            self._routed_topic(target["stream_id"], metadata)
            or self._topic_cache.get(chat_id, "general")
        )
        return {
            "type": "stream",
            "to": target["stream_id"],
            "topic": topic,
            "content": content,
        }

    def _note_trace_reply(self, chat_id: str, metadata: Any) -> None:
        """Record that this work item actually produced a reply."""
        if self._traces:
            self._trace_replied.add(self._trace_key(chat_id, metadata))

    def _session_key_for_event(self, event: Any) -> Optional[str]:
        """The host's own session key for an event, when it exposes one.

        Reused rather than reimplemented: a second key derivation would drift
        from the host's, which is the #143 lesson. Returns None when the host
        offers no such method, so callers fall back to the route alias.
        """
        getter = getattr(self, "_event_session_key", None)
        if not callable(getter):
            return None
        try:
            key = getter(event)
        except Exception:
            return None
        return str(key) if key else None

    def _session_aliases(self, event: Any) -> list[str]:
        """Aliases that identify this event's run, as seen from the adapter."""
        aliases: list[str] = []
        session_key = self._session_key_for_event(event)
        if session_key:
            aliases.append(f"key:{session_key}")
        source = getattr(event, "source", None)
        chat_id = str(getattr(source, "chat_id", "") or "")
        if chat_id:
            thread = _metadata_topic(getattr(event, "metadata", None)) or ""
            aliases.append(f"route:{chat_id}\x00{thread}")
        return aliases

    @staticmethod
    def _session_aliases_from_context() -> list[str]:
        """The same aliases, read from the *current* task's session context.

        Tool callbacks run outside the adapter, so this is how they recover
        which run they belong to. The hook payload's ``session_id`` is the
        agent-side durable id and is deliberately **not** used: it is derived
        differently from the adapter session key, so matching on it would be a
        guess.
        """
        if _host_get_session_env is None:
            return []
        try:
            key = _host_get_session_env("HERMES_SESSION_KEY") or ""
            chat_id = _host_get_session_env("HERMES_SESSION_CHAT_ID") or ""
            thread = _host_get_session_env("HERMES_SESSION_THREAD_ID") or ""
        except Exception:
            return []
        aliases: list[str] = []
        if key:
            aliases.append(f"key:{key}")
        if chat_id:
            aliases.append(f"route:{chat_id}\x00{thread}")
        return aliases

    def _trace_for_current_session(self) -> Optional[ActivityTrace]:
        """The trace for the task we are running inside, or None.

        Shared by the tool hook (mode A) and the progress tool (mode B) so both
        attribute through exactly **one** code path — two would drift.
        """
        if not self._trace_cfg.enabled or not self._trace_sessions:
            return None
        for alias in self._session_aliases_from_context():
            key = self._trace_sessions.get(alias)
            if key is not None:
                return self._traces.get(key)
        return None

    def record_progress_step(self, note: str) -> bool:
        """Add an agent-authored step (mode B). True when it was shown."""
        trace = self._trace_for_current_session()
        if trace is None:
            return False
        step = trace.step(str(note))
        trace.complete(step, ok=True)
        return step is not None

    def record_tool_step(
        self,
        *,
        tool_name: str = "",
        status: Optional[str] = None,
        duration_ms: int = 0,
        error_type: Optional[str] = None,
        **_: Any,
    ) -> None:
        """Attach a finished tool call to its work item's trace.

        A step whose run cannot be identified is **dropped**, never guessed into
        some other topic: a trace that narrates another conversation's work is
        worse than a trace with a gap.
        """
        # ZULIP_TRACE_TOOL_MATCHER (#176): a tool-heavy turn otherwise renders a
        # board far too long to read. The engine's coalescing bounds the API
        # cost, not the readability.
        if not self._trace_cfg.allows_tool(tool_name):
            return

        trace = self._trace_for_current_session()
        if trace is None:
            return

        ok = (status or "ok") != "error"
        detail = ""
        if ok and duration_ms:
            detail = f"{duration_ms} ms"
        elif not ok:
            detail = error_type or "failed"
        step = trace.step(str(tool_name or "tool"))
        trace.complete(step, ok=ok, detail=detail)

    # --- durable trace records (issue #161) ---

    def _trace_records_path(self) -> Path:
        safe = "".join(
            ch if (ch.isalnum() or ch in "._-") else "_"
            for ch in (self.email or "default")
        )
        return Path(self._data_dir) / f"zulip_traces_{safe}.json"

    def _load_trace_records(self) -> dict:
        try:
            with open(self._trace_records_path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except Exception as e:
            logger.warning("zulip: unreadable trace record file, starting fresh: %s", e)
            return {}

    def _save_trace_records(self, records: dict) -> None:
        path = self._trace_records_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(records, fh)
            os.replace(tmp, path)
        except Exception as e:
            logger.debug("zulip: could not persist trace records: %s", e)

    def _persist_trace_record(
        self, key: str, chat_id: str, metadata: Any, message_id: int
    ) -> None:
        records = self._load_trace_records()
        records[key] = {
            "message_id": int(message_id),
            "chat_id": str(chat_id),
            "topic": _metadata_topic(metadata) or "",
            "started_at": time.time(),
        }
        self._save_trace_records(records)

    def _drop_trace_record(self, key: str) -> None:
        records = self._load_trace_records()
        if key in records:
            records.pop(key, None)
            self._save_trace_records(records)

    async def _recover_interrupted_traces(self) -> int:
        """Close out traces whose run died with the previous process.

        A trace can only be finalized by the process that created it, so an
        abrupt restart (deploy, crash, OOM) would leave the topic showing
        ``Working`` forever — the one case where "no trace is left permanently
        in progress" fails. Those records are collapsed here to a terminal
        cancelled board. (Issue #161)
        """
        records = self._load_trace_records()
        if not records:
            return 0

        content = "**Cancelled**\n\nrun interrupted by a gateway restart"
        recovered = 0
        for key, record in list(records.items()):
            message_id = record.get("message_id") if isinstance(record, dict) else None
            if not isinstance(message_id, int):
                # Unusable record: drop it rather than retry it every start.
                records.pop(key, None)
                continue

            ok = False
            try:
                result = await self._sdk_call(
                    self.client.update_message,
                    {"message_id": message_id, "content": content},
                    timeout=self._send_timeout,
                )
                ok = isinstance(result, dict) and result.get("result") == "success"
            except Exception as e:
                logger.warning(
                    "zulip: could not close interrupted trace [key=%s]: %s", key, e
                )

            if not ok:
                # Typical cause: the realm's message-edit limit has passed.
                # Log it and STILL clear the record, otherwise every start
                # retries an edit the server will keep refusing.
                logger.warning(
                    "zulip: interrupted trace left unfinalized"
                    " [key=%s message=%s]",
                    key,
                    message_id,
                )

            records.pop(key, None)
            recovered += 1
            try:
                await self._audit_logger.log_event(
                    "activity_trace_recovered",
                    {
                        "chat_id": mask_pii(str(record.get("chat_id", ""))),
                        "topic": str(record.get("topic", "")),
                        "message_id": message_id,
                        "finalized": ok,
                    },
                )
            except Exception:
                pass  # auditing never blocks recovery

        self._save_trace_records(records)
        if recovered:
            logger.info(
                "zulip: closed %d interrupted trace(s) after restart", recovered
            )
        return recovered

    def _start_trace(self, event: Any) -> None:
        """Begin a trace for a work item. Never raises, never blocks the run."""
        if not self._trace_cfg.enabled:
            return
        source = getattr(event, "source", None)
        chat_id = str(getattr(source, "chat_id", "") or "")
        metadata = getattr(event, "metadata", None)
        if not chat_id:
            return

        key = self._trace_key(chat_id, metadata)
        if key in self._traces:
            return  # already tracing this work item

        async def post(content: str) -> Optional[int]:
            payload = self._trace_payload(chat_id, metadata, content)
            if payload is None:
                return None
            result = await self._sdk_call(
                self.client.send_message, payload, timeout=self._send_timeout
            )
            if not isinstance(result, dict) or result.get("result") != "success":
                return None
            try:
                return int(result.get("id"))
            except (TypeError, ValueError):
                return None

        async def edit(message_id: int, content: str) -> bool:
            result = await self._sdk_call(
                self.client.update_message,
                {"message_id": message_id, "content": content},
                timeout=self._send_timeout,
            )
            return isinstance(result, dict) and result.get("result") == "success"

        trace = ActivityTrace(post, edit, self._trace_cfg)
        self._traces[key] = trace
        self._trace_started[key] = time.monotonic()
        for alias in self._session_aliases(event):
            self._trace_sessions[alias] = key
        # Posted in the background: that is one API round-trip and the agent run
        # must not wait on it. ``_finish_trace`` awaits this task before
        # finalizing, so a fast turn cannot leave a stale "Working" board.
        try:
            self._trace_start_tasks[key] = asyncio.get_running_loop().create_task(
                self._start_trace_and_persist(trace, key, chat_id, metadata)
            )
        except RuntimeError:  # no running loop (sync caller): the trace is inert
            pass

    async def _start_trace_and_persist(
        self, trace: ActivityTrace, key: str, chat_id: str, metadata: Any
    ) -> None:
        """Post the trace, then remember it so a later start can close it out.

        The record is written only once the post succeeded: with no message id
        there is nothing for recovery to finalize. (Issue #161)
        """
        ok = await trace.start()
        if ok and trace.message_id is not None:
            self._persist_trace_record(key, chat_id, metadata, trace.message_id)

    async def _finish_trace(self, event: Any, outcome: Any) -> None:
        """Finalize a work item's trace. Never raises into the gateway loop."""
        if not self._trace_cfg.enabled:
            return
        source = getattr(event, "source", None)
        chat_id = str(getattr(source, "chat_id", "") or "")
        metadata = getattr(event, "metadata", None)
        key = self._trace_key(chat_id, metadata)
        trace = self._traces.pop(key, None)
        if trace is None:
            return

        task = self._trace_start_tasks.pop(key, None)
        if task is not None:
            try:
                await task
            except Exception:
                pass  # a failed post already dropped the trace

        started = self._trace_started.pop(key, None)
        for alias, mapped in list(self._trace_sessions.items()):
            if mapped == key:
                self._trace_sessions.pop(alias, None)
        elapsed = max(0.0, time.monotonic() - started) if started else 0.0
        replied = key in self._trace_replied
        self._trace_replied.discard(key)

        status = getattr(outcome, "value", outcome)
        try:
            if status == "cancelled":
                note = f"cancelled after {elapsed:.0f}s"
                if not replied:
                    note += " — no reply sent"
                await trace.finish(note=note)
            elif status == "failure":
                note = f"run failed after {elapsed:.0f}s"
                if not replied:
                    note += " — no reply sent"
                await trace.fail(note)
            elif replied:
                await trace.finish(note=f"replied in {elapsed:.0f}s")
            else:
                # The case that used to be invisible: the run produced nothing.
                await trace.finish(
                    note=f"run finished in {elapsed:.0f}s — no reply sent"
                )
        except Exception as e:
            logger.warning("activity trace finalize failed (dropped): %s", e)
        finally:
            # Finalized here, so a later start must not try again — even when the
            # final edit failed, or recovery would retry it forever. (#161)
            self._drop_trace_record(key)

    async def on_processing_start(self, event: MessageEvent) -> None:
        """Gateway lifecycle hook: a work item started. (epic #139 / #158)"""
        self._start_trace(event)

    async def on_processing_complete(
        self, event: MessageEvent, outcome: Any = None
    ) -> None:
        """Gateway lifecycle hook: a work item finished, with its outcome.

        The gateway supplies SUCCESS / FAILURE / CANCELLED, which is what makes
        error and abort distinguishable at all — and therefore what lets a run
        that produced nothing say so instead of staying silent.
        """
        await self._finish_trace(event, outcome)

    async def _mark_read(self, message_id: Any) -> None:
        """Mark a message as read. Best-effort."""
        try:
            await self._sdk_call(
                self.client.update_message_flags,
                {"messages": [message_id], "op": "add", "flag": "read"},
                timeout=self._send_timeout,
            )
        except Exception:
            pass

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        """Initialize connection and start listening."""
        logger.info("Zulip adapter connecting...")

        # 0. Pre-flight health probe (side-effect free)
        probe_result = await probe_zulip(self.site, self.email, self.api_key, timeout=10)
        if not probe_result.get("ok"):
            error = probe_result.get("error", "unknown")
            logger.error(
                format_zulip_log(
                    "zulip probe failed",
                    site=mask_pii(self.site),
                    error=error,
                )
            )
            raise ConnectionError(f"Zulip probe failed: {error}")

        bot = probe_result.get("bot", {})
        logger.info(
            format_zulip_log(
                "zulip probe ok",
                bot=mask_pii(bot.get("full_name", "Unknown")),
                id=bot.get("id"),
            )
        )

        # 1. Verify server is reachable (no auth required)
        try:
            settings = await self._sdk_call(
                self.client.get_server_settings,
                timeout=self._connect_timeout,
            )
            if settings.get("result") != "success":
                raise ConnectionError(
                    f"Cannot reach Zulip server: {self.site}"
                )
        except Exception as e:
            logger.error(
                format_zulip_log(
                    "zulip server unreachable",
                    site=mask_pii(self.site),
                    error=mask_pii(str(e)),
                )
            )
            raise ConnectionError(f"Cannot reach Zulip server: {self.site}") from e

        # 2. Validate credentials with lightweight profile call
        try:
            result = await self._sdk_call(
                self.client.get_profile,
                timeout=self._connect_timeout,
            )
            if result.get("result") != "success":
                raise ConnectionError(f"Zulip authentication failed: {result}")
            bot_name = result.get("full_name", "Unknown")
            self.bot_full_name = result.get("full_name") or ""
            logger.info(
                format_zulip_log(
                    "zulip bot authenticated",
                    bot=mask_pii(bot_name),
                )
            )
        except Exception as e:
            logger.error(
                format_zulip_log(
                    "zulip authentication error",
                    error=mask_pii(str(e)),
                )
            )
            raise

        # 3. Log subscriptions so admins know what streams the bot sees
        try:
            subs = await self._sdk_call(
                self.client.get_subscriptions,
                timeout=self._connect_timeout,
            )
            if subs.get("result") == "success":
                stream_names = [s["name"] for s in subs.get("subscriptions", [])]
                if stream_names:
                    logger.info(
                        "zulip bot subscribed to %d stream(s)",
                        len(stream_names),
                    )
                else:
                    logger.warning(
                        "zulip bot not subscribed to any streams — "
                        "stream messages will be invisible"
                    )
        except Exception:
            # Non-fatal: subscription info is advisory
            pass

        logger.info(
            format_zulip_log(
                "zulip connection established",
                site=mask_pii(self.site),
            )
        )

        # Structured health status for monitoring tools
        logger.info(
            "health_status=connected platform=zulip site=%s account=%s",
            mask_pii(self.site),
            mask_pii(self.email),
        )

        # Start presence heartbeat so bot appears online
        self._presence_task = asyncio.create_task(self._presence_heartbeat())

        # Check for plugin updates on startup
        updater.startup_version_check(__version__, __repo__)

        # Ensure queue is registered before starting listener
        await self._queue_mgr.ensure_queue()

        # Recover interrupted messages from previous gateway instance
        bot_user_id = str(probe_result.get("bot", {}).get("id", ""))
        asyncio.create_task(
            recover_interrupted_messages(
                client=self.client,
                bot_email=self.email,
                bot_user_id=bot_user_id,
                reaction_start=self._reaction_cfg.on_start,
                reaction_success=self._reaction_cfg.on_success,
                reaction_error=self._reaction_cfg.on_error,
                handle_message=self._handle_message,
                sdk_call=self._sdk_call,
                send_timeout=self._send_timeout,
            )
        )

        self._listening = True
        self._event_task = asyncio.create_task(self._listen_for_events())
        self._mark_connected()
        return True

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        """Get information about a chat/channel."""
        if chat_id.startswith("dm:"):
            return {"name": chat_id, "type": "dm"}
        return {"name": chat_id, "type": "stream"}

    async def disconnect(self) -> None:
        """Stop listening and close connection."""
        self._listening = False
        if self._event_task:
            self._event_task.cancel()
            try:
                await self._event_task
            except asyncio.CancelledError:
                pass
        if self._presence_task:
            self._presence_task.cancel()
            try:
                await self._presence_task
            except asyncio.CancelledError:
                pass
        self._mark_disconnected()
        logger.info("Zulip adapter disconnected")
        logger.info(
            "health_status=disconnected platform=zulip site=%s account=%s",
            mask_pii(self.site),
            mask_pii(self.email),
        )

    def _needed_event_types(self) -> list:
        """Event types this adapter needs from its Zulip queue.

        ``"message"`` is always required. Features that need more subscribe to
        them through ``self._extra_event_types`` (for example reaction triggers
        add ``"reaction"``), so installs that do not use those features request
        nothing extra. A persisted queue is re-registered when this set changes,
        because ``/register`` fixes ``event_types`` for the queue's whole
        lifetime. (Issues #162, #149)
        """
        return ["message", *self._extra_event_types]

    def _register_queue(self) -> dict:
        """Register the event queue, learning the server's long-poll budget.

        ``fetch_event_types: ["realm"]`` is what makes Zulip include
        ``event_queue_longpoll_timeout_seconds`` in the response; without it
        the field is omitted and there is no way to know how long the server
        intends to hold a /events long-poll. Knowing it lets the poll loop
        abort *after* the server's own budget instead of pre-empting a healthy
        idle poll with our shorter generic read timeout. (Issue #146)
        """
        result = self.client.register(
            event_types=self._needed_event_types(),
            fetch_event_id=0,
            fetch_event_types=["realm"],
        )

        raw_budget = None
        if isinstance(result, dict):
            raw_budget = result.get("event_queue_longpoll_timeout_seconds")
        budget = _clamp_longpoll_budget(raw_budget)
        if budget is not None:
            self._events_timeout = max(
                self._read_timeout, budget + LONGPOLL_GRACE_SECONDS
            )
            logger.info(
                "zulip long-poll budget learned [server=%.0fs client_abort=%.0fs]",
                budget,
                self._events_timeout,
            )
        else:
            logger.debug(
                "zulip long-poll budget absent from /register; "
                "keeping client abort budget at %.0fs",
                self._events_timeout,
            )

        return result

    async def _presence_heartbeat(self):
        """Keep bot presence active while connected."""
        while self._listening:
            try:
                await self._sdk_call(
                    self.client.update_presence,
                    {"status": "active", "ping_only": False},
                    timeout=self._send_timeout,
                )
            except Exception:
                pass  # presence is best-effort
            await asyncio.sleep(60)

    async def _listen_for_events(self):
        """Listen for incoming Zulip messages via persistent event queue."""
        # Close out traces orphaned by an abrupt restart before taking new work
        # (issue #161). Best-effort: it must never block listening.
        try:
            await self._recover_interrupted_traces()
        except Exception as e:
            logger.warning("zulip: interrupted-trace recovery failed: %s", e)

        logger.info("zulip adapter listening [account=%s]", mask_pii(self.email))

        # Latency-gated backoff state (Issue #146). Stays 0.0 while the server
        # holds the long-poll — the healthy case, which must not slow down.
        backoff = 0.0

        while self._listening:
            try:
                queue = await self._queue_mgr.ensure_queue()

                poll_started = time.monotonic()
                events = await self._sdk_call(
                    self.client.get_events,
                    queue_id=queue.queue_id,
                    last_event_id=queue.last_event_id,
                    timeout=self._events_timeout,
                )
                poll_elapsed = time.monotonic() - poll_started

                if events.get("result") == "error":
                    msg = events.get("msg", "")
                    code = events.get("code")
                    is_bad_queue = (
                        code == "BAD_EVENT_QUEUE_ID"
                        or (code == "BAD_REQUEST" and "event newer than" in msg.lower() and "pruned" in msg.lower())
                        or "bad event queue" in msg.lower()
                    )
                    if is_bad_queue:
                        logger.warning("zulip queue expired, re-registering")
                        self._queue_mgr.mark_queue_expired()
                        continue
                    logger.warning(
                        format_zulip_log(
                            "zulip event queue error",
                            error=mask_pii(msg),
                        )
                    )
                    await asyncio.sleep(1)
                    continue

                batch_max_event_id = queue.last_event_id
                processing_tasks = []
                had_message = False
                for event in events.get("events", []):
                    event_id = event["id"]
                    if event_id > batch_max_event_id:
                        batch_max_event_id = event_id
                    if event.get("type") == "message":
                        # Any delivered message means this poll had work to do,
                        # so it is a real return even when dedupe drops it.
                        had_message = True
                        msg = _message_with_flags(event)
                        msg_id = str(msg.get("id", ""))
                        # Dedupe check
                        if self._dedupe.check(msg_id):
                            logger.debug("zulip dedupe hit [msg=%s]", mask_pii(msg_id))
                            continue
                        # Process messages concurrently so a slow model call
                        # does not block the poll loop for unrelated messages.
                        # Per-session serialization is handled by the gateway.
                        # F1 fix: resolve the topic conversation NOW, inline,
                        # in event-id order — a rename later in this batch (or
                        # processed while the handler awaits) must not fork
                        # this message into a fresh conversation under the
                        # freed name. The id is stashed; the handler reuses it.
                        self._pre_resolve_conversation(msg, msg_id)
                        task = asyncio.create_task(self._handle_message(msg))
                        processing_tasks.append(task)
                    elif event.get("type") == "update_message":
                        # Topic renames/moves: registry maintenance for stable
                        # topic sessions. Fast + ordered, handled inline.
                        self._handle_topic_update(event)
                    elif event.get("type") == "delete_message":
                        # Topic deletion (R10): the event is only a trigger;
                        # verified against the channel's topic list before
                        # anything is freed. Spawned like message handling
                        # (one API call), rare.
                        asyncio.create_task(
                            self._handle_message_delete_event(event)
                        )

                # Fire-and-forget: don't await processing tasks here so the
                # poll loop keeps fetching events. Errors are logged inside
                # _handle_message.

                # Batch update event ID
                if batch_max_event_id > queue.last_event_id:
                    self._queue_mgr.update_last_event_id(batch_max_event_id)

                # Pace only a poll the server did not hold (Issue #146).
                backoff = _next_poll_backoff(poll_elapsed, had_message, backoff)
                if backoff:
                    logger.debug(
                        "zulip poll backoff [delay=%.1fs last_poll=%.2fs]",
                        backoff,
                        poll_elapsed,
                    )
                    await asyncio.sleep(backoff)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(
                    format_zulip_log(
                        "zulip event polling error",
                        error=mask_pii(str(e)),
                    )
                )
                await asyncio.sleep(5)

    def _pre_resolve_conversation(self, msg: dict, msg_id: str) -> None:
        """Resolve (mint) a stream topic's conversation at event dispatch,
        in event-id order — the F1 fix.

        `_handle_message` runs as a deferred task, so within one poll batch
        every inline `update_message` rename applies BEFORE any message
        task starts, and a rename can also land while a handler sits in a
        pre-resolve await. Without eager resolution the handler's own
        `resolve()` would then find the old name freed and mint a fresh
        conversation under it — forking the topic's session and routing
        the reply to the resurrected old topic.

        Resolving here, inline in event-id order, makes registry
        operations strictly follow event order for messages and renames
        alike; `_handle_message` pops the stashed id instead of
        re-resolving. Messages later dropped by gating still mint their
        topic's conversation — harmless: the topic exists, so its
        conversation exists, and no gateway session is created until a
        message actually flows. Stash entries are popped at the top of
        `_handle_message` (before any early return), so nothing lingers.
        """
        if self._conversations is None:
            return
        if msg.get("type") != "stream":
            return
        stream_id = msg.get("stream_id")
        topic = msg.get("subject", "")
        if not topic or not isinstance(stream_id, int):
            return
        try:
            conversation_id = self._conversations.resolve(
                stream_id,
                topic,
                anchor_message_id=int(msg_id) if msg_id else None,
            )
        except Exception:
            logger.exception(
                "zulip pre-dispatch conversation resolve failed [msg=%s]",
                mask_pii(msg_id),
            )
            return
        self._pending_conversations[msg_id] = conversation_id

    def _handle_topic_update(self, event: dict) -> None:
        """Registry maintenance for topic renames/moves (stable topic sessions).

        Implements R2/R5 (full rename re-points; the old name keeps only a
        NULL-membership audit row), R3 (partial moves, on any channel, are
        splits: no registry change — the source topic keeps its session)
        and R8 (FULL cross-channel moves free the mapping; the freed set is
        orphaned). Never raises.
        """
        if self._conversations is None:
            return
        stream_id = event.get("stream_id")
        orig_subject = event.get("orig_subject")
        subject = event.get("subject")
        propagate_mode = event.get("propagate_mode", "")
        try:
            if not isinstance(stream_id, int) or not orig_subject:
                return  # content-only edit or malformed event
            if event.get("new_stream_id") is not None:
                # Cross-channel move. Only a FULL move (change_all) empties
                # the source topic: R8 — free the mapping here; the new
                # location becomes a fresh conversation, and the freed
                # session set has no beneficiary (orphaned). A PARTIAL move
                # (change_one/change_later) leaves the source topic alive
                # with its remaining messages — it keeps its session
                # (R3 semantics).
                if propagate_mode == "change_all":
                    freed = self._conversations.free(stream_id, orig_subject)
                    if freed:
                        logger.debug(
                            "zulip conversation freed on cross-channel move"
                            " [channel=%s conv=%s]",
                            stream_id, freed,
                        )
                return
            if not subject or subject == orig_subject:
                return  # same-topic touch (e.g. content edit)
            if propagate_mode == "change_all":
                # R2: full rename — the conversation moves to the new name;
                # the old name keeps only a NULL-membership audit row.
                moved = self._conversations.repoint(stream_id, orig_subject, subject)
                if moved:
                    logger.debug(
                        "zulip conversation repointed [channel=%s conv=%s"
                        " old=%r new=%r]",
                        stream_id, moved, mask_pii(orig_subject), mask_pii(subject),
                    )
            # R3: change_one/change_later are splits — the new name resolves
            # to a new conversation via R1 on its next message.
        except Exception as e:
            logger.warning(
                format_zulip_log(
                    "zulip topic registry update failed",
                    error=mask_pii(str(e)),
                )
            )

    def _routed_topic(self, stream_id: int, metadata: Any) -> Optional[str]:
        """Routing topic from send metadata, resolving conversation ids.

        With stable topic sessions, ``metadata["thread_id"]`` carries a
        conversation id; map it to the conversation's CURRENT topic name (R6 —
        an in-flight reply after a rename lands in the new name). For a
        conversation id that is no longer live (orphaned by a topic deletion
        or a cross-channel move while the reply was in flight), the reply
        lands on the conversation's LAST known topic name instead of
        materializing a ghost topic named like the id. Unknown ids with no
        record, and registry-less runs, return the raw value (legacy
        name-keyed sessions keep working verbatim).
        """
        raw = _metadata_topic(metadata)
        if raw and self._conversations is not None:
            try:
                current = self._conversations.current_name(int(stream_id), raw)
            except (TypeError, ValueError):
                current = None
            if current:
                return current
            if _CONVERSATION_ID_RE.fullmatch(raw):
                # Conv-shaped but not live: route by the LAST known topic
                # name from the conversation's own former_holders row (never a
                # ghost topic named like the id). No mapping is created —
                # the orphaned session stays unreachable (R4/R10 intact).
                try:
                    last = self._conversations.last_topic_of(int(stream_id), raw)
                except (TypeError, ValueError):
                    last = None
                if last:
                    return last
        return raw

    def _routed_topic_for_chat(self, chat_id: str, metadata: Any) -> Optional[str]:
        """``_routed_topic`` for chat-id strings (typing hooks)."""
        if not chat_id.isdigit():
            return _metadata_topic(metadata)
        return self._routed_topic(int(chat_id), metadata)

    # -- upgrade migration --------------------------------------------------

    def set_session_store(self, session_store: Any) -> None:
        super().set_session_store(session_store)
        if self._conversations is not None:
            try:
                self._migrate_legacy_topic_sessions()
            except Exception:
                # Fail open: a failed migration must not block adapter
                # startup; affected topics simply start fresh sessions.
                logger.exception(
                    "zulip legacy-session migration failed; continuing with fresh keys"
                )
            try:
                self._backfill_session_starts()
            except Exception:
                # Non-critical: labels fall back to the lineage origin.
                logger.debug(
                    "zulip session-start backfill failed", exc_info=True
                )

    def _migrate_legacy_topic_sessions(self) -> int:
        """One-time continuity migration (upgrade or first enable).

        Re-keys existing name-keyed zulip stream sessions to the stable
        conversation-id keys, so users keep their current sessions when
        the feature turns on instead of starting fresh per topic:

            agent:<ns>:zulip:stream:<ch>:<topic>  ->  ...:<ch>:<conv_id>

        The registry is seeded with the (topic -> conversation) mapping in
        the same pass; transcripts are untouched (the session id does not
        change, only its routing key). The greedy key tail is parsed
        shape-aware (see ``_split_session_key_tail``):

        - an email-shaped trailing segment is a per-user suffix
          (``group_sessions_per_user`` / ``thread_sessions_per_user``
          deployments) and is preserved on the re-keyed key;
        - a head matching the conversation-id format is recognized as
          already conv-keyed only when the REGISTRY knows that
          conversation (live row or orphaned audit row) — an id-shaped
          head the registry does not know is a legacy session for a topic
          literally named like an id, and migrates normally;
        - an email-shaped head (feature-off legacy key: the tail is the
          sender, not a topic) is left in place — minting a topic for it
          would create a junk conversation and rekey the session to a key
          nothing routes to.

        A name-keyed route whose conv-keyed successor already exists
        (previous enable cycle) is dropped as stale. Runs before the
        first message flows (the gateway wires ``set_session_store``
        during adapter setup).

        Uses the store's routing internals (``_entries``/``_save`` under
        ``_lock``) the same way the store's own ``rekey_profile_routing``
        does — no per-key public rekey API exists on the store yet;
        revisit on gateway upgrades.
        """
        if self._conversations is None:
            return 0
        store = getattr(self, "_session_store", None)
        entries = getattr(store, "_entries", None)
        lock = getattr(store, "_lock", None)
        save = getattr(store, "_save", None)
        if entries is None or lock is None or save is None:
            logger.debug(
                "zulip legacy-session migration skipped: no compatible session store"
            )
            return 0
        with lock:
            moves = []
            for key, entry in list(entries.items()):
                m = _LEGACY_ZULIP_STREAM_KEY.match(key)
                if m is None:
                    continue
                head, user_suffix = _split_session_key_tail(m["topic"])
                if _CONVERSATION_ID_RE.fullmatch(head):
                    if self._conversations.has_conversation(
                        int(m["channel"]), head
                    ):
                        # Registry knows this conversation: the key is
                        # already conv-keyed (with or without a per-user
                        # suffix). An unknown id-shaped head falls through —
                        # it is a legacy session for a topic literally named
                        # like a conversation id, and migrates normally.
                        continue
                elif "@" in head:
                    # Feature-off legacy key: the tail is the sender (a
                    # per-stream-per-user session), not a topic name. Leave
                    # it in place — there is no per-topic successor key for
                    # it, and minting a topic would strand the session.
                    continue
                conversation_id = self._conversations.resolve(
                    int(m["channel"]), head
                )
                new_key = f"{m['prefix']}{conversation_id}"
                if user_suffix:
                    # Preserve the per-user suffix so the re-keyed key
                    # matches what the gateway will build post-enable.
                    new_key = f"{new_key}:{user_suffix}"
                if new_key in entries:
                    # The conv-keyed session is the successor; the name-keyed
                    # route is stale residue from a previous enable cycle.
                    entries.pop(key, None)
                    logger.info(
                        "zulip legacy migration dropped stale route [key=%s]",
                        mask_pii(key),
                    )
                    continue
                moves.append((key, new_key, entry))
            for old_key, new_key, entry in moves:
                entries.pop(old_key, None)
                entries[new_key] = _dc_replace(entry, session_key=new_key)
            if moves:
                save()
        if moves:
            logger.info(
                "zulip legacy-session migration: rekeyed %d session(s)", len(moves)
            )
        return len(moves)

    def _route_entries(self) -> dict:
        """Live gateway routing entries keyed by ``session_key`` (public
        ``SessionStore.list_sessions()``; empty on any failure)."""
        store = getattr(self, "_session_store", None)
        if store is None:
            return {}
        try:
            entries = store.list_sessions() or []
        except Exception as exc:
            logger.debug("zulip store.list_sessions unavailable: %s", exc)
            return {}
        return {e.session_key: e for e in entries}

    def _entry_for_conversation(self, entries: dict, conversation_id: str):
        """The routing entry whose key tail is this conversation id."""
        for key, entry in entries.items():
            if key.rsplit(":", 1)[-1] == conversation_id:
                return key, entry
        return None, None

    def _observe_session_start(
        self, stream_id: int, conversation_id: str
    ) -> None:
        """First sight of a conversation's live session records its start.

        Labels are per session (the topic name where the session was
        created — the current name for a freshly minted generation), not
        per lineage, so they stay truthful across renames between
        generations. First record wins; derivation (see
        ``derive_session_start``) covers sessions minted before the
        labels existed. Failures never disturb message flow.
        """
        if self._conversations is None:
            return
        try:
            _key, entry = self._entry_for_conversation(
                self._route_entries(), conversation_id
            )
            if entry is None or not entry.session_id:
                return
            if (
                self._conversations.session_start(stream_id, entry.session_id)
                is None
            ):
                self._conversations.record_session_start(
                    stream_id, conversation_id, entry.session_id
                )
        except Exception:
            logger.debug(
                "zulip session-start observation failed [conv=%s]",
                conversation_id, exc_info=True,
            )

    def _backfill_session_starts(self) -> int:
        """Record start labels for every known session (idempotent).

        Runs at store wiring after the legacy migration: for each live
        conversation, enumerate its gateway sessions (live routing entry
        plus past generations) and record each missing label via the
        registry's derivation. ``INSERT OR IGNORE`` means existing
        records always win and restarts only ever fill gaps.
        """
        if self._conversations is None:
            return 0
        entries = self._route_entries()
        db = self._session_db()
        recorded = 0
        for channel_id, conversation_id in self._conversations.iter_conversations():
            key, entry = self._entry_for_conversation(entries, conversation_id)
            ids = []
            if entry is not None and entry.session_id:
                ids.append(entry.session_id)
            if db is not None and key is not None:
                try:
                    rows = db.list_sessions_rich(
                        session_key=key, limit=50,
                        order_by_last_active=True, include_hidden=True,
                    )
                except Exception as exc:
                    logger.debug(
                        "zulip session enumeration unavailable [conv=%s]: %s",
                        conversation_id, exc,
                    )
                    rows = []
                for row in rows:
                    sid = (row or {}).get("id") or (row or {}).get(
                        "session_id")
                    if sid and sid not in ids:
                        ids.append(sid)
            for sid in ids:
                if self._conversations.session_start(channel_id, sid) is None:
                    self._conversations.record_session_start(
                        channel_id, conversation_id, sid
                    )
                    recorded += 1
        if recorded:
            logger.debug(
                "zulip session-start backfill recorded %d labels", recorded
            )
        return recorded

    def _session_db(self):
        """Gateway seam: ``SessionStore._db`` (the state-db handle, v0.21.5).

        Used read-only for PAST gateway-session generations, which exist in
        the sessions table but not in the routing index. Guarded: any shape
        change degrades the listing/switch features gracefully (no counts,
        live-session-only /continue) instead of raising.
        """
        store = getattr(self, "_session_store", None)
        return getattr(store, "_db", None)

    def _topic_sessions_command_reply(self, stream_id: int, topic: str) -> str:
        """``/topic-sessions`` (topic sessions): list this topic's session set.

        Read-only for bindings: the current session plus every former
        session, each labeled with the topic where it was created. The
        only write is the first-sight start-label record (v6): ``/new``
        is core-handled and never reaches this adapter, so a fresh
        generation checked before any message traffic must be observed
        here — otherwise its line falls back to the lineage origin
        (Topic261002-2 case). Bindings are not changed;
        ``/continue <session-id>`` (R7) switches.
        """

        if self._conversations is None:
            return (
                "Topic sessions are disabled"
                " (set ZULIP_TOPIC_SESSIONS=true to enable them)."
            )
        current_id, current_origin, members = self._conversations.sessions_for_topic(
            stream_id, topic
        )
        # First sight counts here too (see docstring): observe the live
        # session so its line below shows the name it was minted under.
        if current_id is not None:
            self._observe_session_start(stream_id, current_id)

        entries = self._route_entries()
        db = self._session_db()
        store_missing = getattr(self, "_session_store", None) is None

        def _lineage_sessions(conversation_id: str):
            """All known gateway sessions of one lineage, newest first,
            plus the currently-live id (None when the lineage has no live
            routing entry). Users never see the lineage id itself — only
            its gateway session ids, labeled with the lineage's origin."""
            key, entry = self._entry_for_conversation(entries, conversation_id)
            live = entry.session_id if entry is not None else None
            ids = []
            if db is not None and key is not None:
                try:
                    rows = db.list_sessions_rich(
                        session_key=key, limit=50,
                        order_by_last_active=True, include_hidden=True,
                    )
                except Exception as exc:
                    logger.debug(
                        "zulip session enumeration unavailable [conv=%s]: %s",
                        conversation_id, exc,
                    )
                    rows = []
                for row in rows:
                    sid = (row or {}).get("id") or (row or {}).get(
                        "session_id")
                    if sid and sid not in ids:
                        ids.append(sid)
            if live is not None and live not in ids:
                ids.insert(0, live)
            return live, ids

        # Degraded mode (gateway store not wired): the gateway session ids
        # cannot be known, so lines render without ids rather than falling
        # back to lineage ids (which are plumbing, never user-facing).
        lines = []
        if store_missing:
            # Degraded (gateway store not wired): the gateway session ids
            # cannot be known, so lines render without ids rather than
            # falling back to lineage ids (plumbing, never user-facing).
            number = 0
            if current_id is not None:
                number += 1
                lines.append(
                    f"{number}) **(current)**"
                    f' — started in "{current_origin}"'
                )
            for _member_id, member_origin in members:
                number += 1
                lines.append(f'{number}) — started in "{member_origin}"')
            body = [f"📋 Sessions in this topic: {number}"]
            if lines:
                body += ["", *lines]
            if number > 1:
                body += [""]
                body.append(
                    "Use `/continue <session-id>` to switch to another"
                    " session."
                )
            logger.debug(
                "zulip /topic-sessions listing (degraded)"
                " [channel=%s topic=%r count=%d]",
                stream_id, mask_pii(topic), number,
            )
            return "\n".join(body)

        lines = []
        number = 0
        for is_current, origin, conv in (
            [(True, current_origin, current_id)] if current_id is not None else []
        ) + [(False, origin, member_id) for member_id, origin in members]:
            live, ids = _lineage_sessions(conv)
            for position, sid in enumerate(ids):
                number += 1
                if is_current and sid == live:
                    marker = " **(current)**"
                elif not is_current and (
                    sid == live or (position == 0 and live is None)
                ):
                    marker = " **(last)**"
                else:
                    marker = ""
                label = (
                    self._conversations.session_start(stream_id, sid)
                    or origin
                )
                lines.append(
                    f'{number}) `{sid}`{marker} — started in "{label}"'
                )
        body = [f"📋 Sessions in this topic: {number}"]
        if lines:
            body += ["", *lines]
        if number > 1:
            body += [""]
            body.append(
                "Use `/continue <session-id>` to switch to another session."
            )
        logger.debug(
            "zulip /topic-sessions listing [channel=%s topic=%r count=%d]",
            stream_id, mask_pii(topic), number,
        )
        return "\n".join(body)

    def _continue_command_reply(
        self, stream_id: int, topic: str, arg: str = ""
    ) -> str:
        """``/continue <gateway-session-id>`` (R7, inheritance-scoped).

        Switches this topic to a gateway session from ITS OWN session
        set — the lineages it created plus those handed to it by full
        renames (merges) — as listed by ``/topic-sessions``. Only a
        gateway session id is accepted (user ruling): lineage
        (conversation) ids are grouping labels, not switch tokens.
        Bare ``/continue`` does nothing: there is no implicit pick, and
        a session held by another topic (or orphaned) can never be
        named here, because its lineage is not part of this topic's set.
        """
        if self._conversations is None:
            return (
                "Topic sessions are disabled"
                " (set ZULIP_TOPIC_SESSIONS=true to enable them)."
            )
        arg = (arg or "").strip()
        if not arg:
            return (
                "Usage: `/continue <session-id>` — switch this topic to one"
                " of its own gateway sessions (`YYYYMMDD_HHMMSS_hex`, as"
                " listed by `/topic-sessions`). `/continue` alone does"
                " nothing."
            )
        token = arg.split()[0]
        if _GATEWAY_SESSION_ID_RE.fullmatch(token):
            return self._continue_to_gateway_session(stream_id, topic, token)
        return (
            "That is not a session id shown by `/topic-sessions`."
            " Nothing was changed."
        )

    def _continue_to_gateway_session(
        self, stream_id: int, topic: str, session_id: str
    ) -> str:
        """/continue <gateway-session-id>: one-command switch.

        Resolves the gateway session (live via the routing index, past
        generations via the state-db seam), verifies its conversation
        belongs to THIS topic's own set (R7 inheritance law — a session
        held by another topic or orphaned is never reachable), re-binds
        the topic when needed, and switches the gateway session — all in
        one command.
        """
        store = getattr(self, "_session_store", None)
        if store is None:
            return (
                "Session switching is unavailable (no session store wired)."
                " Nothing was changed."
            )

        # 1. Resolve the session to its routing key / conversation.
        key = None
        entry = None
        try:
            entry = store.lookup_by_session_id(session_id)
        except Exception as exc:
            logger.debug("zulip lookup_by_session_id failed: %s", exc)
        if entry is not None:
            key = entry.session_key
        else:
            db = self._session_db()
            if db is not None:
                try:
                    row = db.get_session(session_id)
                except Exception as exc:
                    logger.debug("zulip get_session failed: %s", exc)
                    row = None
                key = (row or {}).get("session_key")
        if not key:
            return (
                f"No session `{session_id}` was found — use a session id"
                " shown by `/topic-sessions`. Nothing was changed."
            )
        conversation_id = key.rsplit(":", 1)[-1]
        if not _CONVERSATION_ID_RE.fullmatch(conversation_id):
            return (
                "That session is not part of this topic's sessions — use a"
                " session id shown by `/topic-sessions`. Nothing was changed."
            )

        # 2. Inheritance verification (R7): the conversation must be part
        # of this topic's own set.
        current = self._conversations.lookup(stream_id, topic)
        if current is None:
            return "This topic has no session yet — nothing to continue."
        if conversation_id == current and entry is not None:
            return f"Already talking in session `{session_id}` here."
        if conversation_id != current:
            member_ids = {
                member_id
                for member_id, _origin in self._conversations.sessions_for_topic(
                    stream_id, topic
                )[2]
            }
            if conversation_id not in member_ids:
                return (
                    "That session is not one of this topic's sessions —"
                    " use a session id shown by `/topic-sessions`."
                    " Nothing was changed."
                )
            self._conversations.rebind(stream_id, topic, conversation_id)

        # 3. Switch the gateway session under the lineage's key.
        entries = self._route_entries()
        expected = entries[key].session_id if key in entries else None
        try:
            switched = store.switch_session(
                key, session_id, expected_session_id=expected
            )
        except Exception as exc:
            logger.warning(
                "zulip switch_session failed [key=%s target=%s]: %s",
                mask_pii(key), session_id, exc,
            )
            switched = None
        origin = self._conversations.sessions_for_topic(stream_id, topic)[1]
        if switched is None:
            if key not in self._route_entries():
                return (
                    "The topic binding moved, but the gateway has no live"
                    " route for that lineage yet — send a message and it"
                    " will start there."
                )
            return (
                "That lineage moved while switching — please try"
                " `/continue` again."
            )
        self._conversations.record_session_start(
            stream_id, conversation_id, session_id
        )
        label = (
            self._conversations.session_start(stream_id, session_id) or origin
        )
        logger.debug(
            "zulip gateway session switched via /continue"
            " [channel=%s conv=%s session=%s topic=%r]",
            stream_id, conversation_id, session_id, mask_pii(topic),
        )
        return (
            f"🔗 This topic now talks in session `{session_id}`"
            f', started in **{label}**.'
        )

    async def _handle_message_delete_event(self, event: dict) -> None:
        """R10 trigger: a ``delete_message`` event on a mapped topic.

        ANY delete event on a mapped stream topic triggers a verification
        — single-message deletes included, so a topic emptied message-by-
        message (whatever the delete order, anchor first or last) is
        detected by its final delete. The event itself cannot tell a
        topic deletion from a partial one (partial bulk deletes exist —
        deleting 2 of 9 messages is bulk but not a topic deletion), so
        the channel's topic list (``get_stream_topics``) is the
        authority: a topic exists while it has messages. Fail-open: on
        any verification problem the mapping stays.
        """
        if self._conversations is None:
            return
        if event.get("message_type") != "stream":
            return
        stream_id = event.get("stream_id")
        topic = event.get("topic", "")
        if not isinstance(stream_id, int) or not topic:
            return
        if self._conversations.lookup(stream_id, topic) is None:
            return
        # Awaited inline so the spawned task (see the poll loop) covers the
        # whole chain: trigger check -> topic-list verification -> orphaning.
        await self._apply_topic_deletion(stream_id, topic)

    async def _apply_topic_deletion(self, stream_id: int, topic: str) -> None:
        """Verify a deletion trigger against the channel's topic list and,
        only if the topic is really gone, orphan its session set (R10)."""
        try:
            result = await self._sdk_call(
                self.client.get_stream_topics, stream_id, timeout=10.0
            )
        except Exception:
            logger.exception(
                "zulip topic-deletion verification failed; mapping kept"
                " [channel=%s topic=%r]",
                stream_id,
                mask_pii(topic),
            )
            return
        if not isinstance(result, dict) or result.get("result") != "success":
            logger.warning(
                "zulip topic-deletion verification unavailable; mapping kept"
                " [channel=%s topic=%r]",
                stream_id,
                mask_pii(topic),
            )
            return
        names = {str(t.get("name", "")) for t in (result.get("topics") or [])}
        if topic in names:
            logger.info(
                "zulip delete event verified: topic still exists — ignored"
                " [channel=%s topic=%r]",
                stream_id,
                mask_pii(topic),
            )
            return
        orphaned = self._conversations.orphan_topic_sessions(stream_id, topic)
        logger.info(
            "zulip topic deleted — session set orphaned (no beneficiary)"
            " [channel=%s topic=%r former=%d]",
            stream_id,
            mask_pii(topic),
            orphaned,
        )

    async def _handle_message(self, message: dict):
        """Process incoming Zulip message."""
        message_id = message.get("id")
        # Pop the conversation resolved at dispatch (if any) up front —
        # before ANY early return, the self-message filter below included —
        # so a pre-resolved self-message cannot leak a stash entry.
        pre_resolved_conversation = (
            self._pending_conversations.pop(str(message_id), None)
            if message_id is not None
            else None
        )

        # Filter self-messages to prevent loops
        if message.get("sender_email") == self.email:
            return

        msg_type = message.get("type")  # "stream" or "private"
        content = message.get("content", "")
        sender_email = message.get("sender_email", "")
        sender_full_name = message.get("sender_full_name", "Unknown")

        # --- Rate limiting (per-sender) ---
        sender_key = sender_email or str(message.get("sender_id", ""))
        if not self._rate_limiter.check(sender_key):
            logger.warning(
                "zulip rate limit hit [sender=%s msg=%s]",
                mask_pii(sender_key),
                mask_pii(str(message_id)),
            )
            await self._audit_logger.log_rate_limit_exceeded(
                sender_id=sender_key,
                limit=self._rate_limiter.config["max_per_minute"],
            )
            return

        # Strip Zulip @-mention syntax and HTML
        content = strip_html_to_text(content)

        # --- Reactions ---
        # Constructed here so the error path below can reach it, but not
        # started until the message has cleared every drop path. See the
        # acknowledgement block after stream gating.
        reactions = ReactionLifecycle(
            self.client, str(message_id), self._reaction_cfg,
            timeout=self._send_timeout,
        )

        # --- Stream trigger gating ---
        if msg_type == "stream":
            # str() guard: Zulip sends a string here for stream messages, but a
            # malformed event would otherwise raise AttributeError inside the
            # handler rather than being skipped.
            stream_name = str(message.get("display_recipient", ""))
            chatmode, onchar_prefixes, require_mention = _resolve_chatmode(stream_name)

            # Check onchar trigger
            onchar_triggered, stripped = strip_onchar_prefix(content, onchar_prefixes)
            if onchar_triggered:
                content = stripped

            # Check mention (simple substring; bot username from email prefix)
            # Mention detection.
            #
            # Zulip's own "mentioned" flag is authoritative: the server sets it
            # for personal mentions regardless of which markup form was used,
            # so it covers @**Name**, @_**Name** and @**Name|id** without this
            # adapter having to parse any of them. Text matching is only a
            # fallback for events that arrive without flags.
            bot_username = self.email.split("@")[0] if self.email else ""
            mention_regex = (
                create_mention_regex(bot_username, self.bot_full_name)
                if bot_username
                else None
            )
            was_mentioned = "mentioned" in (message.get("flags") or [])
            if not was_mentioned and mention_regex:
                was_mentioned = bool(mention_regex.search(content))

            # Apply gating
            should_process = False
            if chatmode == "onmessage":
                should_process = True
            elif chatmode == "oncall":
                should_process = was_mentioned
            elif chatmode == "onchar":
                should_process = onchar_triggered or was_mentioned

            # requireMention acts as additional gate (ignored in onmessage mode)
            if chatmode != "onmessage" and require_mention and not was_mentioned and not onchar_triggered:
                should_process = False

            if not should_process:
                logger.debug("zulip drop [mode=%s, no trigger] msg=%s", chatmode, mask_pii(str(message_id)))
                return

            # --- Stream filtering (Issue #65) ---
            if self._streams_filter is not None:
                stream_name = message.get("display_recipient", "").lower()
                if stream_name not in self._streams_filter:
                    logger.debug(
                        "zulip drop [stream=%s not in filter] msg=%s",
                        mask_pii(stream_name),
                        mask_pii(str(message_id)),
                    )
                    return

            # --- Group policy check (Issue #66) ---
            if not self._policy.can_group_message(sender_email):
                await self._audit_logger.log_policy_block(
                    sender_id=sender_email,
                    reason=f"group_policy={self._policy.group_mode}",
                    kind="stream",
                )
                if self._policy.group_mode == "disabled":
                    reply = "🚫 Stream messages to this bot are currently disabled."
                else:
                    reply = "🚫 You are not authorized to send stream messages to this bot."
                try:
                    await self._sdk_call(
                        self.client.send_message,
                        {
                            "type": "stream",
                            # Read from the message rather than relying on
                            # locals set elsewhere: these were previously bound
                            # as a side effect of the typing-indicator block,
                            # which now runs after this point.
                            "to": message.get("stream_id"),
                            "topic": message.get("subject", ""),
                            "content": reply,
                        },
                        timeout=self._send_timeout,
                    )
                except Exception as e:
                    logger.warning("group policy rejection reply failed: %s", mask_pii(str(e)))
                # Mark message as read and stop processing
                try:
                    await self._sdk_call(
                        self.client.update_message_flags,
                        {"messages": [message_id], "op": "add", "flag": "read"},
                        timeout=self._send_timeout,
                    )
                except Exception:
                    pass
                logger.info(
                    "zulip group message blocked [policy=%s sender=%s stream=%s]",
                    self._policy.group_mode,
                    mask_pii(sender_email),
                    mask_pii(str(message.get("display_recipient", ""))),
                )
                return

            # Normalize mention from content
            if was_mentioned and mention_regex:
                if mention_regex.search(content):
                    content = normalize_mention(content, mention_regex)
                else:
                    logger.debug(
                        "zulip mention flagged by server but not found in text "
                        "[msg=%s]; passing content through unmodified",
                        message_id,
                    )

        # --- Acknowledge the message ---
        #
        # Deliberately after all stream gating, stream filtering, and group
        # policy checks. These signals used to fire before them, so a message
        # the bot then dropped was left with a permanent "typing..." indicator
        # and an uncleared start reaction — the bot appeared to be thinking
        # about a message it had already discarded, forever.
        #
        # Direct messages skip the stream block above and reach here normally.
        await reactions.start()

        # Typing is owned by the gateway core's keep-typing loop, which calls
        # the send_typing/stop_typing hooks above every ~2s for the whole
        # agent run. The manual start this block used to do only ever lasted
        # ZULIP_TYPING_DELAY_SECONDS, because handle_message() returns as
        # soon as the background agent task is spawned — a ~2s flash instead
        # of a real thinking indicator. Left as None so the legacy
        # _stop_typing(typing_params) calls in the command/policy paths stay
        # safe no-ops.
        typing_params = None

        # --- Command interception (before AI dispatch) ---
        if is_command(content):
            sender_email = message.get("sender_email", "")
            sender_full_name = message.get("sender_full_name", "")
            # Determine chat_id early for command replies
            if msg_type == "stream":
                cmd_chat_id = str(message.get("stream_id", ""))
                cmd_topic = message.get("subject", "")
            else:
                cmd_chat_id = _private_chat_id(message)
                cmd_topic = None

            # /continue and /topic-sessions (stable topic sessions): manual
            # re-bind, and the read-only listing of this topic's sessions.
            topic_cmd = (
                content.strip().lower()
                if self._conversations is not None and msg_type == "stream"
                else ""
            )
            if topic_cmd == "/continue" or topic_cmd.startswith("/continue "):
                cmd_result = CommandResult(
                    handled=True,
                    reply=self._continue_command_reply(
                        int(message.get("stream_id") or 0),
                        cmd_topic or "",
                        topic_cmd[len("/continue"):].strip(),
                    ),
                )
            elif topic_cmd == "/topic-sessions":
                cmd_result = CommandResult(
                    handled=True,
                    reply=self._topic_sessions_command_reply(
                        int(message.get("stream_id") or 0), cmd_topic or ""
                    ),
                )
            else:
                cmd_result = handle_command(
                    content=content,
                    chat_id=cmd_chat_id,
                    sender_email=sender_email,
                    sender_name=sender_full_name,
                    version=__version__,
                )
            if cmd_result.handled:
                # Send command reply directly
                try:
                    if msg_type == "stream":
                        await self._sdk_call(
                            self.client.send_message,
                            {
                                "type": "stream",
                                "to": message.get("stream_id"),
                                "topic": cmd_topic,
                                "content": cmd_result.reply,
                            },
                            timeout=self._send_timeout,
                        )
                    else:
                        await self._sdk_call(
                            self.client.send_message,
                            {
                                "type": "private",
                                "to": _private_recipient_ids(message),
                                "content": cmd_result.reply,
                            },
                            timeout=self._send_timeout,
                        )
                except Exception as e:
                    logger.warning("command reply failed: %s", mask_pii(str(e)))
                # Clean up: stop typing, mark as read
                await self._stop_typing(typing_params)
                await self._mark_read(message_id)
                return

        # --- DM policy check (Issue #48) ---
        if msg_type == "private":
            sender_email = message.get("sender_email", "")
            allowed, pairing_code = self._policy.check_dm(sender_email)
            if not allowed:
                await self._audit_logger.log_policy_block(
                    sender_id=sender_email,
                    reason=f"dm_policy={self._policy.mode}",
                    kind="dm",
                )
                reply = ""
                if pairing_code:
                    reply = (
                        f"👋 Hi! You need to be approved before messaging this bot.\n\n"
                        f"Your pairing code: **PAIR-{pairing_code}**\n\n"
                        f"Share this code with your admin to get access."
                    )
                elif self._policy.mode == "disabled":
                    reply = "🚫 DMs to this bot are currently disabled."
                else:
                    reply = "🚫 You are not authorized to message this bot."

                try:
                    await self._sdk_call(
                        self.client.send_message,
                        {
                            "type": "private",
                            "to": _private_recipient_ids(message),
                            "content": reply,
                        },
                        timeout=self._send_timeout,
                    )
                except Exception as e:
                    logger.warning("DM policy rejection failed: %s", mask_pii(str(e)))

                # Clean up: stop typing, mark as read
                await self._stop_typing(typing_params)
                await self._mark_read(message_id)
                logger.info("zulip DM blocked [policy=%s sender=%s]", self._policy.mode, mask_pii(sender_email))
                return

        if msg_type == "stream":
            stream_id = message.get("stream_id")
            topic = message.get("subject", "")
            stream_name = message.get("display_recipient", str(stream_id))

            # Cache topic for reply threading
            chat_id = str(stream_id)
            self._topic_cache[chat_id] = topic

            source_kwargs: dict[str, Any] = {
                "chat_id": chat_id,
                "chat_name": stream_name,
                "chat_type": "stream",
                "user_id": sender_email,
                "user_name": sender_full_name,
            }
            if topic and self._conversations is not None:
                # Sessions key on a rename-proof conversation id — never the
                # topic name. Renames must not strand or fabricate sessions;
                # /new is the only way to start a fresh session in a topic.
                if isinstance(stream_id, int):
                    if pre_resolved_conversation is not None:
                        # Resolved at dispatch, in event-id order (F1) — a
                        # rename processed since then must not fork this
                        # message onto a fresh conversation.
                        source_kwargs["thread_id"] = pre_resolved_conversation
                    else:
                        source_kwargs["thread_id"] = self._conversations.resolve(
                            stream_id,
                            topic,
                            anchor_message_id=int(message_id) if message_id else None,
                        )
                    # Per-session start labels (v6): first sight of the
                    # conversation's live session records where it started.
                    self._observe_session_start(
                        stream_id, source_kwargs["thread_id"]
                    )
                # Malformed stream_id: no thread_id → degrades to the
                # per-stream session (unreachable for well-formed events).
            source = self.build_source(**source_kwargs)
            extra_meta = {"topic": topic, "stream_id": stream_id}
        else:
            sender_id = message.get("sender_id")
            chat_id = _private_chat_id(message)

            # DM session rotation: prevent context bloat by rotating
            # the session key every N turns (default 20, 0 to disable).
            if self._dm_session_turn_limit > 0:
                base_key = chat_id
                turn_count = self._dm_base_message_counts.get(base_key, 0) + 1
                self._dm_base_message_counts[base_key] = turn_count
                epoch = (turn_count - 1) // self._dm_session_turn_limit
                if epoch > 0:
                    chat_id = f"{base_key}:session:{epoch}"

            source = self.build_source(
                chat_id=chat_id,
                chat_name=sender_full_name,
                chat_type="dm",
                user_id=sender_email,
                user_name=sender_full_name,
            )
            extra_meta = {
                "user_id": sender_id,
                "user_email": sender_email,
                "recipient_ids": _private_recipient_ids(message),
            }

        # --- Context-mitigation metadata ---
        now = time.time()
        msg_count = self._message_counts.get(chat_id, 0) + 1
        self._message_counts[chat_id] = msg_count

        last_time = self._last_message_time.get(chat_id)
        session_gap = (now - last_time) if last_time else 0
        self._last_message_time[chat_id] = now

        # Detect topic change in streams
        topic_changed = False
        if msg_type == "stream":
            prev_topic = self._last_topic_cache.get(chat_id)
            if prev_topic and prev_topic != topic:
                topic_changed = True
            self._last_topic_cache[chat_id] = topic

        extra_meta.update({
            "conversation_turn": msg_count,
            "session_gap_seconds": round(session_gap, 1),
            "topic_changed": topic_changed,
        })

        event = MessageEvent(
            text=content,
            message_type=MessageType.TEXT,
            source=source,
            message_id=str(message_id),
            metadata=extra_meta,
        )

        try:
            await self.handle_message(event)
        except Exception:
            await reactions.error()
            await self._stop_typing(typing_params)
            raise
        finally:
            await self._mark_read(message_id)

        # Only reached on success. The core stops typing itself via the
        # stop_typing() hook when the agent run finishes; mark the success
        # reaction here.
        await reactions.success()

    async def resolve_topic(self, stream_id: int, topic: str) -> dict[str, Any]:
        """Mark a topic as resolved by prepending ✔.

        Returns the API response dict. If the topic is already resolved,
        returns early without calling the API.
        """
        trimmed = topic.strip()
        if not trimmed:
            return {"skipped": True, "reason": "empty topic"}

        resolved_prefix = "✔ "
        if trimmed.startswith(resolved_prefix):
            return {"skipped": True, "reason": "already resolved", "topic": trimmed}

        resolved_topic = resolved_prefix + trimmed
        try:
            result = await self._sdk_call(
                self.client.update_message,
                {
                    "message_id": 0,  # Not used for topic updates with propagate_mode
                    "topic": resolved_topic,
                    "propagate_mode": "change_all",
                },
                timeout=self._send_timeout,
            )
            if result.get("result") == "success":
                logger.info(
                    "zulip topic resolved [stream_id=%d old=%s new=%s]",
                    stream_id,
                    trimmed,
                    resolved_topic,
                )
                return {"ok": True, "stream_id": stream_id, "topic": resolved_topic}
            else:
                logger.warning(
                    "zulip topic resolution failed [stream_id=%d topic=%s error=%s]",
                    stream_id,
                    trimmed,
                    result.get("msg"),
                )
                return {"ok": False, "error": result.get("msg")}
        except Exception as e:
            logger.error(
                "zulip topic resolution error [stream_id=%d topic=%s]: %s",
                stream_id,
                trimmed,
                e,
            )
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------
    # Zulip API Features: Search, Stream CRUD, User Management, Deletion
    # ------------------------------------------------------------------

    async def fetch_messages(
        self,
        stream: str,
        topic: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """Fetch recent messages from a stream, optionally filtered by topic.

        Uses Zulip's /messages endpoint with narrow filters.
        Returns a list of message dicts.
        """
        stream = _validate_string_length(stream, "stream")
        if topic:
            topic = _validate_string_length(topic, "topic")

        narrow = [{"operator": "stream", "operand": stream}]
        if topic:
            narrow.append({"operator": "topic", "operand": topic})

        try:
            result = await self._sdk_call(
                self.client.get_messages,
                {
                    "anchor": "newest",
                    "num_before": min(max(1, limit), 1000),
                    "num_after": 0,
                    "narrow": narrow,
                },
                timeout=self._send_timeout,
            )
            if result.get("result") == "success":
                return result.get("messages", [])
            logger.warning("fetch_messages failed: %s", result.get("msg"))
            return []
        except Exception as e:
            logger.error("fetch_messages error: %s", e)
            return []

    async def search_messages(
        self,
        query: str,
        stream: Optional[str] = None,
        topic: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict]:
        """Search messages by query, optionally scoped to stream/topic."""
        query = _validate_string_length(query, "query")
        if stream:
            stream = _validate_string_length(stream, "stream")
        if topic:
            topic = _validate_string_length(topic, "topic")
        narrow = [{"operator": "search", "operand": query}]
        if stream:
            narrow.append({"operator": "stream", "operand": stream})
        if topic:
            narrow.append({"operator": "topic", "operand": topic})

        try:
            result = await self._sdk_call(
                self.client.get_messages,
                {
                    "anchor": "newest",
                    "num_before": min(max(1, limit), 1000),
                    "num_after": 0,
                    "narrow": narrow,
                },
                timeout=self._send_timeout,
            )
            if result.get("result") == "success":
                return result.get("messages", [])
            logger.warning("search_messages failed: %s", result.get("msg"))
            return []
        except Exception as e:
            logger.error("search_messages error: %s", e)
            return []

    async def list_streams(self) -> list[dict]:
        """List all streams the bot can see."""
        try:
            result = await self._sdk_call(
                self.client.get_streams,
                timeout=self._send_timeout,
            )
            if result.get("result") == "success":
                return result.get("streams", [])
            return []
        except Exception as e:
            logger.error("list_streams error: %s", e)
            return []

    async def subscribe_stream(self, stream_name: str) -> bool:
        """Subscribe the bot to a stream."""
        stream_name = _validate_string_length(stream_name, "stream_name")
        try:
            result = await self._sdk_call(
                self.client.add_subscriptions,
                {stream_name},
                timeout=self._send_timeout,
            )
            return result.get("result") == "success"
        except Exception as e:
            logger.error("subscribe_stream error: %s", e)
            return False

    async def delete_message(self, message_id: int) -> bool:
        """Delete a message by ID."""
        try:
            validated_id = self._validate_message_id(message_id)
            result = await self._sdk_call(
                self.client.delete_message,
                validated_id,
                timeout=self._send_timeout,
            )
            return result.get("result") == "success"
        except Exception as e:
            logger.error("delete_message error: %s", e)
            return False

    async def get_user_presence(self, user_id_or_email: str) -> Optional[dict]:
        """Get presence status for a user."""
        try:
            result = await self._sdk_call(
                self.client.get_user_presence,
                user_id_or_email,
                timeout=self._send_timeout,
            )
            if result.get("result") == "success":
                return result.get("presence")
            return None
        except Exception as e:
            logger.error("get_user_presence error: %s", e)
            return None

    async def star_message(self, message_id: int, starred: bool = True) -> bool:
        """Star or unstar a message."""
        try:
            validated_id = self._validate_message_id(message_id)
            op = "add" if starred else "remove"
            result = await self._sdk_call(
                self.client.update_message_flags,
                {"messages": [validated_id], "op": op, "flag": "starred"},
                timeout=self._send_timeout,
            )
            if result.get("result") == "success":
                logger.debug(
                    "message %s [id=%d]",
                    "starred" if starred else "unstarred",
                    validated_id,
                )
                return True
            logger.warning("star_message failed: %s", result.get("msg"))
            return False
        except Exception as e:
            logger.error("star_message error: %s", e)
            return False

    async def get_user_info(self, user_id_or_email: str) -> Optional[dict]:
        """Get information about a user."""
        try:
            result = await self._sdk_call(
                self.client.get_user,
                user_id_or_email,
                timeout=self._send_timeout,
            )
            if result.get("result") == "success":
                user = result.get("user", {})
                return {
                    "user_id": user.get("user_id"),
                    "email": user.get("email"),
                    "full_name": user.get("full_name"),
                    "is_admin": user.get("is_admin", False),
                    "is_bot": user.get("is_bot", False),
                }
            logger.warning("get_user_info failed: %s", result.get("msg"))
            return None
        except Exception as e:
            logger.error("get_user_info error: %s", e)
            return None

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[dict] = None,
        **kwargs,
    ) -> SendResult:
        """Send a local image as a native Zulip attachment (overrides the
        base class's "unavailable" stub — MEDIA:<path> screenshots were
        silently failing to deliver on Zulip; see #123).

        Zulip has no separate "photo" primitive: an uploaded file becomes an
        inline image automatically when its URL is embedded in message
        markdown (``![name](url)``), so this just uploads via
        upload_file_to_zulip() and sends that markdown as the message body.
        """
        return await self._send_uploaded_media(
            chat_id=chat_id,
            file_path=image_path,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
            as_image=True,
        )

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[dict] = None,
        **kwargs,
    ) -> SendResult:
        """Send a local file as a native Zulip attachment (overrides the
        base class's "unavailable" stub)."""
        return await self._send_uploaded_media(
            chat_id=chat_id,
            file_path=file_path,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
            as_image=False,
        )

    async def _send_uploaded_media(
        self,
        *,
        chat_id: str,
        file_path: str,
        caption: Optional[str],
        reply_to: Optional[str],
        metadata: Optional[dict],
        as_image: bool,
    ) -> SendResult:
        data_dir = os.environ.get("HERMES_DATA_DIR", os.path.expanduser("~/.hermes"))
        try:
            url = await upload_file_to_zulip(
                self.client, file_path, data_dir, account_id=self.email
            )
        except Exception as e:
            logger.error(
                "[%s] native media upload failed [file=%s]: %s",
                self.name, mask_pii(file_path), e,
            )
            text = "⚠️ Couldn't deliver the image attachment." if as_image else "⚠️ Couldn't deliver the file attachment."
            if caption:
                text = f"{caption}\n{text}"
            return await self.send(chat_id=chat_id, content=text, reply_to=reply_to, metadata=metadata)

        _safe_delete_temp_file(file_path)

        name = Path(file_path).name
        # `![alt](url)` renders inline in Zulip; plain `[name](url)` is a
        # downloadable link — same distinction the platform's own compose
        # box makes for drag-and-drop uploads.
        link = f"![{name}]({url})" if as_image else f"[{name}]({url})"
        content = f"{caption}\n{link}" if caption else link
        return await self.send(chat_id=chat_id, content=content, reply_to=reply_to, metadata=metadata)

    # ── Native exec-approval buttons (zform widget) ─────────────────────────
    # Zulip has no Discord-style component API, but bots can attach a generic
    # button widget to any message via the `widget_content` send-message param
    # (zform/choices; the same mechanism the official trivia_bot uses). On
    # web/desktop each choice renders as a button, and a click makes the CLIENT
    # send an ordinary message from the clicker with the choice's `reply` as
    # content. Mapping each reply to the gateway's plain-text approval command
    # reuses the existing resolution path unchanged: the press IS a typed
    # `/approve`-family message from the clicker, so authorization is identical,
    # and slash forms bypass mention gating at the base-adapter guard. Clients
    # without widget support (mobile, terminals) show only the message text —
    # the same prompt the gateway's text fallback renders.
    _EA_ZFORM_REPLY: dict[str, str] = {
        "once": "/approve",
        "session": "/approve session",
        "always": "/approve always",
        "deny": "/deny",
    }
    _EA_ZFORM_INSTRUCTIONS: dict[str, str] = {
        "once": "`/approve` to execute this one operation",
        "session": "`/approve session` to approve this pattern for the session",
        "always": "`/approve always` to approve permanently",
        "deny": "`/deny` to cancel",
    }

    def _zform_widget_for_approval(self, prompt: ExecApprovalPrompt) -> Optional[str]:
        """JSON ``widget_content`` for an exec-approval prompt, or None when the
        prompt carries no renderable actions.

        Schema per web/src/zform_data.ts (client zod): every choice needs
        ``type``/``short_name``/``long_name``/``reply`` strings and extra_data a
        ``heading``. The server validator (check_widget_content) does NOT check
        the per-choice ``type``, but the web renderer rejects its absence — a
        payload missing it sends fine and silently renders nothing.
        """
        choices: list[dict[str, str]] = []
        for label, choice, _style in prompt.actions:
            reply = self._EA_ZFORM_REPLY.get(choice)
            if not reply:
                # Unknown choice vocabulary — bail out so the gateway's text
                # fallback renders instead of a widget that resolves nothing.
                return None
            choices.append(
                {
                    "type": "multiple_choice",
                    "short_name": chr(ord("A") + len(choices)) if len(choices) < 26 else "?",
                    "long_name": str(label),
                    "reply": reply,
                }
            )
        if not choices:
            return None
        return json.dumps(
            {
                "widget_type": "zform",
                "extra_data": {
                    "type": "choices",
                    "heading": "Choose an action:",
                    "choices": choices,
                },
            }
        )

    def _approval_fallback_instructions(self, prompt: ExecApprovalPrompt) -> str:
        """Plain-text reply instructions mirroring the gateway's text fallback,
        built from the same action set as the buttons (widget-less clients)."""
        instructions = [
            self._EA_ZFORM_INSTRUCTIONS[choice]
            for _label, choice, _style in prompt.actions
            if choice in self._EA_ZFORM_INSTRUCTIONS
        ]
        if not instructions:
            return ""
        if len(instructions) == 1:
            return f"Reply {instructions[0]}."
        return "Reply " + ", ".join(instructions[:-1]) + f", or {instructions[-1]}."

    async def _send_exec_approval_prompt(self, prompt: ExecApprovalPrompt) -> SendResult:
        """Send the exec-approval prompt as context text + a zform-button message.

        Two messages, because a rendered zform widget REPLACES its own message
        body on web/desktop (``$outer_elem.empty().append($choices)`` in
        web/src/zform.ts): context sent as the widget message's text would be
        invisible exactly where the buttons render. Message 1 = the shared
        approval text plus reply instructions (visible on every client);
        message 2 = the button widget. Non-widget clients show both as plain
        text. Delivered if either message sends — the text alone is the full
        text-fallback experience — so the runner's plain-text re-send only
        happens when both fail.
        """
        widget_content = self._zform_widget_for_approval(prompt)
        instructions = self._approval_fallback_instructions(prompt)
        content = prompt.text if not instructions else f"{prompt.text}\n\n{instructions}"
        try:
            target = _parse_target(prompt.chat_id)
        except Exception as e:
            logger.error(
                format_zulip_log(
                    "zulip approval prompt send error",
                    chat_id=mask_pii(prompt.chat_id),
                    error=mask_pii(str(e)),
                )
            )
            return SendResult(success=False, message_id="")

        if target["type"] == "dm":
            base: dict[str, Any] = {"type": "private", "to": target["user_ids"]}
        else:
            # prompt.metadata carries the turn's routing metadata (thread_id =
            # a conversation id with stable topic sessions, else the topic
            # name); the cache is only a fallback.
            topic = self._routed_topic(target["stream_id"], prompt.metadata) or (
                self._topic_cache.get(prompt.chat_id, "general")
            )
            base = {"type": "stream", "to": target["stream_id"], "topic": topic}

        async def _send(request: dict[str, Any]) -> Optional[SendResult]:
            try:
                result = await self._sdk_call(
                    self.client.send_message, request, timeout=self._send_timeout
                )
            except Exception as e:
                logger.error(
                    format_zulip_log(
                        "zulip approval prompt send error",
                        chat_id=mask_pii(prompt.chat_id),
                        error=mask_pii(str(e)),
                    )
                )
                return None
            if result.get("result") == "success":
                logger.debug("zulip approval message sent to %s", mask_pii(prompt.chat_id))
                return SendResult(success=True, message_id=str(result.get("id", "")))
            logger.error(
                format_zulip_log(
                    "zulip approval prompt send failed",
                    chat_id=mask_pii(prompt.chat_id),
                    error=mask_pii(str(result)),
                )
            )
            return None

        context_result = await _send({**base, "content": content})
        if widget_content is None:
            return context_result or SendResult(success=False, message_id="")

        widget_result = await _send(
            {
                **base,
                "content": "Choose an action:",
                "widget_content": widget_content,
            }
        )
        if widget_result is not None:
            # Last-sent id: the interactive message is the one later tooling
            # would target (matches SendResult's newest-chunk convention).
            return widget_result
        return context_result or SendResult(success=False, message_id="")

    def _known_secrets(self) -> list[KnownSecret]:
        """Credential values that must never be transmitted (Issue #136).

        Memoised: the credential set does not change at runtime, and re-walking
        the config and environment on every send would be wasted work.
        """
        if self._known_secrets_cache is None:
            self._known_secrets_cache = collect_known_secrets(
                self._platform_extra,
                extra=[("zulip.api_key", self.api_key)],
                env=os.environ,
            )
        return self._known_secrets_cache

    def _detect_secret_leak(self, content: str) -> list[KnownSecret]:
        """Credentials ``content`` would transmit, if the guard is enabled."""
        if not block_secret_leaks_enabled():
            return []
        return find_leaked_secrets(content, self._known_secrets())

    async def _refuse_secret_leak(
        self, hits: list[KnownSecret], chat_id: str
    ) -> str:
        """Audit a refused send, naming only *where* the credential came from.

        The value itself is never logged or audited: a message describing a
        leak must not become one. (Issue #136)
        """
        summary = describe_leaked_secrets(hits)
        logger.error(
            format_zulip_log(
                "zulip outbound blocked: message contained host credentials",
                chat_id=mask_pii(str(chat_id)),
                leaked=summary,
            )
        )
        await self._audit_logger.log_event(
            "secret_leak_blocked",
            {
                "chat_id": mask_pii(str(chat_id)),
                "direction": "outbound",
                "sources": [hit.name for hit in hits],
                "count": len(hits),
            },
        )
        return summary

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to=None,
        metadata=None,
        media_files=None,
    ) -> SendResult:
        """Send message to a Zulip stream or DM, with chunking, topic directives, and files."""
        metadata = metadata or {}
        media_files = media_files or []

        # Outbound secret guard (Issue #136). Checked before media upload, so a
        # message we are about to refuse cannot leave a stray upload behind.
        leaked = self._detect_secret_leak(content)
        if leaked:
            summary = await self._refuse_secret_leak(leaked, chat_id)
            logger.error(
                "zulip send refused: %s. Remove it and rotate the credential.",
                summary,
            )
            return SendResult(success=False, message_id="")

        # Upload files first
        uploaded_urls = []
        uploaded_local_paths = []
        if media_files:
            data_dir = os.environ.get("HERMES_DATA_DIR", os.path.expanduser("~/.hermes"))
            for file_path in media_files:
                # Security: reject URL-like values in media_files (must be local paths)
                if isinstance(file_path, str) and (file_path.startswith("http://") or file_path.startswith("https://")):
                    logger.warning(
                        "zulip send rejected URL in media_files [url=%s]",
                        mask_pii(file_path),
                    )
                    continue
                try:
                    url = await upload_file_to_zulip(
                        self.client, file_path, data_dir, account_id=self.email
                    )
                    uploaded_urls.append(url)
                    uploaded_local_paths.append(file_path)
                except Exception as e:
                    logger.error("zulip upload failed [file=%s]: %s", mask_pii(file_path), e)

        # Clean up local temp files after upload (best-effort)
        for local_path in uploaded_local_paths:
            _safe_delete_temp_file(local_path)

        # Append uploaded file links to content
        if uploaded_urls:
            file_links = "\n".join(f"[{Path(u).name}]({u})" for u in uploaded_urls)
            if content:
                content = f"{content}\n\n{file_links}"
            else:
                content = file_links

        # Extract inline topic directive if present
        content, topic_override = extract_topic_directive(content)

        # Hard cap before chunking (mirrors sibling plugin's maxMessageLength).
        max_length = _resolve_max_message_length()
        if max_length > 0:
            content = truncate_text(content, max_length)

        limit, mode = _resolve_chunk_config()
        chunks = chunk_text(content, limit=limit, mode=mode)

        if not chunks:
            chunks = [""]

        last_result: Optional[SendResult] = None

        # When block streaming is enabled, send each chunk as a separate message
        # immediately. This requires gateway-level support (not yet implemented).
        for idx, chunk in enumerate(chunks):
            result = await self._send_single(chat_id, chunk, metadata, topic_override)
            last_result = result
            if not result.success:
                logger.error(
                    "zulip send failed on chunk %d/%d [chat=%s]",
                    idx + 1,
                    len(chunks),
                    mask_pii(chat_id),
                )

        return last_result or SendResult(success=False, message_id="")

    async def _send_single(
        self,
        chat_id: str,
        content: str,
        metadata: dict,
        topic_override: Optional[str],
    ) -> SendResult:
        """Send a single (unchunked) message, editing placeholder if present."""
        # Prepend response prefix if configured (Issue #65)
        if self._response_prefix and content:
            content = self._response_prefix + content

        try:
            target = _parse_target(chat_id)
            if target["type"] == "dm":
                result = await self._sdk_call(
                    self.client.send_message,
                    {
                        "type": "private",
                        "to": target["user_ids"],
                        "content": content,
                    },
                    timeout=self._send_timeout,
                )
            else:
                stream_id = target["stream_id"]
                topic = topic_override or self._routed_topic(stream_id, metadata)
                if not topic:
                    topic = self._topic_cache.get(chat_id, "general")

                result = await self._sdk_call(
                    self.client.send_message,
                    {
                        "type": "stream",
                        "to": stream_id,
                        "topic": topic,
                        "content": content,
                    },
                    timeout=self._send_timeout,
                )

            if result.get("result") == "success":
                logger.debug("zulip message sent to %s", chat_id)
                # This work item produced a reply, so its trace can say so
                # instead of reporting a silent run (epic #139 / #158).
                self._note_trace_reply(chat_id, metadata)
                return SendResult(
                    success=True, message_id=str(result.get("id", ""))
                )
            else:
                logger.error(
                    format_zulip_log(
                        "zulip send failed",
                        chat_id=mask_pii(chat_id),
                        error=mask_pii(str(result)),
                    )
                )
                return SendResult(success=False, message_id="")

        except Exception as e:
            logger.error(
                format_zulip_log(
                    "zulip send error",
                    chat_id=mask_pii(chat_id),
                    error=mask_pii(str(e)),
                )
            )
            return SendResult(success=False, message_id="")


def check_requirements() -> bool:
    """Return True if the zulip SDK is installed."""
    return _import_zulip_sdk() is not None


def validate_config(config) -> bool:
    """Validate that required credentials are present."""
    extra = getattr(config, "extra", {}) or {}
    return bool(
        (os.getenv("ZULIP_API_KEY") or extra.get("api_key"))
        and (os.getenv("ZULIP_EMAIL") or extra.get("email"))
        and (os.getenv("ZULIP_SITE") or extra.get("site"))
    )


def _env_enablement() -> dict | None:
    """Seed PlatformConfig.extra from environment variables."""
    key = os.getenv("ZULIP_API_KEY", "").strip()
    email = os.getenv("ZULIP_EMAIL", "").strip()
    site = os.getenv("ZULIP_SITE", "").strip()
    if not (key and email and site):
        return None

    return {"api_key": key, "email": email, "site": site}


def interactive_setup() -> None:
    """Interactive `hermes gateway setup` flow for the Zulip platform.

    Lazy-imports ``hermes_cli.setup`` helpers so the plugin stays importable
    in non-CLI contexts (gateway runtime, tests).
    """
    from hermes_cli.setup import (
        prompt,
        prompt_yes_no,
        save_env_value,
        get_env_value,
        print_header,
        print_info,
        print_warning,
        print_success,
    )

    print_header("Zulip")
    existing_email = get_env_value("ZULIP_EMAIL")
    if existing_email:
        print_info(f"Zulip: already configured ({existing_email})")
        if not prompt_yes_no("Reconfigure Zulip?", False):
            return

    print_info("Connect Hermes to Zulip via a bot account.")
    print_info("   Create a bot at: Settings → Bots → Add a new bot (Generic bot)")
    print()

    site = prompt(
        "Zulip site URL (e.g. https://your-org.zulipchat.com)",
        default=get_env_value("ZULIP_SITE") or "",
    )
    if not site:
        print_warning("Site URL is required — skipping Zulip setup")
        return

    # https only, unless the operator already opted into insecure http
    # (Issue #137). The opt-in is read at validation time rather than captured
    # here, so a self-hosted http:// realm keeps working on later calls — the
    # sibling's bug was the flag being discarded after this point.
    normalized_site = _normalize_base_url(site)
    if not normalized_site:
        print_warning(base_url_error(site))
        return
    save_env_value("ZULIP_SITE", normalized_site)

    email = prompt(
        "Bot email address (e.g. hermes-bot@your-org.zulipchat.com)",
        default=get_env_value("ZULIP_EMAIL") or "",
    )
    if not email:
        print_warning("Bot email is required — skipping Zulip setup")
        return
    save_env_value("ZULIP_EMAIL", email.strip())

    api_key = prompt(
        "Bot API key",
        default=get_env_value("ZULIP_API_KEY") or "",
        password=True,
    )
    if not api_key:
        print_warning("API key is required — skipping Zulip setup")
        return
    save_env_value("ZULIP_API_KEY", api_key.strip())

    # Authorization (optional but recommended)
    allowed = prompt(
        "Allowed user emails (comma-separated, or empty for none yet)",
        default=get_env_value("ZULIP_ALLOWED_USERS") or "",
    )
    if allowed:
        save_env_value("ZULIP_ALLOWED_USERS", allowed.strip())

    print_success("Zulip configured.")
    print_info("Tip: Subscribe your bot to streams via Stream settings → Subscribers")


# Topic used for out-of-process sends when the target carries no topic
# (no ``zulip:<stream>:<topic>`` thread id and no inline
# ``[[zulip_topic: …]]`` directive). Matches the in-process adapter's fallback for unknown chats.
STANDALONE_DEFAULT_TOPIC = "general"


def _resolve_standalone_credentials(pconfig) -> tuple[str, str, str]:
    """Return ``(site, email, api_key)`` from the environment or ``pconfig.extra``.

    Same precedence as :func:`validate_config`: the ``ZULIP_*`` environment
    variables win, then the platform config's ``extra`` mapping.
    """
    extra = getattr(pconfig, "extra", {}) or {}
    site = os.getenv("ZULIP_SITE") or extra.get("site") or ""
    email = os.getenv("ZULIP_EMAIL") or extra.get("email") or ""
    api_key = os.getenv("ZULIP_API_KEY") or extra.get("api_key") or ""
    return site, email, api_key


async def _standalone_send(
    pconfig,
    chat_id: str,
    message: str,
    *,
    thread_id=None,
    media_files=None,
    force_document=False,
) -> dict:
    """Out-of-process Zulip delivery (Hermes ``standalone_sender_fn`` contract).

    Hermes calls this from ``tools/send_message_tool._send_via_adapter`` when
    no gateway adapter is live in the current process — e.g. ``hermes cron
    run <job>`` from the CLI, or cron running separately from the gateway.
    Without it, ``deliver: zulip[:<stream_id>]`` jobs fail with
    ``No live adapter for platform 'zulip'``.

    Arguments follow the contract in ``gateway/platform_registry.py``:

    * ``chat_id`` — ``<stream_id>`` or ``dm:<user_id>[,<user_id>…]`` (see
      :func:`_parse_target`). Multiple comma-separated ids address a Zulip
      group direct message.
    * ``thread_id`` — the optional third segment of a ``zulip:<stream>:<topic>``
      target; used as the Zulip topic. An inline ``[[zulip_topic: …]]`` directive in
      the message wins over it, and :data:`STANDALONE_DEFAULT_TOPIC` is used
      when neither is present. Ignored for DMs.
    * ``media_files`` — local paths uploaded via ``/user_uploads`` and appended
      to the message as links, exactly like :meth:`ZulipAdapter.send`.
    * ``force_document`` — accepted for contract compatibility; Zulip has no
      inline-vs-document distinction, so it has no effect.

    Returns ``{"success": True, "message_id": "<id>"}`` or ``{"error": "<why>"}``.
    Never raises: every failure is reported through the ``error`` key so the
    caller can record it as the job's delivery error.
    """
    site, email, api_key = _resolve_standalone_credentials(pconfig)
    if not (site and email and api_key):
        return {
            "error": "Zulip not configured (ZULIP_SITE, ZULIP_EMAIL, ZULIP_API_KEY required)"
        }

    try:
        client = _get_cached_client(site, email, api_key)
    except ImportError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Zulip client init failed: {e}"}

    try:
        target = _parse_target(chat_id)
    except (TypeError, ValueError):
        return {
            "error": (
                f"Invalid Zulip target {chat_id!r}: expected a numeric stream id "
                f"or 'dm:<user_id>[,<user_id>…]'"
            )
        }

    # Outbound secret guard (Issue #136). The out-of-process path needs this
    # just as much as send(): cron-injected text can carry a credential too.
    if block_secret_leaks_enabled():
        leaked = find_leaked_secrets(
            message,
            collect_known_secrets(
                getattr(pconfig, "extra", None),
                extra=[("zulip.api_key", api_key)],
                env=os.environ,
            ),
        )
        if leaked:
            summary = describe_leaked_secrets(leaked)
            logger.error(
                "zulip standalone delivery blocked: message contained host "
                "credentials [%s]",
                summary,
            )
            try:
                await AuditLogger(
                    data_dir=os.environ.get(
                        "HERMES_DATA_DIR", os.path.expanduser("~/.hermes")
                    ),
                    account_id=email or "default",
                ).log_event(
                    "secret_leak_blocked",
                    {
                        "chat_id": mask_pii(str(chat_id)),
                        "direction": "outbound",
                        "transport": "standalone",
                        "sources": [hit.name for hit in leaked],
                        "count": len(leaked),
                    },
                )
            except Exception:
                pass  # auditing must never break the refusal itself
            return {
                "error": (
                    f"Refusing to deliver: the message contains {summary}. "
                    f"Remove it and rotate the credential."
                )
            }

    _connect_timeout, _read_timeout, send_timeout = _resolve_timeouts()
    content = message or ""

    # Media: upload first, then link — same shape as ZulipAdapter.send().
    uploaded_urls: list[str] = []
    if media_files:
        data_dir = os.environ.get("HERMES_DATA_DIR", os.path.expanduser("~/.hermes"))
        for file_path in media_files:
            if isinstance(file_path, (tuple, list)):
                # Some callers pass (path, is_voice) pairs.
                file_path = file_path[0]
            if not isinstance(file_path, str) or file_path.startswith(("http://", "https://")):
                logger.warning(
                    "zulip standalone send rejected media entry [entry=%s]",
                    mask_pii(str(file_path)),
                )
                continue
            try:
                uploaded_urls.append(
                    await upload_file_to_zulip(
                        client, file_path, data_dir, account_id=email
                    )
                )
            except Exception as e:
                logger.error(
                    "zulip standalone upload failed [file=%s]: %s",
                    mask_pii(file_path),
                    e,
                )
    if uploaded_urls:
        file_links = "\n".join(f"[{Path(u).name}]({u})" for u in uploaded_urls)
        content = f"{content}\n\n{file_links}" if content else file_links

    content, topic_directive = extract_topic_directive(content)

    # Hard cap before chunking (mirrors sibling plugin's maxMessageLength).
    max_length = _resolve_max_message_length()
    if max_length > 0:
        content = truncate_text(content, max_length)

    prefix = _resolve_response_prefix()
    if prefix and content:
        content = prefix + content

    if target["type"] == "dm":
        payload = {"type": "private", "to": target["user_ids"], "content": content}
    else:
        topic = topic_directive or (str(thread_id).strip() if thread_id else "") or STANDALONE_DEFAULT_TOPIC
        payload = {
            "type": "stream",
            "to": target["stream_id"],
            "topic": topic,
            "content": content,
        }

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(client.send_message, payload),
            timeout=send_timeout,
        )
    except asyncio.TimeoutError:
        return {"error": f"Zulip send timed out after {send_timeout}s"}
    except Exception as e:
        return {"error": f"Zulip send failed: {e}"}

    if isinstance(result, dict) and result.get("result") == "success":
        return {"success": True, "message_id": str(result.get("id", ""))}
    if isinstance(result, dict):
        detail = " ".join(
            str(result[k]) for k in ("code", "msg") if result.get(k)
        ) or mask_pii(str(result))
    else:
        detail = mask_pii(str(result))
    return {"error": f"Zulip send failed: {detail}"}


def register(ctx):
    """Plugin entry point — called by the Hermes plugin system."""
    # Activity-trace tool checkpoints (epic #139 / #159).
    #
    # Registered ONLY when the trace is enabled: any registration flips
    # has_hook("post_tool_call") true and switches on host-side dispatch, so
    # gating by *not registering* is what keeps a disabled trace free.
    #
    # ``pre_tool_call`` is deliberately never registered — it is fail-closed
    # (it returns (block_message, modified_args)), so a status observer could
    # block the agent's own tool call.
    if TraceConfig.from_env().enabled:
        try:
            ctx.register_hook("post_tool_call", _on_post_tool_call)
        except Exception as e:
            logger.warning("zulip: could not register post_tool_call hook: %s", e)

    # Mode B (epic #139 / #160): let the agent narrate intent that hooks cannot
    # infer. Registered only when the trace is enabled — registration is what
    # exposes the tool to the model, so a disabled trace must not advertise one.
    if TraceConfig.from_env().enabled:
        try:
            ctx.register_tool(
                name="zulip_progress",
                toolset="zulip",
                schema={
                    "name": "zulip_progress",
                    "description": (
                        "Show a short progress note on this conversation's activity "
                        "board while you work. Use it for intent that a tool call does "
                        "not reveal, e.g. 'about to ask a clarifying question' or "
                        "'switching approach'."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "note": {
                                "type": "string",
                                "description": "Short status line, e.g. 'checking the logs'.",
                            }
                        },
                        "required": ["note"],
                    },
                },
                handler=_zulip_progress_handler,
                description="Show a short progress note on the activity trace",
                emoji="\U0001f4dd",
            )
        except Exception as e:
            logger.warning("zulip: could not register zulip_progress tool: %s", e)

    ctx.register_platform(
        name="zulip",
        label="Zulip",
        adapter_factory=lambda cfg: ZulipAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        required_env=["ZULIP_API_KEY", "ZULIP_EMAIL", "ZULIP_SITE"],
        install_hint="pip install zulip",
        env_enablement_fn=_env_enablement,
        allowed_users_env="ZULIP_ALLOWED_USERS",
        allow_all_env="ZULIP_ALLOW_ALL_USERS",
        # Lets Hermes cron accept ``deliver: zulip[:<stream_id>]`` targets.
        # Without this, cron preflight rejects the job as "not a known cron
        # delivery target" and never runs it. The env var supplies the default
        # stream when no explicit id is given.
        cron_deliver_env_var="ZULIP_HOME_CHANNEL",
        # Out-of-process delivery (``hermes cron run``, cron in its own
        # process): without this, Hermes has no way to send to Zulip when no
        # gateway adapter is live and reports "No live adapter for platform".
        standalone_sender_fn=_standalone_send,
        max_message_length=10000,
        platform_hint=(
            "You are chatting via Zulip. Messages are organized into streams and topics. "
            "When replying to a stream message, preserve the original topic unless asked to change it."
        ),
        emoji="📬",
        setup_fn=interactive_setup,
    )
