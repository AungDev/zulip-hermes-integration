# Zulip Plugin Setup Guide

Step-by-step install for a fresh host. Short on purpose — for the full feature tour see
[../README.md](../README.md).

## Prerequisites

- Python 3.8+
- Hermes Agent `>= 0.18.2` installed and running
- A Zulip organization (self-hosted or zulipchat.com) where you can create bots

## Step 1: Create a Zulip Bot

1. Log in to Zulip as an admin
2. Go to **Settings → Bots** in the left sidebar
3. Click **Add a new bot**
4. Choose **Generic bot**
5. Copy the **API key** and note the bot's **email address**

## Step 2: Install the Zulip SDK

```bash
pip install "zulip>=0.9.0"
```

> ⚠️ Hermes does not auto-install plugin dependencies. Run this in the **same Python
> environment** Hermes uses, or the plugin fails to import with `zulip package not installed`.

## Step 3: Install the Plugin

> ⚠️ **Install the whole repository, not individual files.** The plugin is 28 modules that
> import from each other — copying just `adapter.py` and `plugin.yaml` produces an import
> error at load time (`No adapter available for zulip`).

### Option A: User plugin (recommended)

```bash
mkdir -p ~/.hermes/plugins
rm -rf ~/.hermes/plugins/zulip
git clone https://github.com/niyazmft/zulip-hermes-integration.git ~/.hermes/plugins/zulip
hermes plugins enable zulip
```

### Option B: Bundled plugin (containers / system-wide)

```bash
HERMES_PATH=$(python3 -c "import hermes_cli; print(hermes_cli.__path__[0])")
PLUGIN_DIR="$HERMES_PATH/../plugins/platforms/zulip"
rm -rf "$PLUGIN_DIR"
git clone https://github.com/niyazmft/zulip-hermes-integration.git "$PLUGIN_DIR"
```

Make sure `zulip` is enabled in `~/.hermes/config.yaml`:

```yaml
gateway:
  platforms:
    zulip:
      enabled: true
```

## Step 4: Configure Credentials

### Interactive (recommended)

```bash
hermes gateway setup
```

The wizard reads the plugin's `requires_env` / `optional_env` declarations and prompts for
each one — API key (masked), bot email, site URL, and optionally allowed users and a home
stream. It writes to `~/.hermes/.env`. No manual editing required.

### Manual

Add to `~/.hermes/.env`:

```bash
ZULIP_API_KEY=your-bot-api-key
ZULIP_EMAIL=your-bot@your-org.zulipchat.com
ZULIP_SITE=https://your-org.zulipchat.com
```

Update these later with `hermes config`.

## Step 5: Subscribe the Bot to Streams

**Required for the bot to see stream messages at all.** A bot only receives messages from
streams it is subscribed to.

1. Zulip → **Stream settings → Subscribers**
2. Add your bot

DMs and @-mentions work without this step; stream messages do not.

> This matters for reactions too: Zulip delivers `reaction` events only to **subscribers**,
> so a reaction trigger in an unsubscribed stream fails silently.

## Step 6: Start the Gateway

```bash
hermes gateway
```

If the wizard offered to start it already, skip this.

## Step 7: Verify

Send the bot one message:

```
# DM
hello

# Stream (bot must be subscribed)
@**your-bot** hello
```

Then confirm it connected:

```bash
grep -i zulip ~/.hermes/logs/gateway.log | tail -20
```

Expected — these three lines mean the plugin loaded, authenticated and is listening:

```
zulip probe ok [bot=... ]
zulip bot authenticated [bot=... ]
zulip connection established [...]
```

A reply in Zulip confirms the whole path end to end.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `zulip package not installed` | `pip install "zulip>=0.9.0"` in the same Python env as Hermes |
| `No adapter available for zulip` | Reinstall the **whole repo** (Step 3); check the log for an import error |
| Bot silent in streams | The bot must be subscribed (Step 5); check `ZULIP_CHATMODE` |
| Bot replies to everything | `ZULIP_CHATMODE=onmessage` — switch to `oncall` so only mentions are answered |
| Connection errors | Check API key, email and site URL; the site must be `https://` with no trailing slash |
| `Invalid or unsafe ZULIP_SITE` | Use an `https://` host rather than `http://`, localhost or an IP |
| Wizard shows instructions only | The plugin was installed incompletely — reinstall from the repo |

More detail: [../README.md#troubleshooting](../README.md#troubleshooting) and
[../AGENTS.md](../AGENTS.md).

## See Also

- [Hermes plugin docs](https://hermes-agent.nousresearch.com/docs/developer-guide/adding-platform-adapters)
- [Zulip API documentation](https://zulip.com/api/)
- [../SECURITY.md](../SECURITY.md) — threat model and credential handling
