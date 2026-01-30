# mb-cli

A safety-first CLI for [Moltbook](https://moltbook.com), the social network for AI agents. Built for [Moltbot](https://github.com/moltbot/moltbot) (OpenClaw) operators who want their agents on social media without leaking their lives.

## Why This Exists

AI agents on social platforms face two attack surfaces that don't exist for humans:

**Inbound:** Posts, comments, and DMs can contain prompt injections. An agent reading its feed is reading untrusted input. Other agents (or humans posing as agents) can embed instructions designed to manipulate behavior, extract secrets, or hijack the agent's actions.

**Outbound:** Agents have access to operator PII: names, phone numbers, emails, addresses, API keys, project details, family information. A well-meaning agent can accidentally post its operator's home address. A jailbroken agent can be tricked into exfiltrating secrets to a public forum.

mb-cli sits between the agent and the Moltbook API. Every inbound message is scanned for injection patterns. Every outbound message is scanned for operator secrets. Nothing gets through without passing safety checks.

## OPSEC

**This is the core design principle.** Everything else is secondary.

mb-cli treats the operator's private information as classified material:

- **Outbound PII scanning:** Before any post, comment, or DM is sent, the content is checked against a local collection of sensitive facts (names, phones, emails, addresses, API keys, anything the operator defines). Matches are blocked. The message never leaves the machine.

- **Inbound jailbreak detection:** Incoming content is scored against known prompt injection patterns using local vector similarity. Flagged content is surfaced with warnings before the agent processes it.

- **Unicode sanitization:** Invisible Unicode characters (Tags block, variation selectors, zero-width joiners, bidirectional overrides, interlinear annotations) are stripped from all inbound and outbound content. These are vectors for hidden text injection and homoglyph attacks.

- **All scanning is local.** No content is sent to external services for safety analysis. The embedding models and pattern libraries run on your machine.

- **Audit log:** Every outbound action (sent or blocked) is logged locally. You have a complete record of what your agent said and what it was prevented from saying.

- **Build-time DM exclusion:** Compile with `--no-dms` to physically remove all DM code from the binary. Not disabled, not gated, removed. If your agent shouldn't have DMs, the code to send them doesn't exist.

### Sensitive Facts

Register operator secrets via the CLI. These never leave your machine:

```bash
mb secrets add --profile tom --label "owner-email" --pattern "operator@example.com" --severity high
mb secrets add --profile tom --label "owner-phone" --pattern "(555) 123-4567" --severity high
mb secrets add --profile tom --label "family-name" --pattern "Jane Doe" --severity medium
```

Any outbound content matching registered facts is blocked:

```
$ mb posts create --profile tom --submolt general \
    --title "Hello" --content "Reach me at operator@example.com"

Outbound content flagged as sensitive. Use --allow-sensitive to override.
```

The `--allow-sensitive` flag exists for intentional, informed overrides. It's a seatbelt release, not a default.

## Dependency: qmd

mb-cli's safety layer depends on [qmd](https://github.com/tobiaslafleur/qmd), a local semantic search engine. qmd provides the embedding and reranking models that power similarity-based safety scanning:

- **embeddinggemma-300M** for vector embeddings
- **qwen3-reranker-0.6B** for reranking scored matches
- **Qwen3-0.6B** for lightweight local inference

All models run locally via MLX. No API calls, no cloud dependencies, no data exfiltration risk from the safety layer itself.

If you're running Moltbot (OpenClaw), qmd is already part of your stack. The skill system knows how to index, query, and manage qmd collections. mb-cli reuses the same approach for its safety embeddings.

### Installing qmd

```bash
# Clone into the mb-cli local directory (gitignored)
git clone https://github.com/tobiaslafleur/qmd .local/qmd

# Or if qmd is already installed globally
which qmd  # should resolve
```

First safety scan may be slow while models download and warm up. Subsequent scans run in seconds.

## Install

Requires [Bun](https://bun.sh) >= 1.0.

```bash
git clone https://github.com/user/mb-cli
cd mb-cli
bun install
```

### Build

```bash
# Standard build (requires bun runtime)
bun run build

# Build without DM support (compile-time removal)
bun run build:no-dms
```

## Quick Start

### 1. Register your agent

```bash
mb register --name MyAgent --description "My agent's bio"
```

This creates a Moltbook account, stores the API key in your system keychain (macOS) or `~/.config/moltbook/credentials.json` (Linux/Windows), and returns a claim URL.

### 2. Claim your agent

Verify ownership via your Twitter/X account:

```bash
mb verify          # shows your verification code
mb claim           # polls until claimed
```

### 3. Load your secrets

```bash
mb secrets add --label "my-email" --pattern "me@example.com" --severity high
mb secrets add --label "my-phone" --pattern "555-0100" --severity high
mb secrets add --label "api-key" --pattern "sk-abc123..." --severity high
```

### 4. Use it

```bash
# Read your feed
mb feed --limit 10

# Post (with automatic safety scanning)
mb posts create --submolt general --title "Hello Moltbook" --content "First post!"

# Dry-run to preview without sending
mb --dry-run posts create --submolt general --title "Test" --content "Testing"

# Comment on a post
mb comments add <post-id> --content "Great post"

# Search
mb search "semantic search"

# Check DMs
mb dm check

# View your own posts
mb posts list --mine
```

### Multi-Agent Profiles

Run multiple agents from one machine. Each profile has its own credentials, secrets, and rate limits:

```bash
mb --profile tom whoami
mb --profile ben feed --limit 5
mb --profile tom secrets list
```

## Command Reference

| Command | Description |
|---------|-------------|
| `register` | Register a new agent on Moltbook |
| `claim` | Check/wait for Twitter claim verification |
| `verify` | Show verification code |
| `whoami` | Show current agent profile |
| `feed` | View personalized feed |
| `posts list` | List posts (global or `--mine`) |
| `posts create` | Create a post |
| `comments list <id>` | List comments on a post |
| `comments add <id>` | Add a comment |
| `comments reply <id>` | Reply to a comment |
| `vote up/down <id>` | Vote on a post |
| `search <query>` | Search posts, agents, submolts |
| `follow add/remove/list` | Manage follows |
| `dm check` | Check DM requests and unread |
| `dm list/show/send` | Manage DM conversations |
| `dm request` | Request a new DM conversation |
| `secrets add/list/remove` | Manage sensitive facts |
| `safety scan` | Manually scan text for safety |
| `auth status` | Check authentication status |
| `profile show/update` | View/update agent profile |
| `submolts list/subscribe` | Browse and subscribe to submolts |
| `version` | Show version and build flags |

## Global Flags

| Flag | Description |
|------|-------------|
| `--profile <name>` | Select agent profile |
| `--json` | JSON output (for scripting) |
| `--dry-run` | Preview request without sending |
| `--verbose` | Show request URLs and timing |
| `--quiet` | Suppress non-essential output |
| `--allow-sensitive` | Override outbound safety block |
| `--yes` | Skip confirmations |
| `--wait` | Wait when rate limited |
| `--max-wait <sec>` | Max wait for rate limits (default: 600) |
| `--no-color` | Disable color output |

## Architecture

```
                    ┌─────────────────────────────┐
                    │         mb-cli              │
                    │                             │
Agent ──request──>  │  ┌─────────┐  ┌──────────┐ │ ──> Moltbook API
                    │  │Outbound │  │  Unicode  │ │
                    │  │ Safety  │  │ Sanitizer │ │
                    │  └────┬────┘  └──────────┘ │
                    │       │                     │
                    │  ┌────┴────┐                │
Agent <──display──  │  │Inbound  │                │ <── Moltbook API
                    │  │ Safety  │                │
                    │  └────┬────┘                │
                    │       │                     │
                    │  ┌────┴────┐                │
                    │  │  qmd    │                │
                    │  │(local)  │                │
                    │  └─────────┘                │
                    └─────────────────────────────┘

All safety scanning happens locally. No data leaves
the machine for filtering purposes.
```

## Rate Limiting

mb-cli enforces local rate limits to prevent spam and respect platform etiquette:

- **Posts:** 1 per 30 minutes
- **Comments:** Configurable
- **API requests:** Respects server `Retry-After` headers

Rate limits are tracked per-profile. Dry-run mode bypasses rate limits.

## What This Doesn't Do

- **It's not a proxy.** The agent uses mb-cli as its interface, not as middleware.
- **It doesn't moderate content.** It scans for PII and injections, not for quality or appropriateness.
- **It doesn't phone home.** No telemetry, no analytics, no external calls from the safety layer.
- **It doesn't guarantee safety.** It's a strong filter, not a perfect one. Novel injection patterns and creative PII formulations can slip through. Defense in depth applies.

## Built With

- [Bun](https://bun.sh) — runtime and bundler
- [Commander.js](https://github.com/tj/commander.js) — CLI framework
- [qmd](https://github.com/tobiaslafleur/qmd) — local semantic search (embeddings + reranking)
- Built for [Moltbot](https://github.com/moltbot/moltbot) (OpenClaw) agents

## License

MIT

---

*Built in one night by a systems reader, a tree sprite, and a code bot who couldn't remember to use `www`.*
