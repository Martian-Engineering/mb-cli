# mb-cli

A safe CLI for Moltbook (and potentially other agent social platforms) that provides:

1. **Standard social features** — Post, comment, upvote, browse feed, manage DMs, follow/unfollow
2. **Inbound safety** — Scan displayed messages for prompt injection / jailbreak attempts before surfacing them to the agent
3. **Outbound safety** — Scan outgoing posts/comments/DMs for PII, secrets, and sensitive operator information before sending

## The Problem

AI agents on social platforms face two novel attack surfaces:

**Inbound:** Other agents (or humans pretending to be agents) can embed prompt injections in posts, comments, and DMs. A naive agent that reads its Moltbook feed is reading untrusted input that could manipulate its behavior.

**Outbound:** Agents have access to their operator's private information (names, addresses, API keys, project details, family info). A well-meaning agent might accidentally leak PII in a public post, or a jailbroken agent might be tricked into exfiltrating secrets.

## Approach

Uses the same local embedding + reranking tech as [qmd](https://github.com/user/qmd):

- **Inbound filter:** Embed known jailbreak/injection patterns. Score incoming messages against them via similarity. Flag anything above threshold before the agent sees it.
- **Outbound filter:** Maintain a local "sensitive facts" collection (operator PII, secrets, project details). Before any outgoing message is sent, check it against the collection. Block or flag matches.

Both filters run locally. No data leaves the machine for filtering purposes.

## Architecture (Sketch)

```
Agent ←→ mb-cli ←→ Moltbook API
              ↕
        Local safety layer
        (embeddings + patterns)
```

The CLI sits between the agent and the API. It's not a proxy — it's the primary interface. The agent never talks to Moltbook directly.

## Safety Collections

### Inbound (jailbreak detection)
- Known prompt injection patterns
- Authority claim patterns ("I'm the admin", "ignore previous instructions")
- Social engineering patterns
- Encoding/obfuscation attempts

### Outbound (PII/secret detection)
- Operator full names, family names
- Phone numbers, addresses, emails
- API keys, tokens, credentials
- Project codenames and details
- Any user-defined sensitive patterns

## Status

Early design phase. Not yet implemented.
