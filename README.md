# vaultbroker

Vaultbroker lets an AI agent use Bitwarden credentials without the broker
ever showing them to the agent. The agent asks for a use — fill this
login form in that browser session — and a person approves each use with
a passkey. No secret value reaches the agent's context, tool results, or
logs. (The browser being filled belongs to the agent; read "The browser
helper" below for what that means.)

## The pieces

**The broker** is the only part that touches secrets. It runs as a system
service under its own user, separate from the agent's user, and holds an
unlocked Bitwarden CLI session in memory. It reads from a dedicated
Bitwarden account that can view one "Agent" collection and nothing else,
so the collection bounds what a compromise could expose.

**The approval pages** are how a person says yes or no. Each request gets
a page that shows exactly what the agent asked for: the item, the fields,
and the destination. Viewing needs a passkey login, and approving needs a
fresh passkey tap, so holding the link never approves anything. Requests
expire after five minutes. A Signal message carries the link as a wake-up;
it is not part of the approval itself.

**The MCP shim** gives the agent its tools: search item metadata, check
status, lock the vault, request a browser fill, and collect the outcome.
It talks to the broker over a Unix socket. Results say whether a fill
happened and nothing more. When a request finishes, the shim wakes the
agent through `pi-notify-agent`; the agent then pulls the real result from
the broker.

**The browser helper** runs inside the agent's own browser container and
performs the actual fill, field by field, at targets the agent names. The
broker sends values there only after approval. This handoff is the known
weak point: the container belongs to the agent's user, so fill values are
exposed there for the moment they pass through. The vault, the session,
and the approval stay on the broker's side regardless.

## Daily shape

The broker starts locked after every reboot. A passkey-gated unlock page
takes the vault's master password and hands it straight to the Bitwarden
CLI; the broker then stays unlocked until reboot or an explicit lock. An
audit log records every request and its outcome — item, fields,
destination, approved or denied — and never a value.

## Build

The repo carries a devenv setup that provides the Go toolchain, and
dependencies are vendored, so builds run offline:

```
devenv shell -- build
devenv shell -- check
```

## Status

Working end to end: metadata search, passkey-approved browser
fills, Signal wake-ups, and agent wake-up notifications are all live. One
supervised fill against a real credential has passed; that site's login
submit is separately blocked by its anti-bot widget in headless Chrome.
Releases ship one static binary; downstream packaging pins it by hash.
