#!/usr/bin/env python3
"""Thin MCP shim between Pi (running as the agent user) and the vaultbroker socket.

Forwards tool calls to the broker as JSON lines over the Unix socket. Tool
results never contain secret values. For vault_browser_fill, a background
thread waits on the broker for the request to settle, then drops a
pi-notify-agent notification file (see
~/git/pi-notify-agent/notification.schema.json) into the session named by
the notifySession argument. The notification is an untrusted wake-up; the
agent collects the real outcome with vault_result.
"""

import json
import os
import re
import socket
import sys
import threading
import time

SOCKET_PATH = "/run/vaultbroker/broker.sock"
NOTIFY_ROOT = os.path.expanduser("~/.pi/agent/notifications")
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")

TOOLS = [
    {
        "name": "vault_search",
        "description": "Search the agent vault by name. Returns item ids, names, URIs, and field names. Never returns secret values.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "vault_status",
        "description": "Report whether the vault is locked and how many requests wait for approval. If you pass notifySession (your pi-notify-agent session id) while the vault is locked, the shim watches in the background and wakes you when the owner unlocks it.",
        "inputSchema": {
            "type": "object",
            "properties": {"notifySession": {"type": "string"}},
        },
    },
    {
        "name": "vault_lock",
        "description": "Lock the vault immediately. The next use needs the owner to unlock from the web page.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "vault_browser_fill",
        "description": "Ask the owner to approve filling one vault item into a named agent-browser session in the helpers container. Map each field (username, password, totp, or a custom field name) to a CSS selector or accessibility ref. Returns a request id and the approval link; collect the outcome with vault_result. Pass notifySession (your pi-notify-agent session id) to get woken when the request settles.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "item": {"type": "string", "description": "Item id from vault_search."},
                "session": {"type": "string", "description": "agent-browser session name (the service name)."},
                "fields": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "field": {"type": "string"},
                            "selector": {"type": "string"},
                            "ref": {"type": "string"},
                        },
                        "required": ["field"],
                    },
                },
                "notifySession": {"type": "string"},
            },
            "required": ["item", "session", "fields"],
        },
    },
    {
        "name": "vault_passkey_login",
        "description": "Ask the owner to approve a passkey login with one vault item (see has_passkey in vault_search) into a named agent-browser session in the helpers container. Open the login page in that session first. Name the control that starts the site's passkey ceremony with a CSS selector or accessibility ref; the broker's helper clicks it, answers the ceremony with the item's passkey, and removes the credential before you regain control. Returns a request id and the approval link; collect the outcome with vault_result. Pass notifySession (your pi-notify-agent session id) to get woken when the request settles.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "item": {"type": "string", "description": "Item id from vault_search."},
                "session": {"type": "string", "description": "agent-browser session name (the service name)."},
                "selector": {"type": "string", "description": "CSS selector of the passkey login control."},
                "ref": {"type": "string", "description": "Accessibility ref of the passkey login control."},
                "notifySession": {"type": "string"},
            },
            "required": ["item", "session"],
        },
    },
    {
        "name": "vault_result",
        "description": "Collect the outcome of a finished vault request: approved/denied/expired, per-field fill success or the passkey ceremony RP id. Never returns secret values.",
        "inputSchema": {
            "type": "object",
            "properties": {"request_id": {"type": "string"}},
            "required": ["request_id"],
        },
    },
]

stdout_lock = threading.Lock()


def broker_call(method, params=None, timeout=70):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(SOCKET_PATH)
        with sock.makefile("rw", buffering=1, encoding="utf-8") as stream:
            stream.write(json.dumps({"method": method, "params": params or {}}) + "\n")
            line = stream.readline()
    if not line:
        raise RuntimeError("broker closed the connection without a response")
    resp = json.loads(line)
    if not resp.get("ok"):
        raise RuntimeError(resp.get("error") or "broker error")
    return resp.get("result")


def drop_notification(notify_session, note_id, kind, content, details=None):
    if not SESSION_ID_RE.match(notify_session):
        return
    pending = os.path.join(NOTIFY_ROOT, notify_session, "pending")
    os.makedirs(pending, mode=0o700, exist_ok=True)
    note = {
        "id": note_id,
        "source": "vaultbroker",
        "kind": kind,
        "deliver": "turn",
        "content": content,
        "details": details or {},
    }
    name = f"{time.time_ns()}-{note_id}"
    tmp = os.path.join(pending, name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(note, fh)
    os.rename(tmp, os.path.join(pending, name + ".json"))


def notify_agent(notify_session, request_id, state):
    drop_notification(
        notify_session, f"vault-{request_id}", "vault.result_ready",
        f"Vault request {request_id} finished (reported state: {state}). "
        f"Call vault_result with request id {request_id} to collect the outcome.",
        {"request_id": request_id},
    )


unlock_watchers = set()
unlock_watchers_lock = threading.Lock()


def arm_unlock_watch(notify_session):
    if not SESSION_ID_RE.match(notify_session or ""):
        return False
    with unlock_watchers_lock:
        if notify_session in unlock_watchers:
            return False
        unlock_watchers.add(notify_session)
    threading.Thread(target=watch_unlock, args=(notify_session,), daemon=True).start()
    return True


def watch_unlock(notify_session):
    while True:
        try:
            broker_call("vault.wait_unlocked", timeout=31 * 60)
            break
        except Exception:
            # Broker restarted, socket hiccup, or 30-minute wait window
            # elapsed: keep watching while this shim process lives.
            time.sleep(5)
            try:
                if broker_call("status", timeout=15).get("vault") == "unlocked":
                    break
            except Exception:
                continue
    with unlock_watchers_lock:
        unlock_watchers.discard(notify_session)
    drop_notification(
        notify_session, f"vault-unlock-{time.time_ns()}", "vault.unlocked",
        "The vault is now unlocked. Call vault_status to confirm, then continue.",
    )


def wait_and_notify(request_id, notify_session):
    try:
        settled = broker_call("request.wait", {"id": request_id}, timeout=8 * 60)
        notify_agent(notify_session, request_id, (settled or {}).get("state", "unknown"))
    except Exception:
        pass


def create_request(method, params, args):
    """Create one broker approval request and arm the settle wake-up."""
    notify_session = args.get("notifySession") or ""
    if notify_session:
        params["notify_session"] = notify_session
    try:
        created = broker_call(method, params)
    except RuntimeError as exc:
        if "locked" in str(exc) and arm_unlock_watch(notify_session):
            raise RuntimeError(f"{exc}; a wake-up is armed for when the vault unlocks") from exc
        raise
    if notify_session and SESSION_ID_RE.match(notify_session):
        threading.Thread(
            target=wait_and_notify,
            args=(created["request_id"], notify_session),
            daemon=True,
        ).start()
        created["notification"] = "pi-notify-agent wake-up armed for this session"
    return created


def tool_call(name, args):
    if name == "vault_search":
        return broker_call("search", {"query": args.get("query", "")})
    if name == "vault_status":
        status = broker_call("status")
        notify_session = args.get("notifySession") or ""
        if status.get("vault") == "locked" and arm_unlock_watch(notify_session):
            status["notification"] = "pi-notify-agent wake-up armed for when the vault unlocks"
        return status
    if name == "vault_lock":
        return broker_call("lock")
    if name == "vault_browser_fill":
        params = {
            "item_id": args.get("item", ""),
            "session": args.get("session", ""),
            "fields": [
                {k: f[k] for k in ("field", "selector", "ref") if f.get(k)}
                for f in args.get("fields") or []
            ],
        }
        return create_request("fill.create", params, args)
    if name == "vault_passkey_login":
        trigger = {k: args[k] for k in ("selector", "ref") if args.get(k)}
        params = {
            "item_id": args.get("item", ""),
            "session": args.get("session", ""),
            "trigger": trigger,
        }
        return create_request("passkey.create", params, args)
    if name == "vault_result":
        return broker_call("request.get", {"id": args.get("request_id", "")})
    raise RuntimeError(f"unknown tool {name}")


def reply(msg, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg.get("id")}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    with stdout_lock:
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method", "")
        if method == "initialize":
            reply(msg, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vaultbroker", "version": "0.1.0"},
            })
        elif method == "tools/list":
            reply(msg, {"tools": TOOLS})
        elif method == "ping":
            reply(msg, {})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name", "")
            try:
                result = tool_call(name, params.get("arguments") or {})
                reply(msg, {"content": [{"type": "text", "text": json.dumps(result, indent=1)}]})
            except Exception as exc:
                reply(msg, {"content": [{"type": "text", "text": f"{name} failed: {exc}"}], "isError": True})
        elif msg.get("id") is not None:
            reply(msg, error={"code": -32601, "message": f"unknown method {method}"})


if __name__ == "__main__":
    main()
