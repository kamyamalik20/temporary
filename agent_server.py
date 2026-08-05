"""
agent_server.py — runs ON each remote server being monitored.

Deploy the whole project to the remote machine and run this file there
(see RUNBOOK.md). It exposes a small HTTP API that the central server
(app/AI_server.py, via app/agent_client.py) calls:

    GET  /health              -> {"status": "ok", "hostname": ...}
    GET  /scan                -> {"hostname", "scanned_at", "files": [...]}
    POST /execute              -> body {"actions": [...]}  (pre-approved by
                                   the central server's safety_checker)

SECURITY NOTE — defense in depth:
    The central server already runs every action through
    app.safety_checker.process_cleanup_plan() before sending it here. This
    agent does NOT trust that and re-validates every single action from
    scratch (path allow-list, critical-path/filename block-list, file-type
    pattern, and UID ownership) using the exact same app.policy module,
    against ITS OWN local filesystem, before touching anything. A
    compromised or buggy central server cannot make this agent delete
    files outside its own rules.

Auth: a single shared secret (AGENT_API_KEY env var) checked via the
X-API-Key header. This matches the "plaintext in config.yaml" choice on
the central server's side — the central server holds this same value in
its config.yaml `servers:` entry for this machine.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

# Allow running this file directly (python agent/agent_server.py) by making
# sure the project root (parent of agent/) is on sys.path so `app.*` imports
# resolve regardless of current working directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.files import scan as run_scan, default_paths  # noqa: E402
from app.policy import check_path, check_ownership, canonicalize, DEFAULT_MIN_HUMAN_UID  # noqa: E402
from app.safety_checker import ALLOWED_DIRS, _matches_expected_type, sanitize_display_text  # noqa: E402

API_KEY = os.environ.get("AGENT_API_KEY")
if not API_KEY:
    print("WARNING: AGENT_API_KEY is not set. Set it before running in production:")
    print("  export AGENT_API_KEY='some-long-random-value'")
    API_KEY = "unset-insecure-default"

MIN_HUMAN_UID = int(os.environ.get("AGENT_MIN_HUMAN_UID", DEFAULT_MIN_HUMAN_UID))
SCAN_PATHS = os.environ.get("AGENT_SCAN_PATHS")
SCAN_PATHS = SCAN_PATHS.split(",") if SCAN_PATHS else default_paths()
MIN_SIZE_MB = float(os.environ.get("AGENT_MIN_SIZE_MB", 50))
MIN_AGE_DAYS = int(os.environ.get("AGENT_MIN_AGE_DAYS", 30))

app = FastAPI(title="Disk Monitor Agent")


class ActionEntry(BaseModel):
    action: str
    path: str
    reason: str = ""


class ExecuteRequest(BaseModel):
    actions: list[ActionEntry]


def _check_api_key(x_api_key: str = Header(default="")):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid API key")


@app.get("/health")
def health():
    return {"status": "ok", "hostname": socket.gethostname()}


@app.get("/scan")
def scan_endpoint(x_api_key: str = Header(default="")):
    _check_api_key(x_api_key)
    files = run_scan(SCAN_PATHS, MIN_SIZE_MB, MIN_AGE_DAYS)
    return {
        "hostname": socket.gethostname(),
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "files": files,
    }


def _locally_revalidate(entry: ActionEntry) -> tuple[bool, str, str]:
    """
    Independent re-validation against THIS machine's filesystem.
    Returns (allowed, resolved_path, reason).
    """
    if entry.action not in {"delete", "compress"}:
        return False, "", f"unknown action type: {entry.action!r}"

    result = check_path(entry.path, ALLOWED_DIRS)
    if not result.allowed:
        return False, "", result.reason

    resolved = canonicalize(entry.path)

    if not _matches_expected_type(resolved):
        return False, resolved, "path does not match expected log/cache/tmp/backup/iso pattern"

    if not os.path.exists(resolved):
        return False, resolved, "path does not exist on this host"

    ownership = check_ownership(resolved, MIN_HUMAN_UID)
    if not ownership.allowed:
        return False, resolved, ownership.reason

    return True, resolved, "ok"


@app.post("/execute")
def execute_endpoint(req: ExecuteRequest, x_api_key: str = Header(default="")):
    _check_api_key(x_api_key)

    results = []
    for entry in req.actions:
        allowed, resolved, reason = _locally_revalidate(entry)
        if not allowed:
            results.append({
                "path": entry.path, "action": entry.action,
                "success": False, "detail": f"rejected by agent: {reason}",
            })
            continue

        try:
            if entry.action == "delete":
                os.remove(resolved)
                results.append({"path": resolved, "action": "delete", "success": True, "detail": "deleted"})
            elif entry.action == "compress":
                archive_path = resolved + ".gz"
                import gzip
                with open(resolved, "rb") as f_in, gzip.open(archive_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.remove(resolved)
                results.append({
                    "path": resolved, "action": "compress", "success": True,
                    "detail": f"compressed to {archive_path}",
                })
        except OSError as e:
            results.append({"path": resolved, "action": entry.action, "success": False, "detail": str(e)})

    return {"results": results}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("AGENT_PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)
