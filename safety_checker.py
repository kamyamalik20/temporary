"""
safety_checker.py — Task 4: Safety Checker

Consumes the JSON contract produced by the AI Decision Engine
(POST /cleanup-plan or POST /servers/{name}/cleanup-plan):

    {"actions": [{"action": "delete"|"compress", "path": "...", "reason": "..."}]}

This module is the ONLY enforcement boundary. The model is prompted to
avoid /etc, /usr, /home, /bin, /lib, but nothing stops a future response
from violating that. Every action is re-validated here from scratch,
independent of what the model claims about itself.

Layers of defense applied to every action, in order:
    1. Shape validation (action type, path type/presence)
    2. Directory allow-list + critical-path/critical-filename block-list
       (policy.check_path)
    3. File-type allow-list (looks like a log/cache/tmp/backup/iso)
    4. Ownership check (policy.check_ownership) — file must be owned by a
       real human user account (UID >= min_human_uid), not a system/
       service account, regardless of where it sits on disk.

Contract assumptions (do NOT silently relax these):
    - action is always "delete" or "compress" today, but we defensively
      reject anything else rather than assume the set is closed forever.
    - path is an absolute string, untrusted — canonicalize/resolve before
      any comparison (handles ../ traversal and symlink escapes).
    - reason is free text for logging/display only — never parsed for
      logic, and sanitized before it could ever reach a UI.
    - actions can be an empty list — treated as a no-op, not an error.
    - malformed entries (missing fields, wrong types) must not crash the
      whole batch — each entry is validated independently.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, asdict
from typing import Any

from .policy import check_path, check_ownership, canonicalize, is_critical_path, RiskLevel, DEFAULT_MIN_HUMAN_UID

logger = logging.getLogger("safety_checker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# ---------------------------------------------------------------------------
# Allow-list: directories the cleanup agent is permitted to act on.
# Deliberately does NOT include /etc, /usr, /home, /bin, /lib, /sbin, /boot,
# /root — those are already covered by policy.py's CRITICAL_PATH_PREFIXES
# as a second, independent layer of defense.
# ---------------------------------------------------------------------------
ALLOWED_DIRS = [
    "/tmp",
    "/var/tmp",
    "/var/cache",
    "/var/log",       # rotated/old logs only — see _matches_expected_type
    "/var/backups",
]

# UID below which a file is considered system/service-owned and therefore
# never eligible for cleanup. Overridable per-deployment via config.yaml's
# `min_human_uid` (see AI_server.py / agent_server.py startup).
MIN_HUMAN_UID = DEFAULT_MIN_HUMAN_UID

# Valid action types today. Anything else is rejected, defense-in-depth
# against a future model version emitting a new action type this checker
# was never reviewed against.
ALLOWED_ACTION_TYPES = {"delete", "compress"}

# File-type allow-list, matching what the model was prompted to act on:
# log, cache, tmp, backup, iso files. This is an *additional* layer on top
# of the directory allow-list — being in /var/log is not sufficient if the
# file doesn't look like a log/cache/backup/tmp/iso artifact.
_ALLOWED_SUFFIX_RE = re.compile(
    r"(\.log(\.\d+)?(\.gz)?$|\.gz$|\.tmp$|\.cache$|\.bak$|\.old$|\.iso$|~$)",
    re.IGNORECASE,
)


@dataclass
class CheckedAction:
    action: str
    path: str
    reason: str
    approved: bool
    rejection_reason: str = ""
    requested_by: str = "unknown"


def sanitize_display_text(text: Any, max_len: int = 500) -> str:
    """
    Treat model-provided free text as untrusted. Strip control characters
    and cap length before it could ever be rendered in a UI or log viewer
    that interprets HTML/ANSI.
    """
    if not isinstance(text, str):
        return ""
    text = text[:max_len]
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # neutralize the most common injection vectors without being a full
    # HTML sanitizer — callers rendering to HTML must still escape properly.
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return text


def _matches_expected_type(resolved_path: str) -> bool:
    return bool(_ALLOWED_SUFFIX_RE.search(resolved_path))


def _validate_single_action(raw_entry: Any, requested_by: str) -> CheckedAction:
    """
    Validate one action entry in isolation. Never raises — always returns
    a CheckedAction, so one malformed entry can't take down the batch.
    """
    if not isinstance(raw_entry, dict):
        return CheckedAction(
            action=str(raw_entry)[:100], path="", reason="",
            approved=False, rejection_reason="entry is not a JSON object",
            requested_by=requested_by,
        )

    action = raw_entry.get("action")
    path = raw_entry.get("path")
    reason = sanitize_display_text(raw_entry.get("reason", ""))

    if not isinstance(action, str) or action not in ALLOWED_ACTION_TYPES:
        return CheckedAction(
            action=str(action), path=str(path or ""), reason=reason,
            approved=False,
            rejection_reason=f"unknown or missing action type: {action!r}",
            requested_by=requested_by,
        )

    if not isinstance(path, str) or not path.strip():
        return CheckedAction(
            action=action, path=str(path or ""), reason=reason,
            approved=False, rejection_reason="missing or invalid path",
            requested_by=requested_by,
        )

    result = check_path(path, ALLOWED_DIRS)
    if not result.allowed:
        return CheckedAction(
            action=action, path=path, reason=reason,
            approved=False, rejection_reason=result.reason,
            requested_by=requested_by,
        )

    resolved = canonicalize(path)

    if not _matches_expected_type(resolved):
        return CheckedAction(
            action=action, path=path, reason=reason,
            approved=False,
            rejection_reason=(
                "path is in an allowed directory but does not match an "
                "expected log/cache/tmp/backup/iso file pattern"
            ),
            requested_by=requested_by,
        )

    # Ownership layer — only meaningful if the file actually exists locally
    # (agents run this against real files; the central orchestrator running
    # against a remote server's *reported* paths won't have local inodes to
    # stat, so it skips this and leaves final enforcement to the agent).
    if os.path.exists(resolved) or os.path.islink(resolved):
        ownership_result = check_ownership(resolved, MIN_HUMAN_UID)
        if not ownership_result.allowed:
            return CheckedAction(
                action=action, path=path, reason=reason,
                approved=False, rejection_reason=ownership_result.reason,
                requested_by=requested_by,
            )

    return CheckedAction(action=action, path=path, reason=reason, approved=True, requested_by=requested_by)


def process_cleanup_plan(payload: dict, requested_by: str = "unknown") -> dict:
    """
    Entry point matching the AI Decision Engine's response shape.

    Input:  {"actions": [{"action": ..., "path": ..., "reason": ...}, ...]}
    Output: {"approved": [...], "rejected": [...]}   (both lists of dicts)

    requested_by: identity of the authenticated user/session that triggered
    this plan (from app.users), stamped onto every resulting action for
    audit purposes. Defaults to "unknown" for callers that don't yet have
    an authenticated context (e.g. legacy/local single-host usage).

    - Empty `actions` list is a valid no-op; returns immediately.
    - Each entry is validated independently; one bad entry does not affect
      the others.
    - Every rejection is logged with its reason.
    """
    if not isinstance(payload, dict) or "actions" not in payload:
        logger.error("Malformed payload: missing 'actions' key: %r", payload)
        return {"approved": [], "rejected": [], "error": "missing 'actions' key"}

    actions = payload["actions"]
    if not isinstance(actions, list):
        logger.error("Malformed payload: 'actions' is not a list: %r", type(actions))
        return {"approved": [], "rejected": [], "error": "'actions' must be a list"}

    if len(actions) == 0:
        logger.info("Empty action list received — no-op.")
        return {"approved": [], "rejected": []}

    approved, rejected = [], []
    for entry in actions:
        checked = _validate_single_action(entry, requested_by)
        if checked.approved:
            approved.append(asdict(checked))
        else:
            logger.warning(
                "REJECTED action=%r path=%r requested_by=%r reason=%r",
                checked.action, checked.path, checked.requested_by, checked.rejection_reason,
            )
            rejected.append(asdict(checked))

    logger.info("Processed %d actions for %s: %d approved, %d rejected",
                len(actions), requested_by, len(approved), len(rejected))
    return {"approved": approved, "rejected": rejected}


def forward_to_warning_system(approved_actions: list[dict]) -> None:
    """
    Stub for handoff to the downstream consumer ("Task 5 / Warning System").
    Confirm the actual transport (HTTP call, queue, direct import) with the
    team before wiring this up.

    For now this only logs what would be forwarded, so the safety boundary
    is testable in isolation before the downstream integration exists.
    """
    if not approved_actions:
        logger.info("No approved actions to forward.")
        return
    for a in approved_actions:
        logger.info("FORWARD -> warning system: %s", a)


if __name__ == "__main__":
    import json
    import sys

    data = json.load(sys.stdin) if not sys.stdin.isatty() else {"actions": []}
    result = process_cleanup_plan(data)
    forward_to_warning_system(result["approved"])
    print(json.dumps(result, indent=2))
