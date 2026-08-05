"""
policy.py — Core Policy Engine

Generic, reusable rules for validating filesystem-affecting actions proposed
by an AI system. This module knows nothing about any specific caller's API
contract (that lives in safety_checker.py) — it only answers three questions:

    1. Is this path safe to touch, given an allow-list and a deny-list?
    2. Is this path owned by a real human user, or a system/service account?
    3. Does this path/command match a known-dangerous pattern?

Design principles:
    - Fail closed. Any ambiguity (unresolvable path, unknown action type,
      symlink escape, traversal, unreadable ownership) results in REJECTION,
      not a warning.
    - Canonicalize before comparing. Never compare raw strings; always
      resolve to an absolute, symlink-free path first.
    - Defense in depth. Even if a path is under an allowed directory and
      matches an expected file type, it is still checked against critical
      filename/path lists AND file-ownership rules independently.
"""

from __future__ import annotations

import os
import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger("policy_engine")


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PolicyResult:
    allowed: bool
    risk_level: RiskLevel
    reason: str
    rule_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Critical system paths — never touchable, regardless of allow-list contents.
# This is intentionally broader than any one caller's block-list so the core
# engine stays safe even if a caller misconfigures its own allow-list.
# ---------------------------------------------------------------------------
CRITICAL_PATH_PREFIXES = [
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root",
    "/sys", "/proc", "/dev", "/opt",
    "/home",  # user home dirs are off-limits by default for AI-initiated ops
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "/System", "/Library/LaunchDaemons", "/Library/LaunchAgents",
]

CRITICAL_FILENAMES = {
    "passwd", "shadow", "sudoers", "fstab", "hosts", "crontab",
    "authorized_keys", "id_rsa", "id_ed25519", "known_hosts",
}

# Default cutoff between "system/service account" UIDs and "real human
# user" UIDs on a typical Linux distro. UIDs below this are reserved for
# the OS and daemons (root=0, various service accounts 1-999). Debian/
# Ubuntu and RHEL-family both default new human accounts to 1000+.
DEFAULT_MIN_HUMAN_UID = 1000

DANGEROUS_COMMAND_PATTERNS = [
    (r"rm\s+-rf\s+/(?:\s|$)", "recursive delete of root"),
    (r"rm\s+-rf\s+~", "recursive delete of home"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    (r"dd\s+if=.*of=/dev/(sd|nvme|hd)", "raw disk write"),
    (r"mkfs\.", "filesystem format"),
    (r"chmod\s+-R\s+777\s+/", "recursive world-writable root"),
    (r">\s*/dev/sd[a-z]", "raw device overwrite"),
    (r"curl.*\|\s*(sh|bash)", "pipe download to shell"),
    (r"wget.*\|\s*(sh|bash)", "pipe download to shell"),
    (r"\bsudo\b", "privilege escalation"),
    (r"DROP\s+(DATABASE|TABLE)", "destructive SQL"),
    (r"shutdown|reboot|init\s+0", "system power control"),
]
_DANGEROUS_COMMAND_RE = [(re.compile(p, re.IGNORECASE), why) for p, why in DANGEROUS_COMMAND_PATTERNS]


def canonicalize(raw_path: str, base: Optional[str] = None) -> str:
    """
    Resolve a path to an absolute, symlink-free, normalized form.
    Raises ValueError if the path cannot be safely resolved.
    """
    if raw_path is None:
        raise ValueError("path is None")
    if "\x00" in raw_path:
        raise ValueError("null byte in path")

    p = Path(raw_path)
    if base and not p.is_absolute():
        p = Path(base) / p

    if not p.is_absolute():
        raise ValueError(f"path is not absolute: {raw_path!r}")

    # os.path.realpath resolves '..', '.', and symlinks (even if the target
    # does not exist, it resolves as much of the chain as it can).
    resolved = os.path.realpath(str(p))
    return resolved


def is_critical_path(resolved_path: str) -> Optional[str]:
    """Return a reason string if the path is a protected system path, else None."""
    norm = resolved_path.replace("\\", "/")
    for prefix in CRITICAL_PATH_PREFIXES:
        prefix_norm = prefix.replace("\\", "/")
        if norm == prefix_norm or norm.startswith(prefix_norm.rstrip("/") + "/"):
            return f"path is under protected system directory {prefix}"

    filename = os.path.basename(norm)
    if filename in CRITICAL_FILENAMES:
        return f"filename '{filename}' matches critical-file list"

    return None


def is_within_any(resolved_path: str, allowed_dirs: Iterable[str]) -> Optional[str]:
    """Return the matching allowed-dir prefix if resolved_path is inside it, else None."""
    for d in allowed_dirs:
        allowed_resolved = os.path.realpath(d)
        if resolved_path == allowed_resolved or resolved_path.startswith(allowed_resolved.rstrip("/") + "/"):
            return allowed_resolved
    return None


def check_path(
    raw_path: str,
    allowed_dirs: Iterable[str],
    base: Optional[str] = None,
) -> PolicyResult:
    """
    Validate a single path against an allow-list, with mandatory
    critical-path protection layered on top regardless of allow-list content.
    """
    try:
        resolved = canonicalize(raw_path, base=base)
    except ValueError as e:
        return PolicyResult(False, RiskLevel.HIGH, f"path rejected: {e}", rule_id="PATH_UNRESOLVABLE")

    critical_reason = is_critical_path(resolved)
    if critical_reason:
        return PolicyResult(False, RiskLevel.CRITICAL, critical_reason, rule_id="CRITICAL_PATH")

    match = is_within_any(resolved, allowed_dirs)
    if not match:
        return PolicyResult(
            False, RiskLevel.HIGH,
            f"path '{resolved}' is not under any allowed directory",
            rule_id="OUTSIDE_ALLOWLIST",
        )

    return PolicyResult(True, RiskLevel.SAFE, f"path within allowed directory {match}", rule_id="OK")


def check_ownership(resolved_path: str, min_human_uid: int = DEFAULT_MIN_HUMAN_UID) -> PolicyResult:
    """
    Reject actions on files owned by a system/service account (UID below
    min_human_uid — typically 0-999 on Linux/Debian/RHEL conventions).

    This is an INDEPENDENT layer from path-based rules: a file can sit in
    an allowed directory like /var/log and still be owned by a daemon
    (e.g. uid 0 root, uid 33 www-data) rather than a real human user, and
    we don't want the AI cleanup agent deleting/compressing files it
    didn't create just because the path looks right.

    On platforms without POSIX ownership (Windows), this check is skipped
    and always passes — ownership-based rules there would need a different
    mechanism (ACLs), not implemented here.

    Fails closed: if the path can't be stat'd at all, it is rejected rather
    than assumed safe.
    """
    if not hasattr(os, "getuid"):
        # Non-POSIX platform (e.g. Windows) — ownership concept doesn't map
        # the same way; skip rather than produce a misleading result.
        return PolicyResult(True, RiskLevel.SAFE, "ownership check not applicable on this platform", rule_id="OK")

    try:
        st = os.stat(resolved_path, follow_symlinks=False)
    except OSError as e:
        return PolicyResult(False, RiskLevel.HIGH, f"cannot stat path for ownership check: {e}", rule_id="STAT_FAILED")

    if st.st_uid < min_human_uid:
        return PolicyResult(
            False, RiskLevel.CRITICAL,
            f"path is owned by system/service UID {st.st_uid} (< {min_human_uid}); "
            f"only files owned by human user accounts are eligible for AI-initiated cleanup",
            rule_id="SYSTEM_OWNED_FILE",
        )

    return PolicyResult(True, RiskLevel.SAFE, f"file owned by human UID {st.st_uid}", rule_id="OK")


def check_command(command: str) -> PolicyResult:
    """Check a shell-command-like string against known-dangerous patterns."""
    if command is None:
        return PolicyResult(False, RiskLevel.HIGH, "command is None", rule_id="EMPTY_COMMAND")
    for pattern, why in _DANGEROUS_COMMAND_RE:
        if pattern.search(command):
            return PolicyResult(False, RiskLevel.CRITICAL, f"matched dangerous pattern: {why}", rule_id="DANGEROUS_COMMAND")
    return PolicyResult(True, RiskLevel.SAFE, "no dangerous pattern matched", rule_id="OK")
