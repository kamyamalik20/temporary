"""
agent_client.py — central server's client for talking to remote agents.

Each remote machine runs agent/agent_server.py, which exposes:
    GET  /health
    GET  /scan
    POST /execute

Credentials (api_key) come from config.yaml's `servers:` list, per the
"plaintext in config.yaml" decision — fine for an internal/trusted network,
but note in RUNBOOK.md that config.yaml should have restrictive file
permissions (chmod 600) since it holds secrets.
"""

from __future__ import annotations

import requests

DEFAULT_TIMEOUT = 20


class AgentError(Exception):
    pass


class AgentClient:
    def __init__(self, name: str, host: str, port: int, api_key: str, timeout: int = DEFAULT_TIMEOUT):
        self.name = name
        self.base_url = f"http://{host}:{port}"
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"X-API-Key": self.api_key}

    def health(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/health", headers=self._headers(), timeout=self.timeout)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def scan(self) -> dict:
        """
        Trigger a scan on the remote agent and return its result:
            {"hostname": ..., "scanned_at": ..., "files": [...]}
        Raises AgentError with a diagnosable message on failure — this is
        the "why can't it connect" path requirement #3 asked for.
        """
        try:
            r = requests.get(f"{self.base_url}/scan", headers=self._headers(), timeout=self.timeout)
        except requests.ConnectionError as e:
            raise AgentError(
                f"could not connect to agent '{self.name}' at {self.base_url} — "
                f"is agent_server.py running there, and is the port open/firewalled correctly? ({e})"
            )
        except requests.Timeout as e:
            raise AgentError(f"agent '{self.name}' at {self.base_url} timed out after {self.timeout}s ({e})")
        except requests.RequestException as e:
            raise AgentError(f"request to agent '{self.name}' failed: {e}")

        if r.status_code == 401:
            raise AgentError(
                f"agent '{self.name}' rejected our API key (401) — check that config.yaml's "
                f"api_key for '{self.name}' matches that server's AGENT_API_KEY env var"
            )
        if r.status_code != 200:
            raise AgentError(f"agent '{self.name}' returned HTTP {r.status_code}: {r.text[:300]}")

        return r.json()

    def execute(self, approved_actions: list[dict]) -> dict:
        """
        Ask the remote agent to actually perform a list of pre-approved
        actions. The agent independently re-validates every action before
        touching disk — this call does not bypass that.
        """
        try:
            r = requests.post(
                f"{self.base_url}/execute",
                json={"actions": approved_actions},
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise AgentError(f"could not reach agent '{self.name}' to execute actions: {e}")

        if r.status_code == 401:
            raise AgentError(f"agent '{self.name}' rejected our API key (401) while executing actions")
        if r.status_code != 200:
            raise AgentError(f"agent '{self.name}' returned HTTP {r.status_code} on execute: {r.text[:300]}")

        return r.json()


def load_agents_from_config(config: dict) -> dict[str, AgentClient]:
    """config is the parsed config.yaml dict; returns {name: AgentClient}."""
    agents = {}
    for entry in config.get("servers", []):
        client = AgentClient(
            name=entry["name"],
            host=entry["host"],
            port=entry.get("port", 8001),
            api_key=entry["api_key"],
        )
        agents[client.name] = client
    return agents
