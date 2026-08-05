import json
from pathlib import Path
from typing import List, Optional

import requests
import yaml
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from .agent_client import AgentClient, AgentError, load_agents_from_config
from .safety_checker import process_cleanup_plan
from .users import bootstrap_default_admin, create_user, get_current_user, issue_token, require_role, verify_user

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
CONFIG_PATH = BASE_DIR / "config.yaml"

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:7b-instruct"
REQUEST_TIMEOUT_SECONDS = 120

app = FastAPI(title="AI Cleanup Decision Engine")


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f) or {}


CONFIG = load_config()
AGENTS: dict[str, AgentClient] = load_agents_from_config(CONFIG)

bootstrap_default_admin()


class FileEntry(BaseModel):
    path: str
    size_mb: float
    age_days: int
    type: Optional[str] = "unknown"
    modified_date: Optional[str] = None
    size_bytes: Optional[int] = None
    owner_uid: Optional[int] = None


class CleanupRequest(BaseModel):
    hostname: str
    scanned_at: Optional[str] = None
    files: List[FileEntry]


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class ExecuteRequest(BaseModel):
    server: str
    actions: List[dict]


SYSTEM_PROMPT = """
You are a Linux storage optimization assistant.

Recommend which files are safe to delete or compress.

Rules:
- NEVER recommend actions under /etc /usr /home /bin /lib
- Only recommend actions for log, cache, tmp, backup and iso files.
- Prefer compress for large logs.
- Prefer delete for old temp, cache, backup and iso files.

Return ONLY valid JSON.

Example:
{
  "actions":[
    {
      "action":"delete",
      "path":"/tmp/test.iso",
      "reason":"Old ISO"
    }
  ]
}

If nothing qualifies return:
{"actions":[]}
"""


def build_prompt(files: List[FileEntry]) -> str:
    return SYSTEM_PROMPT + "\n\nFiles:\n" + json.dumps(
        [f.model_dump() for f in files], indent=2
    )


def call_ollama(prompt: str) -> str:
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": {"temperature": 0},
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))

    return response.json().get("response", "")


def _get_plan_for_files(files: List[FileEntry]) -> dict:
    prompt = build_prompt(files)
    raw = call_ollama(prompt)
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail=f"Model returned invalid JSON:\n{raw}")
    if "actions" not in plan or not isinstance(plan["actions"], list):
        raise HTTPException(status_code=502, detail="Model response missing actions list")
    return plan


# ---------------------------------------------------------------------------
# Public / health
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "AI Cleanup Decision Engine Running"}


@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_NAME}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.post("/login")
def login(req: LoginRequest):
    user = verify_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="invalid username or password")
    token = issue_token(user["username"], user["role"])
    return {"token": token, "role": user["role"]}


@app.post("/users")
def add_user(req: CreateUserRequest, current_user: dict = Depends(require_role("admin"))):
    try:
        create_user(req.username, req.password, req.role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"created": req.username, "role": req.role, "created_by": current_user["username"]}


# ---------------------------------------------------------------------------
# Legacy single-host endpoints (kept for backward compatibility — operate
# on locally-supplied file lists, no remote agent involved)
# ---------------------------------------------------------------------------
@app.post("/cleanup-plan")
def cleanup_plan(request: CleanupRequest, current_user: dict = Depends(get_current_user)):
    if not request.files:
        return {"actions": []}
    plan = _get_plan_for_files(request.files)
    with open(DATA_DIR / "sample_actions.json", "w") as f:
        json.dump(plan, f, indent=4)
    return plan


@app.post("/cleanup-plan/from-file")
def cleanup_plan_from_file(current_user: dict = Depends(get_current_user)):
    file_path = DATA_DIR / "files.json"
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="data/files.json not found")
    with open(file_path, "r") as f:
        payload = json.load(f)
    request = CleanupRequest(**payload)
    return cleanup_plan(request, current_user)


# ---------------------------------------------------------------------------
# Multi-server endpoints
# ---------------------------------------------------------------------------
@app.get("/servers")
def list_servers(current_user: dict = Depends(get_current_user)):
    return {
        name: {"host": client.base_url, "healthy": client.health()}
        for name, client in AGENTS.items()
    }


def _get_agent_or_404(name: str) -> AgentClient:
    agent = AGENTS.get(name)
    if not agent:
        raise HTTPException(
            status_code=404,
            detail=f"no server named '{name}' in config.yaml. Known servers: {list(AGENTS)}",
        )
    return agent


@app.post("/servers/{name}/scan")
def scan_server(name: str, current_user: dict = Depends(get_current_user)):
    agent = _get_agent_or_404(name)
    try:
        result = agent.scan()
    except AgentError as e:
        # Requirement #3: surface *why* the connection failed, not just "error".
        raise HTTPException(status_code=502, detail=str(e))

    out_path = DATA_DIR / "servers" / f"{name}_files.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    return result


@app.post("/servers/{name}/cleanup-plan")
def cleanup_plan_for_server(name: str, current_user: dict = Depends(get_current_user)):
    scan_path = DATA_DIR / "servers" / f"{name}_files.json"
    if not scan_path.exists():
        raise HTTPException(status_code=404, detail=f"no scan on file for '{name}' — call /servers/{name}/scan first")

    with open(scan_path, "r") as f:
        scanned = json.load(f)

    files = [FileEntry(**f) for f in scanned.get("files", [])]
    if not files:
        return {"actions": []}

    plan = _get_plan_for_files(files)
    checked = process_cleanup_plan(plan, requested_by=current_user["username"])

    out_path = DATA_DIR / "servers" / f"{name}_plan.json"
    with open(out_path, "w") as f:
        json.dump(checked, f, indent=2)
    return checked


@app.post("/servers/{name}/cleanup-plan/execute")
def execute_plan_for_server(name: str, current_user: dict = Depends(require_role("admin"))):
    """
    Executes the *approved* actions from the most recent cleanup-plan run
    for this server. Requires the admin role — viewers can request scans
    and see plans, but only admins can actually delete/compress files.
    """
    agent = _get_agent_or_404(name)
    plan_path = DATA_DIR / "servers" / f"{name}_plan.json"
    if not plan_path.exists():
        raise HTTPException(status_code=404, detail=f"no plan on file for '{name}' — call cleanup-plan first")

    with open(plan_path, "r") as f:
        checked = json.load(f)

    approved = checked.get("approved", [])
    if not approved:
        return {"results": [], "note": "no approved actions to execute"}

    try:
        result = agent.execute(approved)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
