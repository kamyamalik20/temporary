# RUNBOOK — running this on Ubuntu

This system has two kinds of machine:

- **Central server** (one machine) — runs `app/AI_server.py`, talks to
  Ollama for AI decisions, holds the login system, and calls out to every
  remote agent.
- **Agents** (one per monitored server) — each runs `agent/agent_server.py`
  locally on that machine, and does the actual scanning/deleting there.

Deploy the **whole project folder** to every machine (central + every
agent) — they all import from the same `app/` package.

---

## 0. One-time setup on every machine (central + each agent)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

# copy/clone the project, then:
cd /path/to/project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 1. Set up each AGENT server (run this on every remote machine you want monitored)

```bash
cd /path/to/project
source venv/bin/activate

# Pick a long random secret for this machine — this is what the central
# server must present to talk to it.
export AGENT_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
echo "Agent key for this machine: $AGENT_API_KEY"
# ^ copy this value — you'll paste it into the central server's config.yaml

export AGENT_PORT=8001                # default; change if needed
# Optional overrides (defaults come from app/files.py's default_paths()):
# export AGENT_SCAN_PATHS="/tmp,/var/log,/backup"
# export AGENT_MIN_SIZE_MB=50
# export AGENT_MIN_AGE_DAYS=30
# export AGENT_MIN_HUMAN_UID=1000

python3 agent/agent_server.py
```

Leave this running (or set it up as a systemd service — see below).
Make sure port 8001 (or whatever you chose) is reachable from the central
server, e.g.:

```bash
sudo ufw allow from <central-server-ip> to any port 8001 proto tcp
```

### Run the agent as a systemd service (recommended for production)

`/etc/systemd/system/disk-agent.service`:
```ini
[Unit]
Description=Disk Monitor Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/project
Environment=AGENT_API_KEY=paste-the-key-here
Environment=AGENT_PORT=8001
ExecStart=/path/to/project/venv/bin/python3 agent/agent_server.py
Restart=on-failure
User=diskmonitor

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now disk-agent
sudo systemctl status disk-agent
```

---

## 2. Set up the CENTRAL server

### 2a. Install and start Ollama (for the AI decision engine)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b-instruct
ollama serve &   # or run as its own systemd service
```

### 2b. Edit `config.yaml`

Fill in each agent you set up in step 1, using the `AGENT_API_KEY` you
generated for it:

```yaml
servers:
  - name: web-01
    host: 10.0.0.10
    port: 8001
    api_key: "paste-web-01s-generated-key-here"
  - name: db-01
    host: 10.0.0.11
    port: 8001
    api_key: "paste-db-01s-generated-key-here"
```

Lock the file down since it has secrets in it:
```bash
chmod 600 config.yaml
```

### 2c. Start the central server

```bash
cd /path/to/project
source venv/bin/activate
python3 -m app.AI_server
```

On first run with no users yet, it auto-creates a default admin account
and prints the generated password **once** to the console:

```
No users existed — created a default admin account:
  username: admin
  password: <random>
Log in and create a real account, then remove/rotate this one.
```

Save that password now — it won't be shown again. Log in immediately and
create your real account(s).

---

## 3. Using the system (curl examples)

```bash
BASE=http://localhost:8000

# Log in, save the token
TOKEN=$(curl -s -X POST $BASE/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<the printed password>"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Create a second, real admin account (requires an admin token)
curl -s -X POST $BASE/users \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"a-strong-password-here","role":"admin"}'

# Create a read-only account
curl -s -X POST $BASE/users \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"a-strong-password-here","role":"viewer"}'

# See configured servers and whether each is reachable
curl -s $BASE/servers -H "Authorization: Bearer $TOKEN"

# Scan a specific server
curl -s -X POST $BASE/servers/web-01/scan -H "Authorization: Bearer $TOKEN"

# Ask the AI for a cleanup plan for that server (safety-checked automatically)
curl -s -X POST $BASE/servers/web-01/cleanup-plan -H "Authorization: Bearer $TOKEN"

# Execute the approved actions on that server (admin role required)
curl -s -X POST $BASE/servers/web-01/cleanup-plan/execute -H "Authorization: Bearer $TOKEN"
```

---

## 4. Troubleshooting connections ("why can't it connect")

If `/servers/{name}/scan` or `/execute` fails, the central server returns
a specific, diagnosable message (HTTP 502) rather than a generic error:

- **"could not connect to agent ... is agent_server.py running there, and
  is the port open/firewalled correctly?"** → the agent process isn't
  running, or a firewall/security group is blocking the port. Check
  `systemctl status disk-agent` on that machine, and `curl` the agent's
  `/health` endpoint directly from the central server:
  ```bash
  curl -H "X-API-Key: <that server's key>" http://<agent-host>:8001/health
  ```
- **"rejected our API key (401)"** → the `api_key` in the central
  server's `config.yaml` for that server doesn't match the `AGENT_API_KEY`
  environment variable set on that agent. Re-copy the value exactly (no
  extra whitespace/newlines) on both sides.
- **timeout** → network path exists but is slow/blocked partway (e.g. a
  security group allows the port from a different IP than the central
  server actually uses). Confirm the central server's outbound IP matches
  what's allowed.

---

## 5. Running the test suite

```bash
cd /path/to/project
source venv/bin/activate
pytest -v test_security.py
```

All tests should pass regardless of which user runs pytest (root or not)
— see the notes in `test_security.py`'s `sandbox` fixture and
`TestOwnershipProtection` for why.
