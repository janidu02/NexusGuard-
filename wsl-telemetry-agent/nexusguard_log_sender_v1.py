import os
import time
import json
import socket
import datetime
import requests

try:
    from requests_aws4auth import AWS4Auth
except ImportError:
    AWS4Auth = None

# ==========================
# CONFIG
# ==========================
LOG_FILE = r"C:\ProgramData\NexusGuard\command_stream.log"
CONFIG_FILE = r"C:\ProgramData\NexusGuard\agent_config.json"

WEBHOOK_URL = "https://discord.com/api/webhooks/1445332786419597443/kk6XcxOu1Lsx6TaXuNBe2N5kqGp2W-c-YgkpuXz14HUV99IbxchzOWK52aCMvYqOiZvt"

MAX_BATCH_SIZE = 10
MAX_BATCH_INTERVAL = 10.0

AWS_ENDPOINT = "https://60oyks9dz0.execute-api.ap-south-1.amazonaws.com/prod/ingest"
AWS_REGION = "ap-south-1"
AWS_SERVICE = "execute-api"

AWS_ACCESS_KEY_ID = " "
AWS_SECRET_ACCESS_KEY = " "

AWS_AUTH = None
if AWS4Auth:
    AWS_AUTH = AWS4Auth(
        AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY,
        AWS_REGION,
        AWS_SERVICE
    )

# ==========================
# Agent ID handling
# ==========================

def load_or_init_agent_id():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)["agent_id"]

    agent_id = input("Enter Agent ID (one-time setup): ").strip()
    if not agent_id:
        raise SystemExit("Agent ID is required")

    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump({"agent_id": agent_id}, f, indent=2)

    return agent_id

# ==========================
# Helpers
# ==========================

def make_batch_id(agent_id: str) -> str:
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    host = socket.gethostname()
    return f"{ts}-{agent_id}-{host}"

def parse_log_line(line: str, seq: int):
    line = line.strip()
    if not line:
        return None

    parts = line.split("|")
    if len(parts) < 6:
        return None

    ts = parts[0]
    cmd = parts[1]

    pid = None
    if parts[2].startswith("PID="):
        val = parts[2][4:]
        if val.lower() != "null":
            try:
                pid = int(val)
            except:
                pid = None

    return {
        "timestamp": ts,
        "sequence": seq,
        "command": cmd,
        "pid": pid,
        "user": parts[3],
        "host": parts[4]
    }

# ==========================
# Senders
# ==========================

def send_batch_to_discord(batch_payload: dict):
    pretty = json.dumps(batch_payload, indent=2)
    content = f"```json\n{pretty}\n```"

    try:
        resp = requests.post(WEBHOOK_URL, json={"content": content}, timeout=10)
        if 200 <= resp.status_code < 300:
            print(f"[+] Sent batch {batch_payload['batch_id']} to Discord "
                  f"({len(batch_payload['logs'])} logs)")
        else:
            print(f"[!] Discord error {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[!] Discord send error: {e}")


def send_batch_to_aws(payload):
    if not AWS_AUTH:
        print("[WARN] AWS auth not available")
        return

    print("\n=== AWS POST ===")
    try:
        r = requests.post(AWS_ENDPOINT, json=payload, auth=AWS_AUTH, timeout=10)
        print("HTTP:", r.status_code)
        print("Body:", r.text)
    except Exception as e:
        print("[!] AWS error:", e)

# ==========================
# Tail + Batch
# ==========================

def tail_and_batch(agent_id):
    while not os.path.exists(LOG_FILE):
        print("Waiting for log file...")
        time.sleep(2)

    print(f"[+] Watching {LOG_FILE}")

    batch = []
    batch_start = None
    seq = 1

    def flush(force=False):
        nonlocal batch, batch_start, seq

        if not batch:
            return

        age = time.time() - batch_start if batch_start else 0
        if not force and len(batch) < MAX_BATCH_SIZE and age < MAX_BATCH_INTERVAL:
            return

        payload = {
            "agent_id": agent_id,
            "batch_id": make_batch_id(agent_id),
            "logs": batch
        }

        #send_batch_to_aws(payload)
        send_batch_to_discord(payload)

        batch = []
        batch_start = None
        seq = 1

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.3)
                    flush(False)
                    continue

                entry = parse_log_line(line, seq)
                if entry:
                    if not batch:
                        batch_start = time.time()
                    batch.append(entry)
                    seq += 1

                flush(False)

        except KeyboardInterrupt:
            print("\n[!] Exiting → flushing")
            flush(True)

# ==========================
# Main
# ==========================

def main():
    print("=== NexusGuard Log Sender ===\n")
    agent_id = load_or_init_agent_id()
    tail_and_batch(agent_id)

if __name__ == "__main__":
    main()
