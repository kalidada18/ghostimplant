import requests
import json
import sys
import getpass
from datetime import datetime

BASE_URL = "https://127.0.0.1"
VERIFY_SSL = False  # for self-signed

def list_sessions():
    r = requests.get(f"{BASE_URL}/sessions", verify=VERIFY_SSL)
    if r.status_code == 200:
        for s in r.json():
            print(f"Session: {s['session']}  Last: {datetime.fromtimestamp(s['last_beacon'])}  Recon: {s['recon']}")
    else:
        print("Error")

def task_session(sid, cmd):
    payload = {"session": sid, "cmd": cmd}
    r = requests.post(f"{BASE_URL}/task", json=payload, verify=VERIFY_SSL)
    if r.status_code == 200:
        print("Task queued")
    else:
        print("Error")

def get_results(sid):
    r = requests.get(f"{BASE_URL}/results/{sid}", verify=VERIFY_SSL)
    if r.status_code == 200:
        data = r.json()
        for line in data['results']:
            print(line)
    else:
        print("No results")

def main():
    if len(sys.argv) < 2:
        print("Commands: list, task <sid> <cmd>, results <sid>")
        return
    cmd = sys.argv[1].lower()
    if cmd == "list":
        list_sessions()
    elif cmd == "task" and len(sys.argv) >= 4:
        task_session(sys.argv[2], sys.argv[3])
    elif cmd == "results" and len(sys.argv) >= 3:
        get_results(sys.argv[2])
    else:
        print("Invalid command")

if __name__ == "__main__":
    main()