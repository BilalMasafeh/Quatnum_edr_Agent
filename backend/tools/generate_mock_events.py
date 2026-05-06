import urllib.request
import json
import random
import time

API_URL = "http://localhost:8000/api/event"

MOCK_EVENTS = [
    {
        "type": "Malicious (Ransomware Behavior)",
        "data": {
            "process_name": "unknown_encrypter.exe",
            "pid": 0, # Replaced dynamically
            "parent_process": "explorer.exe",
            "network_connections": 55,
            "file_writes": 2500,
            "registry_changes": 20,
            "child_processes": 0,
            "unique_ips": 5,
            "suspicious_ports": 2
        }
    },
    {
        "type": "Malicious (Reverse Shell)",
        "data": {
            "process_name": "powershell.exe",
            "pid": 0,
            "parent_process": "cmd.exe",
            "network_connections": 120,
            "file_writes": 5,
            "registry_changes": 2,
            "child_processes": 5,
            "unique_ips": 1,
            "suspicious_ports": 1 # e.g. 4444
        }
    },
    {
        "type": "Suspicious (Unusual Network)",
        "data": {
            "process_name": "updater.exe",
            "pid": 0,
            "parent_process": "svchost.exe",
            "network_connections": 40,
            "file_writes": 50,
            "registry_changes": 5,
            "child_processes": 1,
            "unique_ips": 15,
            "suspicious_ports": 0
        }
    },
    {
        "type": "Safe (Browser)",
        "data": {
            "process_name": "chrome.exe",
            "pid": 0,
            "parent_process": "explorer.exe",
            "network_connections": 25,
            "file_writes": 10,
            "registry_changes": 0,
            "child_processes": 4,
            "unique_ips": 10,
            "suspicious_ports": 0
        }
    },
    {
        "type": "Safe (System Service)",
        "data": {
            "process_name": "svchost.exe",
            "pid": 0,
            "parent_process": "services.exe",
            "network_connections": 2,
            "file_writes": 0,
            "registry_changes": 1,
            "child_processes": 0,
            "unique_ips": 1,
            "suspicious_ports": 0
        }
    }
]

def send_event(event):
    print(f"Sending {event['type']}...")
    req = urllib.request.Request(API_URL)
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-API-Key', 'quantum-edr-dev-key')

    jsondata = json.dumps(event['data']).encode('utf-8')

    try:
        response = urllib.request.urlopen(req, jsondata)
        res_body = response.read().decode('utf-8')
        print(f"Response: {res_body}\n")
    except Exception as e:
        print(f"Error sending event: {e}\n")

if __name__ == "__main__":
    import sys
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 10

    print(f"Quantum EDR Mock Event Generator - Sending {count} events\n")

    for i in range(count):
        event = random.choice(MOCK_EVENTS)
        event['data']['pid'] = random.randint(1000, 9999)
        send_event(event)
        if i < count - 1:
            time.sleep(2)
    print("Done!")
