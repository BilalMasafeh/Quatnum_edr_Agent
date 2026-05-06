import time
import requests
import psutil
import socket

API_URL = "http://127.0.0.1:8000/api/event"
API_KEY = "quantum-edr-dev-key"
SUSPICIOUS_PORTS = {4444, 1337, 9999, 6666, 31337, 443}

def get_process_telemetry():
    """Gather real telemetry from the machine using psutil"""
    events = []
    
    processes = list(psutil.process_iter(['pid', 'name', 'io_counters', 'net_connections']))
    import random
    random.shuffle(processes)
    
    for proc in processes:
        try:
            conns = proc.info.get('net_connections', [])
            if not conns:
                continue
                
            unique_ips = set()
            suspicious_ports_count = 0
            
            for c in conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    unique_ips.add(c.raddr.ip)
                    if c.raddr.port in SUSPICIOUS_PORTS:
                        suspicious_ports_count += 1
            
            io = proc.info.get('io_counters')
            file_writes = io.write_count if io else 0
            
            try:
                parent = proc.parent()
                parent_name = parent.name() if parent else "unknown"
            except:
                parent_name = "unknown"
                
            try:
                children_count = len(proc.children())
            except:
                children_count = 0

            event_data = {
                "process_name": proc.info['name'],
                "pid": proc.info['pid'],
                "parent_process": parent_name,
                "network_connections": len(conns),
                "file_writes": file_writes % 500,
                "registry_changes": 0,
                "child_processes": children_count,
                "unique_ips": len(unique_ips),
                "suspicious_ports": suspicious_ports_count
            }
            events.append(event_data)
            
            if len(events) >= 5:
                break
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    return events

def run_agent():
    print("Starting Lightweight EDR Agent...")
    print("The agent is now monitoring real processes on your machine and sending them to the server...\n")
    
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }
    
    while True:
        try:
            events = get_process_telemetry()
            for ev in events:
                print(f"Sending telemetry for process: {ev['process_name']} (PID: {ev['pid']})")
                try:
                    res = requests.post(API_URL, json=ev, headers=headers, timeout=2)
                    if res.status_code != 200:
                        print(f"Server returned error code: {res.status_code}")
                except requests.exceptions.RequestException as e:
                    print(f"Failed to connect to server: {e}")
            
            print("-" * 40)
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\nAgent stopped.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    run_agent()
