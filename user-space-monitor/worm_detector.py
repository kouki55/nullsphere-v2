import time
import os
import sys
from collections import defaultdict

# 実際の環境ではeBPFやauditdからネットワークイベントを取得する必要がありますが、
# ここではログファイルから取得するシミュレーションとします。
LOG_FILE = "/tmp/ghostlock_detector.log"

SCAN_THRESHOLD = 20
TIME_WINDOW = 10
TARGET_PORTS = ["445", "3389", "22", "1433", "135", "139"]

def main():
    print("Starting Worm Detector (Lateral Movement Monitoring)...")
    
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    # process_connections[pid] = [(timestamp, dest_ip), ...]
    process_connections = defaultdict(list)
    last_position = 0

    while True:
        try:
            with open(LOG_FILE, "r") as f:
                f.seek(last_position)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    
                    parts = line.strip().split(" | ")
                    # ネットワークイベントのフォーマット: TIMESTAMP | CONNECT | DEST_IP:PORT | PID
                    if len(parts) == 4 and parts[1] == "CONNECT":
                        timestamp_str, event_type, dest_info, pid_str = parts
                        pid = int(pid_str)
                        now = time.time()
                        
                        if ":" in dest_info:
                            dest_ip, dest_port = dest_info.split(":")
                            if dest_port in TARGET_PORTS:
                                process_connections[pid].append((now, dest_ip))
                
                last_position = f.tell()
            
            # Evaluate port scans
            current_time = time.time()
            cutoff = current_time - TIME_WINDOW
            pids_to_clear = []
            
            for pid, history in process_connections.items():
                # Filter old events
                process_connections[pid] = [(t, ip) for t, ip in history if t >= cutoff]
                
                # Count unique IPs
                unique_ips = set(ip for t, ip in process_connections[pid])
                
                if len(unique_ips) >= SCAN_THRESHOLD:
                    print(f"\n\033[91m[WORM ALERT] Lateral Movement / Port Scan Detected!\033[0m")
                    print(f"Process ID: {pid}")
                    print(f"Attempted to connect to {len(unique_ips)} unique IPs on target ports in {TIME_WINDOW} seconds.")
                    pids_to_clear.append(pid)
            
            for pid in pids_to_clear:
                del process_connections[pid]
                
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error: {e}")
            
        time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
