import time
import os
import sys
from collections import defaultdict

LOG_FILE = "/tmp/ghostlock_detector.log"

# 既知のC2サーバーIP (モック)
KNOWN_C2_IPS = ["198.51.100.50", "203.0.113.100"]

# DDoS検知のしきい値
PACKET_RATE_THRESHOLD = 1000
TIME_WINDOW = 1

def main():
    print("Starting Bot/DDoS Detector...")
    
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    process_packet_history = defaultdict(list)
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
                    # ネットワークイベントのフォーマット: TIMESTAMP | CONNECT/SEND | DEST_IP:PORT | PID
                    if len(parts) == 4:
                        timestamp_str, event_type, dest_info, pid_str = parts
                        pid = int(pid_str)
                        now = time.time()
                        
                        dest_ip = dest_info.split(":")[0] if ":" in dest_info else dest_info
                        
                        # 1. C2通信検知
                        if event_type == "CONNECT" and dest_ip in KNOWN_C2_IPS:
                            print(f"\n\033[91m[BOT ALERT] C2 Communication Detected!\033[0m")
                            print(f"Process ID: {pid}")
                            print(f"Connected to known C2 server: {dest_ip}")
                        
                        # 2. DDoS挙動検知 (SEND)
                        if event_type == "SEND":
                            process_packet_history[pid].append(now)
                
                last_position = f.tell()
            
            # Evaluate DDoS (Packet Flood)
            current_time = time.time()
            cutoff = current_time - TIME_WINDOW
            pids_to_clear = []
            
            for pid, history in process_packet_history.items():
                # Filter old events
                process_packet_history[pid] = [t for t in history if t >= cutoff]
                
                if len(process_packet_history[pid]) >= PACKET_RATE_THRESHOLD:
                    print(f"\n\033[91m[BOT ALERT] DDoS Activity (Flood) Detected!\033[0m")
                    print(f"Process ID: {pid}")
                    print(f"Sent {len(process_packet_history[pid])} packets in {TIME_WINDOW} second.")
                    pids_to_clear.append(pid)
            
            for pid in pids_to_clear:
                del process_packet_history[pid]
                
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
