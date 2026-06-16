import time
import os
import sys
from collections import defaultdict

LOG_FILE = "/tmp/ghostlock_detector.log"
HONEYPOT_FILES = ["/tmp/.hidden_passwords.txt", "/tmp/.financial_data.csv"]
MASS_MODIFICATION_THRESHOLD = 30
TIME_WINDOW = 10

def create_honeypots():
    for hp in HONEYPOT_FILES:
        if not os.path.exists(hp):
            try:
                with open(hp, 'w') as f:
                    f.write("Honeypot file. Do not modify.")
            except Exception:
                pass

def main():
    print("Starting Ransomware Detector...")
    create_honeypots()
    
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    process_write_history = defaultdict(list)
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
                    if len(parts) == 4:
                        timestamp_str, event_type, file_path, pid_str = parts
                        if event_type in ("WRITE", "RENAME"):
                            pid = int(pid_str)
                            now = time.time()
                            
                            # 1. Honeypot check
                            if file_path in HONEYPOT_FILES:
                                print(f"\n\033[91m[RANSOMWARE ALERT] Honeypot modified by PID {pid}!\033[0m")
                                print(f"File: {file_path}")
                            
                            # 2. Mass modification check
                            process_write_history[pid].append(now)
                
                last_position = f.tell()
            
            # Evaluate mass modifications
            current_time = time.time()
            cutoff = current_time - TIME_WINDOW
            pids_to_clear = []
            
            for pid, history in process_write_history.items():
                # Filter old events
                process_write_history[pid] = [t for t in history if t >= cutoff]
                
                if len(process_write_history[pid]) >= MASS_MODIFICATION_THRESHOLD:
                    print(f"\n\033[91m[RANSOMWARE ALERT] Mass file modification detected!\033[0m")
                    print(f"Process ID: {pid}")
                    print(f"Modified {len(process_write_history[pid])} files in {TIME_WINDOW} seconds.")
                    pids_to_clear.append(pid)
            
            for pid in pids_to_clear:
                del process_write_history[pid]
                
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
