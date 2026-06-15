import time
import os
import sys
import re
from collections import defaultdict

LOG_FILE = "/tmp/ghostlock_detector.log"
ANOMALY_THRESHOLD = 20  # 10秒間に20ファイル以上の排他ロック
TIME_WINDOW = 10        # 秒
IO_TIMEOUT = 5          # I/Oなしでロックを保持する許容時間（秒）

class LockInfo:
    def __init__(self, acquired_time, file_path):
        self.acquired_time = acquired_time
        self.has_io_activity = False
        self.file_path = file_path

def parse_log_line(line):
    # Format: YYYY-MM-DD HH:MM:SS | EVENT_TYPE | FILE_PATH | PID
    match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| ([A-Z_]+) \| (.+) \| (\d+)", line)
    if match:
        timestamp_str, event_type, file_path, pid_str = match.groups()
        timestamp = time.mktime(time.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S"))
        pid = int(pid_str)
        return timestamp, event_type, file_path, pid
    return None, None, None, None

def main():
    print(f"Starting advanced anomaly detector. Monitoring {LOG_FILE}...")
    
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    # State management
    # process_lock_states[pid][file_path] = LockInfo
    process_lock_states = defaultdict(dict)
    last_position = 0

    while True:
        try:
            with open(LOG_FILE, "r") as f:
                f.seek(last_position)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    
                    timestamp, event_type, file_path, pid = parse_log_line(line.strip())
                    if not timestamp:
                        continue

                    file_states = process_lock_states[pid]

                    if event_type in ("O_EXCL_OPEN", "O_EXCL_OPENAT", "LOCK_EX_FLOCK", "F_WRLCK_FCNTL"):
                        file_states[file_path] = LockInfo(timestamp, file_path)
                    
                    elif event_type in ("READ", "WRITE"):
                        if file_path in file_states:
                            file_states[file_path].has_io_activity = True
                    
                    elif event_type == "CLOSE":
                        if file_path in file_states:
                            del file_states[file_path]
                
                last_position = f.tell()
            
            evaluate_anomalies(process_lock_states)
            
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error: {e}")
            
        time.sleep(1)

def evaluate_anomalies(process_lock_states):
    now = time.time()
    pids_to_clear = []

    for pid, active_locks in process_lock_states.items():
        # Indicator 1 & 2: Prolonged exclusive locks without I/O
        suspicious_locks = [
            lock_info for lock_info in active_locks.values()
            if not lock_info.has_io_activity and (now - lock_info.acquired_time) > IO_TIMEOUT
        ]

        if len(suspicious_locks) >= ANOMALY_THRESHOLD:
            # Indicator 3: Directory traversal pattern
            dir_counts = defaultdict(int)
            for lock_info in suspicious_locks:
                dir_name = os.path.dirname(lock_info.file_path)
                dir_counts[dir_name] += 1
            
            target_dir = None
            is_traversal = False
            if dir_counts:
                target_dir = max(dir_counts, key=dir_counts.get)
                if dir_counts[target_dir] >= (ANOMALY_THRESHOLD / 2):
                    is_traversal = True

            print("\n\033[91m[ALERT] GhostLock Anomaly Detected!\033[0m")
            print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}")
            print(f"Process ID: {pid}")
            print(f"Suspicious Locks: {len(suspicious_locks)} (No I/O activity detected)")
            
            if is_traversal:
                print(f"\033[93m[WARNING] Directory Traversal Pattern Detected in: {target_dir}\033[0m")
            
            print("Involved Files (Sample):")
            for lock_info in suspicious_locks[:5]:
                print(f"  - {lock_info.file_path}")
            if len(suspicious_locks) > 5:
                print(f"  ... and {len(suspicious_locks) - 5} more.")

            # Mark for clearing to prevent continuous alerts
            pids_to_clear.append(pid)

    for pid in pids_to_clear:
        del process_lock_states[pid]

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopping anomaly detector.")
        sys.exit(0)
