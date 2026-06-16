import time
import os
import sys

LOG_FILE = "/tmp/ghostlock_detector.log"

# 監視対象の永続化ディレクトリ/ファイル
PERSISTENCE_PATHS = [
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.monthly/",
    "/etc/cron.weekly/",
    "/etc/systemd/system/",
    "/usr/lib/systemd/system/",
    "/.bashrc",
    "/.bash_profile"
]

def is_persistence_path(path):
    for p in PERSISTENCE_PATHS:
        if path.startswith(p) or path.endswith(p.strip('/')):
            return True
    return False

def main():
    print("Starting Trojan Detector...")
    
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

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
                        
                        # 1. 永続化の監視 (WRITE to persistence paths)
                        if event_type == "WRITE" and is_persistence_path(file_path):
                            print(f"\n\033[91m[TROJAN ALERT] Suspicious Persistence Detected!\033[0m")
                            print(f"Process ID: {pid_str}")
                            print(f"Modified autorun/service file: {file_path}")
                        
                        # 2. プロセスインジェクションの監視 (ptrace)
                        # 注: 実際のptraceフックはLD_PRELOADかeBPFで追加実装が必要。
                        # ここではログに "PTRACE_ATTACH" が出力されたと仮定。
                        elif event_type == "PTRACE_ATTACH":
                            print(f"\n\033[91m[TROJAN ALERT] Process Injection (ptrace) Detected!\033[0m")
                            print(f"Process ID: {pid_str}")
                            print(f"Target PID: {file_path}")
                
                last_position = f.tell()
                
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
