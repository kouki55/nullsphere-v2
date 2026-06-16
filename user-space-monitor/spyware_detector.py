import time
import os
import sys

LOG_FILE = "/tmp/ghostlock_detector.log"

# 監視対象のブラウザデータパス (Linux)
BROWSER_DATA_PATHS = [
    "/.config/google-chrome/Default/Login Data",
    "/.config/google-chrome/Default/Cookies",
    "/.mozilla/firefox/",
    "/.config/chromium/Default/Login Data"
]

ALLOWED_PROCESSES = ["chrome", "firefox", "chromium"]

def is_browser_data_path(path):
    for p in BROWSER_DATA_PATHS:
        if p in path:
            return True
    return False

def get_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"

def main():
    print("Starting Spyware/InfoStealer Detector...")
    
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
                        
                        # 1. ブラウザデータへの不正アクセス監視 (READ/OPEN)
                        if event_type in ("READ", "OPEN", "OPEN_EXCL") and is_browser_data_path(file_path):
                            pid = int(pid_str)
                            proc_name = get_process_name(pid)
                            
                            if proc_name not in ALLOWED_PROCESSES:
                                print(f"\n\033[91m[SPYWARE ALERT] InfoStealer Activity Detected!\033[0m")
                                print(f"Process: {proc_name} (PID: {pid})")
                                print(f"Unauthorized access to browser data: {file_path}")
                        
                        # 2. キーロガー検知 (/dev/input/event* へのアクセス)
                        if event_type in ("OPEN", "READ") and file_path.startswith("/dev/input/event"):
                            pid = int(pid_str)
                            proc_name = get_process_name(pid)
                            
                            # XorgやWayland等のシステムプロセス以外をブロック
                            if proc_name not in ["Xorg", "wayland", "systemd-logind", "acpid"]:
                                print(f"\n\033[91m[SPYWARE ALERT] Keylogger Activity Detected!\033[0m")
                                print(f"Process: {proc_name} (PID: {pid})")
                                print(f"Unauthorized access to input device: {file_path}")
                
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
