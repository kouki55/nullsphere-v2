import time
import os
import sys
import re

# 実際の環境ではeBPFやauditdからexecveイベントを取得する必要がありますが、
# ここではログファイルから取得するシミュレーションとします。
LOG_FILE = "/tmp/ghostlock_detector.log"

# 不審なコマンドライン引数のパターン
SUSPICIOUS_PATTERNS = [
    re.compile(r"base64\s+-d\s+\|\s*(sh|bash|zsh)", re.IGNORECASE),
    re.compile(r"curl\s+.*\|\s*(sh|bash|zsh)", re.IGNORECASE),
    re.compile(r"wget\s+.*-O\s+-\s+\|\s*(sh|bash|zsh)", re.IGNORECASE),
    re.compile(r"python\s+-c\s+['\"]import\s+(urllib|socket|base64)", re.IGNORECASE),
    re.compile(r"perl\s+-e\s+['\"]use\s+Socket", re.IGNORECASE),
    re.compile(r"echo\s+[A-Za-z0-9+/=]{20,}\s+\|\s*base64\s+-d", re.IGNORECASE)
]

def main():
    print("Starting Fileless Malware Detector (Command Line Monitoring)...")
    
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
                    # プロセス起動イベントのフォーマット: TIMESTAMP | EXECVE | COMMAND_LINE | PID
                    if len(parts) == 4 and parts[1] == "EXECVE":
                        timestamp_str, event_type, cmd_line, pid_str = parts
                        pid = int(pid_str)
                        
                        for pattern in SUSPICIOUS_PATTERNS:
                            if pattern.search(cmd_line):
                                print(f"\n\033[91m[FILELESS ALERT] Suspicious Command Line Detected!\033[0m")
                                print(f"Process ID: {pid}")
                                print(f"Command: {cmd_line}")
                                print(f"Matched Pattern: {pattern.pattern}")
                                break
                
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
