import time
import os
import sys

LOG_FILE = "/tmp/ghostlock_detector.log"

# Linux環境でのOffice代替アプリケーション
OFFICE_PROCESSES = ["soffice.bin", "wps", "et", "wpp"]

# 不審な子プロセス
SUSPICIOUS_CHILD_PROCESSES = ["sh", "bash", "zsh", "python", "python3", "perl", "curl", "wget"]

def main():
    print("Starting Macro Virus Detector (Office Child Process Monitoring)...")
    
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
                    # プロセス起動イベントのフォーマット: TIMESTAMP | EXECVE | COMMAND_LINE | PID | PARENT_PID | PARENT_NAME
                    if len(parts) == 6 and parts[1] == "EXECVE":
                        timestamp_str, event_type, cmd_line, pid_str, ppid_str, parent_name = parts
                        
                        # コマンドラインから実行ファイル名を抽出
                        child_proc = cmd_line.split()[0].split('/')[-1]
                        
                        if parent_name in OFFICE_PROCESSES and child_proc in SUSPICIOUS_CHILD_PROCESSES:
                            print(f"\n\033[91m[MACRO ALERT] Malicious Macro Activity Detected!\033[0m")
                            print(f"Parent Process: {parent_name} (PID: {ppid_str})")
                            print(f"Spawned Suspicious Child: {child_proc} (PID: {pid_str})")
                            print(f"Command: {cmd_line}")
                
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
