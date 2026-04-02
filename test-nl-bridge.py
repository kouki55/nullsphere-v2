#!/usr/bin/env python3
"""
NullSphere Netlink Bridge Test Simulator
=========================================

nl_bridge_enhanced.py との接続テスト用シミュレーター。
Express サーバーの代わりに、nl_bridge からのイベント受信をテストする。

使用方法:
  python3 test-nl-bridge.py [--port 9998]
"""

import socket
import json
import logging
import argparse
import threading
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [test-bridge] %(message)s",
)
log = logging.getLogger("test_bridge")


class TestBridgeServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server_sock = None
        self.running = True
        self.event_count = 0
        self.threat_count = 0

    def start(self):
        """
        テストサーバーを起動し、nl_bridge からのイベント受信を待つ。
        """
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(1)
            log.info(f"テストサーバー起動: {self.host}:{self.port}")
            log.info("nl_bridge からの接続を待機中...")

            while self.running:
                try:
                    client_sock, client_addr = self.server_sock.accept()
                    log.info(f"接続受け入れ: {client_addr}")
                    threading.Thread(
                        target=self.handle_client,
                        args=(client_sock, client_addr),
                        daemon=True
                    ).start()
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    log.error(f"接続受け入れエラー: {e}")

        except Exception as e:
            log.error(f"サーバー起動エラー: {e}")
        finally:
            if self.server_sock:
                self.server_sock.close()
            log.info(f"テストサーバー停止。受信イベント: {self.event_count}, 脅威: {self.threat_count}")

    def handle_client(self, client_sock: socket.socket, client_addr: tuple):
        """
        クライアント（nl_bridge）からのイベントを受信・処理する。
        """
        buffer = ""
        try:
            while self.running:
                data = client_sock.recv(4096).decode('utf-8', errors='replace')
                if not data:
                    break

                buffer += data
                lines = buffer.split('\n')
                buffer = lines[-1]  # 最後の不完全な行をバッファに保持

                for line in lines[:-1]:
                    if not line.strip():
                        continue

                    try:
                        event = json.loads(line)
                        self.process_event(event)
                    except json.JSONDecodeError as e:
                        log.warning(f"JSON パースエラー: {e}")

        except Exception as e:
            log.error(f"クライアント処理エラー: {e}")
        finally:
            client_sock.close()
            log.info(f"クライアント切断: {client_addr}")

    def process_event(self, event: dict):
        """
        受信したイベントを処理・ログ出力する。
        """
        self.event_count += 1

        event_type = event.get("type", "unknown")
        pid = event.get("pid", 0)
        comm = event.get("comm", "?")
        threat_level = event.get("threat_level", 0)
        threat_name = event.get("threat_name", "?")
        action_name = event.get("action_name", "?")
        ts = event.get("ts", "?")

        # 脅威レベルが HIGH 以上の場合はカウント
        if threat_level >= 3:
            self.threat_count += 1
            log.warning(
                f"[THREAT] #{self.event_count} | Type={event_type} | "
                f"PID={pid} | COMM={comm} | Level={threat_name} | "
                f"Action={action_name} | TS={ts}"
            )
        else:
            log.info(
                f"[EVENT] #{self.event_count} | Type={event_type} | "
                f"PID={pid} | COMM={comm} | Level={threat_name} | TS={ts}"
            )

        # ネットワークイベントの詳細表示
        if event_type == "net" and event.get("net"):
            net_info = event["net"]
            log.info(
                f"  └─ Network: {net_info.get('daddr')}:{net_info.get('dport')} "
                f"(family={net_info.get('family')}, proto={net_info.get('proto')})"
            )

        # ファイルアクセスイベントの詳細表示
        if event_type == "file":
            filename = event.get("filename", "?")
            log.info(f"  └─ File: {filename}")

        # 実行イベントの詳細表示
        if event_type == "exec":
            filename = event.get("filename", "?")
            args = event.get("args", "?")
            log.info(f"  └─ Exec: {filename} {args}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NullSphere Netlink Bridge Test Simulator")
    parser.add_argument("--host", default="127.0.0.1", help="バインドホスト")
    parser.add_argument("--port", type=int, default=9998, help="バインドポート")
    args = parser.parse_args()

    server = TestBridgeServer(args.host, args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        log.info("シャットダウン中...")
        server.running = False
