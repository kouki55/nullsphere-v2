#!/usr/bin/env python3
"""
NullSphere — Enhanced Netlink Bridge for Express Integration
===========================================================

改良版 nl_bridge.py：
  1. Express サーバーとの直接 TCP 接続（NullHorizon ではなく）
  2. リトライロジック・自動再接続
  3. エラーハンドリング・ログ記録
  4. ヘルスチェック・統計情報

起動方法 (root 権限が必要):
  sudo python3 nl_bridge_enhanced.py [--express-host 127.0.0.1] [--express-port 9998]
"""

import os
import sys
import json
import time
import struct
import socket
import signal
import logging
import argparse
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from collections import deque

# ─── ロギング設定 ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [nl_bridge] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/nullsphere_nl_bridge.log"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("nl_bridge")

# ─── Netlink 定数 ─────────────────────────────────────────────
NETLINK_USERSOCK = 2
NS_NETLINK_FAMILY = 31    # nullsphere_core.h と合わせる
NS_NETLINK_GROUP  = 1

NLMSG_NOOP    = 1
NLMSG_ERROR   = 2
NLMSG_DONE    = 3
NLMSG_OVERRUN = 4

# ─── ns_event 構造体 レイアウト ───────────────────────────────
NS_EVENT_FMT = (
    "BBBB"    # version, event_type, threat_level, action
    "IIII"    # pid, ppid, uid, gid
    "QQ"      # timestamp_ns, inode
    "16s"     # comm
    "256s"    # filename
    "128s"    # args
    "IHBBI"   # net_daddr, net_dport, net_family, net_proto, container_id
)
NS_EVENT_SIZE = struct.calcsize(NS_EVENT_FMT)

# Netlink メッセージヘッダ
NLMSGHDR_FMT  = "IHHII"   # len, type, flags, seq, pid
NLMSGHDR_SIZE = struct.calcsize(NLMSGHDR_FMT)

# ─── イベントタイプ名マッピング ───────────────────────────────
EVT_NAMES = {
    0x01: "exec",
    0x02: "file",
    0x03: "net",
    0x04: "kill",
    0x05: "module_load",
    0x06: "ptrace",
}

THREAT_NAMES = {0: "NONE", 1: "LOW", 2: "MED", 3: "HIGH", 4: "CRITICAL"}
ACTION_NAMES = {0: "LOG", 1: "KILL", 2: "ISOLATE", 3: "KILL+ISOLATE"}

# ─── リトライ設定 ─────────────────────────────────────────────
MAX_RETRIES = 5
RETRY_DELAY = 3  # seconds
HEALTH_CHECK_INTERVAL = 30  # seconds


def decode_event(data: bytes) -> Optional[dict]:
    """
    カーネルから受信した raw bytes を dict に変換する。
    """
    if len(data) < NS_EVENT_SIZE:
        log.warning(f"受信データが短すぎます: {len(data)} < {NS_EVENT_SIZE}")
        return None

    try:
        fields = struct.unpack_from(NS_EVENT_FMT, data)
    except struct.error as e:
        log.error(f"アンパックエラー: {e}")
        return None

    (version, event_type, threat_level, action,
     pid, ppid, uid, gid,
     timestamp_ns, inode,
     comm_b, filename_b, args_b,
     net_daddr, net_dport, net_family, net_proto,
     container_id) = fields

    def decode_str(b: bytes) -> str:
        return b.split(b'\x00', 1)[0].decode('utf-8', errors='replace')

    # net_daddr をドット記法に変換
    daddr_str = socket.inet_ntoa(struct.pack(">I", net_daddr)) if net_daddr else ""

    return {
        "source":       "lkm",
        "version":      version,
        "type":         EVT_NAMES.get(event_type, f"unknown({event_type})"),
        "event_type":   event_type,
        "threat_level": threat_level,
        "threat_name":  THREAT_NAMES.get(threat_level, "?"),
        "action":       action,
        "action_name":  ACTION_NAMES.get(action, "?"),
        "pid":          pid,
        "ppid":         ppid,
        "uid":          uid,
        "gid":          gid,
        "ts_ns":        timestamp_ns,
        "ts":           datetime.fromtimestamp(timestamp_ns / 1e9, tz=timezone.utc).isoformat(),
        "inode":        inode,
        "comm":         decode_str(comm_b),
        "filename":     decode_str(filename_b),
        "args":         decode_str(args_b),
        "net": {
            "daddr":  daddr_str,
            "dport":  socket.ntohs(net_dport),
            "family": net_family,
            "proto":  net_proto,
        } if net_daddr else None,
        "container_id": container_id,
    }


def build_nlmsg(payload: bytes) -> bytes:
    """
    Netlink メッセージを組み立てる。
    """
    total_len = NLMSGHDR_SIZE + len(payload)
    header = struct.pack(NLMSGHDR_FMT,
                         total_len,    # len
                         NLMSG_DONE,   # type
                         0,            # flags
                         0,            # seq
                         os.getpid())  # pid
    return header + payload


class EnhancedNLBridge:
    def __init__(self, express_host: str, express_port: int):
        self.express_host = express_host
        self.express_port = express_port
        self.nl_sock: Optional[socket.socket] = None
        self.express_sock: Optional[socket.socket] = None
        self.running = True
        self.connected = False
        self.stats = {
            "received": 0,
            "threats": 0,
            "forwarded": 0,
            "errors": 0,
            "reconnects": 0,
        }
        self.event_buffer = deque(maxlen=1000)  # 最新1000イベントをバッファ

    # ── Netlink 接続 ─────────────────────────────────────────
    def connect_netlink(self):
        """
        カーネルモジュールの Netlink ソケットに接続し、
        自身の PID を登録する。
        """
        try:
            self.nl_sock = socket.socket(
                socket.AF_NETLINK,
                socket.SOCK_RAW,
                NS_NETLINK_FAMILY
            )
            self.nl_sock.bind((os.getpid(), NS_NETLINK_GROUP))
            log.info(f"Netlink ソケット接続: family={NS_NETLINK_FAMILY} pid={os.getpid()}")

            # カーネルに PID を登録
            reg_msg = build_nlmsg(b"register")
            self.nl_sock.sendto(reg_msg, (0, 0))  # PID=0 = カーネル
            log.info("カーネルモジュールに PID 登録完了")

            # /proc 経由でも設定
            self._write_proc_config(f"nl_pid={os.getpid()}")

        except PermissionError:
            log.error("Netlink ソケットには root 権限が必要です")
            sys.exit(1)
        except OSError as e:
            log.error(f"Netlink 接続失敗: {e}")
            log.error("カーネルモジュール (nullsphere.ko) がロードされているか確認してください")
            sys.exit(1)

    # ── Express サーバー接続（リトライ付き） ───────────────────
    def connect_express(self):
        """
        Express サーバーに TCP で接続。リトライロジック付き。
        """
        for attempt in range(MAX_RETRIES):
            try:
                self.express_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.express_sock.settimeout(5)
                self.express_sock.connect((self.express_host, self.express_port))
                log.info(f"Express サーバー接続成功: {self.express_host}:{self.express_port}")
                self.connected = True
                return
            except Exception as e:
                log.warning(f"Express 接続試行 {attempt + 1}/{MAX_RETRIES} 失敗: {e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                else:
                    log.error(f"Express サーバーに接続できません。ローカルログのみで続行します。")
                    self.connected = False

    def _reconnect_express(self):
        """
        Express サーバーへの再接続を試みる。
        """
        try:
            if self.express_sock:
                self.express_sock.close()
        except Exception:
            pass
        
        self.stats["reconnects"] += 1
        log.info(f"Express 再接続を試みます... (試行 #{self.stats['reconnects']})")
        time.sleep(RETRY_DELAY)
        self.connect_express()

    # ── /proc 設定書き込み ────────────────────────────────────
    def _write_proc_config(self, cmd: str):
        config_path = Path("/proc/nullsphere/config")
        if config_path.exists():
            try:
                config_path.write_text(cmd)
                log.debug(f"/proc/nullsphere/config <- '{cmd}'")
            except Exception as e:
                log.warning(f"/proc 書き込みエラー: {e}")
        else:
            log.debug("/proc/nullsphere/config が見つかりません (モジュール未ロード)")

    # ── イベント転送 ──────────────────────────────────────────
    def forward_event(self, event: dict):
        """
        イベントを Express サーバーに転送。失敗時は再接続。
        """
        self.event_buffer.append(event)
        
        payload = json.dumps(event, ensure_ascii=False) + "\n"
        
        if self.connected and self.express_sock:
            try:
                self.express_sock.sendall(payload.encode())
                self.stats["forwarded"] += 1
                log.debug(f"イベント転送成功: {event.get('type')} PID={event.get('pid')}")
            except Exception as e:
                log.warning(f"Express への転送失敗: {e}。再接続を試みます...")
                threading.Thread(target=self._reconnect_express, daemon=True).start()
        else:
            # Express が未接続の場合はローカルログに出力
            log.info(f"[EVENT] {event.get('type')} PID={event.get('pid')} "
                     f"COMM={event.get('comm')} LEVEL={event.get('threat_name')}")

    # ── 受信ループ ─────────────────────────────────────────────
    def receive_loop(self):
        log.info("Netlink 受信ループ開始...")
        self.nl_sock.settimeout(1.0)

        while self.running:
            try:
                raw, _ = self.nl_sock.recvfrom(65536)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log.error(f"受信エラー: {e}")
                    self.stats["errors"] += 1
                break

            # Netlink ヘッダを除去してペイロードを取得
            if len(raw) < NLMSGHDR_SIZE:
                continue

            try:
                nlh_fields = struct.unpack_from(NLMSGHDR_FMT, raw)
                msg_len = nlh_fields[0]
                payload  = raw[NLMSGHDR_SIZE:msg_len]
            except struct.error as e:
                log.error(f"Netlinkヘッダパースエラー: {e}")
                self.stats["errors"] += 1
                continue

            if not payload:
                continue

            event = decode_event(payload)
            if not event:
                continue

            self.stats["received"] += 1
            if event["threat_level"] > 0:
                self.stats["threats"] += 1

            log.debug(f"受信: type={event['type']} pid={event['pid']} "
                      f"comm={event['comm']} level={event['threat_name']}")

            self.forward_event(event)

    # ── ヘルスチェックスレッド ─────────────────────────────────
    def health_check_thread(self):
        """
        Express 接続状態を定期的に確認。
        """
        while self.running:
            time.sleep(HEALTH_CHECK_INTERVAL)
            
            if not self.connected or not self.express_sock:
                log.warning("Express 接続が切断されています。再接続を試みます...")
                threading.Thread(target=self._reconnect_express, daemon=True).start()

    # ── 統計ログスレッド ─────────────────────────────────────
    def stats_thread(self):
        while self.running:
            time.sleep(60)
            log.info(f"[統計] 受信={self.stats['received']} "
                     f"脅威={self.stats['threats']} "
                     f"転送={self.stats['forwarded']} "
                     f"エラー={self.stats['errors']} "
                     f"再接続={self.stats['reconnects']} "
                     f"Express接続={self.connected}")

    # ── メイン ────────────────────────────────────────────────
    def run(self):
        if os.geteuid() != 0:
            sys.exit("[ERROR] root 権限が必要です (sudo で実行してください)")

        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        self.connect_netlink()
        self.connect_express()

        threading.Thread(target=self.stats_thread, daemon=True).start()
        threading.Thread(target=self.health_check_thread, daemon=True).start()

        log.info("=" * 60)
        log.info("  NullSphere Enhanced Netlink Bridge 起動完了")
        log.info(f"  Netlink Family : {NS_NETLINK_FAMILY}")
        log.info(f"  Express Server : {self.express_host}:{self.express_port}")
        log.info(f"  Connected      : {self.connected}")
        log.info("=" * 60)

        self.receive_loop()

    def _shutdown(self, signum, frame):
        log.info("シャットダウン中...")
        self.running = False
        if self.nl_sock:
            self.nl_sock.close()
        if self.express_sock:
            self.express_sock.close()
        log.info(f"最終統計: {self.stats}")
        log.info(f"バッファ内イベント数: {len(self.event_buffer)}")
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NullSphere Enhanced Netlink Bridge")
    parser.add_argument("--express-host", default="127.0.0.1",
                        help="Express サーバーホスト (デフォルト: 127.0.0.1)")
    parser.add_argument("--express-port", type=int, default=9998,
                        help="Express サーバーポート (デフォルト: 9998)")
    parser.add_argument("--log-level", default="INFO",
                        help="ログレベル (DEBUG/INFO/WARNING/ERROR)")
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level.upper(), logging.INFO))

    bridge = EnhancedNLBridge(args.express_host, args.express_port)
    bridge.run()
