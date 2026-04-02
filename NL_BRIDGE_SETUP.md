# NullSphere Netlink Bridge セットアップガイド

## 概要

`nl_bridge_enhanced.py` は、Linux カーネルモジュール（nullsphere.ko）から Netlink 経由でセキュリティイベントを受信し、Express サーバーに TCP で転送するブリッジです。

## ファイル構成

| ファイル | 説明 |
|---------|------|
| `nl_bridge_enhanced.py` | 改良版 Netlink ブリッジ（本番用） |
| `test-nl-bridge.py` | テスト用シミュレーター |
| `NL_BRIDGE_SETUP.md` | このドキュメント |

## 前提条件

- **OS**: Linux（Ubuntu 20.04 以上推奨）
- **権限**: root 権限（Netlink ソケット使用のため）
- **Python**: 3.8 以上
- **カーネルモジュール**: nullsphere.ko がロード済みであること

## インストール

### 1. ファイルの配置

```bash
# nl_bridge_enhanced.py をシステムディレクトリに配置
sudo cp nl_bridge_enhanced.py /opt/nullsphere/nl_bridge.py
sudo chmod +x /opt/nullsphere/nl_bridge.py

# ログディレクトリの作成
sudo mkdir -p /var/log/nullsphere
sudo chmod 755 /var/log/nullsphere
```

### 2. systemd サービスの作成（オプション）

```bash
sudo tee /etc/systemd/system/nullsphere-nl-bridge.service > /dev/null <<EOF
[Unit]
Description=NullSphere Netlink Bridge
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/nullsphere/nl_bridge.py --express-host 127.0.0.1 --express-port 9998
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable nullsphere-nl-bridge
```

## 使用方法

### テスト環境での実行

#### ターミナル 1: テストサーバーの起動

```bash
python3 test-nl-bridge.py --port 9998
```

出力例：
```
2026-04-03 10:15:30,123 [test-bridge] テストサーバー起動: 127.0.0.1:9998
2026-04-03 10:15:30,124 [test-bridge] nl_bridge からの接続を待機中...
```

#### ターミナル 2: nl_bridge の起動

```bash
sudo python3 nl_bridge_enhanced.py --express-host 127.0.0.1 --express-port 9998 --log-level DEBUG
```

出力例：
```
2026-04-03 10:15:35,456 [nl_bridge] Netlink ソケット接続: family=31 pid=12345
2026-04-03 10:15:35,457 [nl_bridge] カーネルモジュールに PID 登録完了
2026-04-03 10:15:35,500 [nl_bridge] Express サーバー接続成功: 127.0.0.1:9998
2026-04-03 10:15:35,501 [nl_bridge] ============================================================
2026-04-03 10:15:35,502 [nl_bridge]   NullSphere Enhanced Netlink Bridge 起動完了
2026-04-03 10:15:35,503 [nl_bridge]   Netlink Family : 31
2026-04-03 10:15:35,504 [nl_bridge]   Express Server : 127.0.0.1:9998
2026-04-03 10:15:35,505 [nl_bridge]   Connected      : True
2026-04-03 10:15:35,506 [nl_bridge] ============================================================
```

#### ターミナル 3: イベント生成（テスト用）

```bash
# 実行イベントを生成
/bin/ls /tmp

# ファイルアクセスイベントを生成
cat /etc/passwd

# ネットワークイベントを生成
curl https://example.com
```

### 本番環境での実行

```bash
# systemd サービスとして起動
sudo systemctl start nullsphere-nl-bridge

# ステータス確認
sudo systemctl status nullsphere-nl-bridge

# ログ確認
sudo journalctl -u nullsphere-nl-bridge -f

# または
tail -f /var/log/nullsphere_nl_bridge.log
```

## コマンドラインオプション

```bash
python3 nl_bridge_enhanced.py [OPTIONS]

OPTIONS:
  --express-host HOST    Express サーバーホスト (デフォルト: 127.0.0.1)
  --express-port PORT    Express サーバーポート (デフォルト: 9998)
  --log-level LEVEL      ログレベル: DEBUG/INFO/WARNING/ERROR (デフォルト: INFO)
```

## イベント形式

nl_bridge から Express サーバーに送信されるイベントは JSON 形式です：

```json
{
  "source": "lkm",
  "version": 1,
  "type": "exec",
  "event_type": 1,
  "threat_level": 2,
  "threat_name": "MED",
  "action": 0,
  "action_name": "LOG",
  "pid": 12345,
  "ppid": 1,
  "uid": 1000,
  "gid": 1000,
  "ts_ns": 1712138135000000000,
  "ts": "2026-04-03T10:15:35+00:00",
  "inode": 987654,
  "comm": "bash",
  "filename": "/bin/ls",
  "args": "/tmp",
  "net": {
    "daddr": "192.168.1.100",
    "dport": 443,
    "family": 2,
    "proto": 6
  },
  "container_id": 0
}
```

### イベントタイプ

| type | 説明 |
|------|------|
| exec | プロセス実行 |
| file | ファイルアクセス |
| net | ネットワーク通信 |
| kill | プロセス終了 |
| module_load | カーネルモジュールロード |
| ptrace | プロセストレース |

### 脅威レベル

| level | 名前 | 説明 |
|-------|------|------|
| 0 | NONE | 脅威なし |
| 1 | LOW | 低リスク |
| 2 | MED | 中リスク |
| 3 | HIGH | 高リスク |
| 4 | CRITICAL | 重大リスク |

### アクション

| action | 名前 | 説明 |
|--------|------|------|
| 0 | LOG | ログ記録のみ |
| 1 | KILL | プロセス終了 |
| 2 | ISOLATE | プロセス隔離 |
| 3 | KILL+ISOLATE | 終了 + 隔離 |

## トラブルシューティング

### 問題: "Netlink ソケットには root 権限が必要です"

**原因**: root 権限なしで実行している

**解決方法**:
```bash
sudo python3 nl_bridge_enhanced.py
```

### 問題: "Netlink 接続失敗"

**原因**: カーネルモジュール（nullsphere.ko）がロードされていない

**解決方法**:
```bash
# モジュールの確認
lsmod | grep nullsphere

# モジュールのロード
sudo insmod nullsphere.ko
```

### 問題: "Express 接続試行が失敗する"

**原因**: Express サーバーが起動していない、またはポートが異なる

**解決方法**:
```bash
# Express サーバーが起動しているか確認
netstat -tlnp | grep 9998

# ポート番号を確認して指定
sudo python3 nl_bridge_enhanced.py --express-port 9998
```

### 問題: イベントが受信されない

**原因**: カーネルモジュールがイベントを生成していない

**解決方法**:
```bash
# /proc/nullsphere/config でモジュールの状態を確認
cat /proc/nullsphere/config

# イベント生成テスト
/bin/ls /tmp
cat /etc/passwd
curl https://example.com
```

## パフォーマンス最適化

### イベントバッファサイズ

デフォルトでは最新 1000 イベントをメモリに保持します。
高スループット環境では、ソースコードの `maxlen=1000` を調整してください。

### ログレベル

本番環境では `--log-level INFO` を使用してください。
DEBUG ログはパフォーマンスに影響します。

## セキュリティ考慮事項

1. **ファイアウォール**: Express サーバーへの接続は localhost のみに制限してください
2. **ログファイル**: `/var/log/nullsphere_nl_bridge.log` は機密情報を含むため、アクセス制限を設定してください
3. **権限**: nl_bridge は root 権限で実行する必要があります。最小権限の原則に従ってください

## ログ出力

ログは以下の場所に出力されます：

- **stdout**: コンソール出力（フォアグラウンド実行時）
- **ファイル**: `/var/log/nullsphere_nl_bridge.log`
- **systemd**: `journalctl -u nullsphere-nl-bridge`

## サポート

問題が発生した場合は、以下の情報を収集してください：

1. ログファイル全体
2. `uname -a` の出力
3. `lsmod | grep nullsphere` の出力
4. nl_bridge 起動時のコマンドラインオプション
