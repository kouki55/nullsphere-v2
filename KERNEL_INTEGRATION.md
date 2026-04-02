# NullSphere V2 - Kernel Module Integration Guide

## Overview

NullSphere V2 Webダッシュボードとカーネルモジュール（nullsphere.ko）を統合し、リアルタイムで脅威イベントを受信・表示・制御できるシステムです。

## Architecture

```
┌─────────────────────────────────────────────┐
│  Linux Kernel                               │
│  nullsphere.ko (kprobe hooks)               │
│  ↓ Netlink                                  │
└─────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────┐
│  User Space                                 │
│  nl_bridge.py (Netlink → TCP)               │
│  ↓ TCP:9998                                 │
└─────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────┐
│  Express Server (Node.js)                   │
│  - KernelBridge (TCP listener)              │
│  - Socket.io (WebSocket)                    │
│  - tRPC kernel control API                  │
└─────────────────────────────────────────────┘
        ↓ WebSocket
┌─────────────────────────────────────────────┐
│  Web Dashboard (React)                      │
│  - Events.tsx (リアルタイムイベント表示)    │
│  - VmManagement.tsx (カーネル操作)          │
└─────────────────────────────────────────────┘
```

## Components

### 1. Backend: Kernel Bridge (`server/kernel-bridge.ts`)

カーネルモジュールからのイベントをTCP:9998で受信し、以下の処理を実行：

- **イベント受信**: NetlinkブリッジからのJSON行を解析
- **DB保存**: `events`テーブルに記録
- **WebSocket配信**: Socket.ioで全クライアントに配信
- **攻撃者追跡**: 攻撃元IP・位置情報を`attackers`テーブルに記録

```typescript
// 使用例
const bridge = new KernelBridge(io);
await bridge.start(9998); // TCP:9998でリッスン開始
```

### 2. Backend: Kernel Integration (`server/_core/kernel-integration.ts`)

Express サーバーに Socket.io と KernelBridge を統合：

```typescript
setupKernelIntegration(httpServer);
// Socket.io サーバー起動
// KernelBridge TCP リスナー起動
```

### 3. Backend: Kernel Control (`server/kernel-control.ts`)

ダッシュボードからカーネルモジュールを操作するtRPCプロシージャ：

| API | 説明 |
|---|---|
| `kernel.isolateProcess` | プロセスを隔離 |
| `kernel.whitelistProcess` | プロセスをホワイトリスト追加 |
| `kernel.blockNetwork` | ネットワークをブロック |
| `kernel.enableTracing` | トレーシングを有効化 |
| `kernel.disableTracing` | トレーシングを無効化 |
| `kernel.getStatus` | カーネル状態を取得 |

実装詳細：
- `/proc/nullsphere/config` に JSON形式でコマンドを書き込み
- 実運用では root権限が必要
- ファイル未存在時はデモモード（ログのみ）

### 4. Frontend: useKernelEvents Hook (`client/src/hooks/useKernelEvents.ts`)

Socket.io経由でカーネルイベントをリアルタイム受信：

```typescript
const { events, isConnected, sendCommand } = useKernelEvents();

// イベント受信時に自動的に state 更新
// isConnected: Socket.io 接続状態
// sendCommand: カーネルコマンド送信
```

### 5. Frontend: Events Page (`client/src/pages/Events.tsx`)

リアルタイムイベント表示：

- **カーネルイベント**: Socket.io受信（cyan色、アニメーション表示）
- **DBイベント**: tRPC query（通常表示）
- **フィルタリング**: イベントタイプ別フィルタ
- **接続状態**: Kernel接続インジケーター

### 6. Frontend: VM Management (`client/src/pages/VmManagement.tsx`)

隔離VM管理とカーネル操作：

- **VM一覧**: リソース使用状況表示
- **隔離**: プロセスを隔離VM内に移動
- **ネットワークブロック**: 指定時間ネットワークを遮断
- **トレーシング**: eBPFトレーシングを有効化

## Setup & Installation

### Prerequisites

```bash
# Linux kernel 5.8+
# eBPF support enabled
# root権限
```

### 1. Kernel Module Build & Load

```bash
cd /path/to/nullsphere-kernel
make
sudo insmod nullsphere.ko
```

### 2. nl_bridge.py Setup

```bash
# Netlink → TCP bridge を起動（バックグラウンド）
python3 nl_bridge.py &

# TCP:9998でリッスン開始
# Netlinkイベント → JSON行 → Express サーバーに送信
```

### 3. Web Server Start

```bash
cd /home/ubuntu/nullsphere-v2
pnpm install
pnpm dev

# Server: http://localhost:3000
# Socket.io: ws://localhost:3000/socket.io
```

### 4. Access Dashboard

ブラウザで `http://localhost:3000` にアクセス

## Event Flow

### 1. Threat Detection

```
Kernel (kprobe) 
  → Netlink message 
  → nl_bridge.py 
  → TCP:9998 
  → KernelBridge.handleEvent()
```

### 2. Event Processing

```
KernelBridge.handleEvent()
  → Parse JSON
  → Save to DB (events table)
  → Extract attacker info
  → Save to DB (attackers table)
  → Emit Socket.io event
```

### 3. Frontend Display

```
Socket.io event (kernel:event)
  → useKernelEvents hook
  → React state update
  → Events.tsx re-render
```

### 4. Kernel Control

```
Dashboard (VmManagement.tsx)
  → trpc.kernel.isolateProcess()
  → kernel-control.ts
  → Write to /proc/nullsphere/config
  → Kernel module reads & executes
```

## Demo Mode

実運用環境がない場合、以下のデモモードで動作確認可能：

### 1. Seed Data

```bash
cd /home/ubuntu/nullsphere-v2
npx tsx seed-db.mjs
```

デモ攻撃者・脅威・イベントをDB に投入

### 2. Mock Kernel Events

`useKernelEvents` フックは Socket.io 接続状態を表示：

- **KERNEL接続**: nl_bridge.py が実行中
- **OFFLINE**: nl_bridge.py が未実行（デモモード）

### 3. Kernel API Demo

`/proc/nullsphere/config` が未存在時：

```
kernel.isolateProcess()
  → File not found
  → Demo mode: return true
  → Log: "[KernelControl] Demo action: {...}"
```

## Testing

### 1. Unit Tests

```bash
pnpm test
```

### 2. Integration Test

```bash
# Terminal 1: Web server
pnpm dev

# Terminal 2: nl_bridge.py
python3 nl_bridge.py

# Terminal 3: Test client
curl http://localhost:3000/api/trpc/events.list
```

### 3. Manual Test

1. Dashboard → Events ページ
2. Kernel接続状態を確認
3. VM Management → 「操作」ボタン
4. 「隔離」「ブロック」「トレース」を実行
5. コンソールログで `/proc/nullsphere/config` 書き込みを確認

## Troubleshooting

### Socket.io Connection Failed

```
原因: nl_bridge.py が起動していない
解決: python3 nl_bridge.py を実行
```

### /proc/nullsphere/config Permission Denied

```
原因: root権限がない
解決: sudo で実行、または root 権限で Expressサーバー起動
```

### Kernel Module Not Loaded

```
原因: nullsphere.ko がロードされていない
解決: sudo insmod nullsphere.ko を実行
```

## Production Deployment

### 1. Security Considerations

- `/proc/nullsphere/config` へのアクセス制御（root のみ）
- Socket.io 認証（JWT等）
- tRPC API 認証（protectedProcedure 推奨）
- ファイアウォール設定（TCP:9998 制限）

### 2. Performance Tuning

- イベントバッファサイズ調整
- DB インデックス最適化
- Socket.io メモリ管理

### 3. Monitoring

- カーネルモジュール状態監視
- nl_bridge.py プロセス監視
- Express サーバーヘルスチェック

## References

- [nullsphere.c](../upload/nullsphere(1).c) - Kernel module
- [nl_bridge.py](../upload/nl_bridge(1).py) - Netlink bridge
- [kernel-bridge.ts](./server/kernel-bridge.ts) - Backend integration
- [useKernelEvents.ts](./client/src/hooks/useKernelEvents.ts) - Frontend hook

## Next Steps

1. **実運用接続**: nl_bridge.py との連携確認
2. **権限管理**: ロールベースアクセス制御（RBAC）
3. **リアルタイム通知**: WebSocket push notification
4. **フォレンジック**: イベントログ分析・レポート生成
