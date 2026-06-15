# Phase 24: WebSocket リアルタイム脅威フィード 実装計画

## 1. 概要
本フェーズでは、`KernelBridge` を通じて受信される低レベルなカーネルイベントを、ユーザーが直感的に理解できる「脅威フィード」としてリアルタイムにフロントエンドへ配信する機能を実装します。

## 2. サーバー側実装 (Node.js / Socket.io)
- **イベントの洗練**: `KernelBridge` で受信した `kernel:event` を元に、`threat:feed` イベントを定義。
- **データ整形**: フロントエンドが表示しやすい形式（ID, タイムスタンプ, 深刻度, メッセージ, ソースIP等）に変換。
- **ブロードキャスト**: 接続中の全クライアントに `threat:feed` を送信。

## 3. フロントエンド実装 (React / Socket.io-client)
- **WebSocket コンテキストの作成**: `Socket.io` の接続を管理する `SocketContext` を実装。
- **リアルタイム・フィード・コンポーネント**: `Dashboard.tsx` の「Event Stream」セクションを、WebSocket からのリアルタイムデータで更新されるように変更。
- **通知システム**: 深刻度が `critical` または `high` の脅威が発生した際、トースト通知を表示。

## 4. 実装ステップ
1.  `socket.io-client` のインストール。
2.  サーバー側 `KernelBridge` の拡張（`threat:feed` イベントの追加）。
3.  フロントエンド `useSocket` フックの実装。
4.  `Dashboard.tsx` への統合。
5.  モックデータによる動作確認。

## 5. セキュリティ考慮事項
- WebSocket 接続時の認証（既存のセッション/トークンを利用）。
- 送信データのサニタイズ。
