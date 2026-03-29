# NullSphere V2 - TODO

## Phase 1: データベーススキーマ・バックエンドAPI
- [x] DB スキーマ設計 (threats, attackers, events, vms, decoys, notifications)
- [x] マイグレーション生成・適用
- [x] tRPC ルーター構築 (dashboard, threats, events, vms, decoys, notifications, analysis)
- [x] シードデータ投入ロジック

## Phase 2: グローバルテーマ・レイアウト
- [x] サイバーパンク・SOCテーマ (ダーク, アクセントカラー: #00c8ff, #00ff99)
- [x] DashboardLayout カスタマイズ (サイドバーナビゲーション)
- [x] App.tsx ルーティング設定

## Phase 3: ダッシュボード・アーキテクチャ・データフロー
- [x] リアルタイム脅威検知ダッシュボード
- [x] システムアーキテクチャビュー (4コンポーネント状態監視)
- [x] データフローシミュレーター (6段階アニメーション)

## Phase 4: 脅威マップ・攻撃者・イベントログ
- [x] Google Maps 脅威マップ (攻撃元・経路・標的)
- [x] 攻撃者プロファイリングパネル
- [x] イベントログビューア (リアルタイム表示)

## Phase 5: VM管理・デコイ・通知・LLM
- [x] 隔離VM管理インターフェース
- [x] デコイ生成コントロール
- [x] 通知システム (メール・アプリ内)
- [x] LLM攻撃パターン分析レポート

## Phase 6: 最終確認・デプロイ
- [x] ログイン不要でダッシュボードにアクセスできるように変更（取り消し）
- [x] 認証ありに戻す（protectedProcedureに復元）
- [x] 動作確認・バグ修正
- [x] チェックポイント保存
- [x] ユーザーへの提供

## ログイン不要化対応
- [x] バックエンドAPIをprotectedProcedure→publicProcedureに変更
- [x] フロントエンドのDashboardLayoutから認証チェック・ログインリダイレクトを除去
- [x] ホームページを直接ダッシュボードに遷移するよう変更
- [x] 動作確認・チェックポイント保存

## バグ修正
- [x] 画面遷移時の予期せぬエラーを修正
