# Phase 28：セキュリティ脆弱性の一括修正 実装計画

## 1. 目的
Phase 24〜27 で実装した新機能に潜む脆弱性、および既存のセキュリティ負債（C-1〜M-5）を一括で修正し、NullSphere V2 を製品レベルの堅牢なシステムへと進化させる。

## 2. 修正対象

### Critical (緊急)
- **C-1: XSS (innerHTML)**: `ThreatMap.tsx` 等での危険な DOM 操作の排除。
- **C-2: WebSocket 認証/CORS**: `Socket.io` の認証ミドルウェア導入と CORS 制限。

### High (高)
- **H-1: IDOR (markRead)**: 通知等の既読処理における所有権チェック。
- **H-2: LLM インジェクション**: プロンプトの構造化と出力サニタイズ。
- **H-3: レート制限**: `jwt-middleware.ts` の改善と全 API への適用。
- **H-4: Helmet なし**: セキュリティヘッダーの強制適用。
- **H-5: 無制限 SELECT**: ページネーション制限の導入。

### Medium (中)
- **M-1: Body サイズ制限**: リクエストボディの最大サイズを 10MB に制限。
- **M-2: Cookie 設定**: `sameSite: "strict"` への変更。
- **M-3: 監査ログ**: IP アドレスと User-Agent の記録。
- **M-4: Webhook SSRF**: 外部リクエストの検証と制限。
- **M-5: 入力長さ制限**: 文字列フィールドの最大長制限。

### 新規特定 (NEW)
- **NEW-1: RateLimiter メモリリーク**: 古いバケットの自動削除。
- **NEW-2: x-forwarded-for 偽装**: プロキシ信頼設定の厳格化。
- **NEW-3: WebSocket イベント認証欠如**: 脅威フィード操作の admin 制限。

## 3. 実装ステップ
1. 脆弱性修正用 ZIP ファイルの解析。
2. Critical 脆弱性の修正。
3. High 脆弱性の修正。
4. Medium 脆弱性の修正。
5. 統合テストと TypeScript コンパイルチェック。
6. GitHub へのプッシュとレポート提出。
