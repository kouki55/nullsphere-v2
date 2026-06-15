/**
 * security-headers.ts
 * ====================
 * [H-4] Helmet によるセキュリティヘッダーの設定
 *
 * セキュリティヘッダーを設定し、一般的な Web 攻撃を防ぐ
 */

import helmet from 'helmet';
import type { Express } from 'express';

/**
 * Helmet セキュリティヘッダーを Express アプリに適用
 */
export function setupSecurityHeaders(app: Express): void {
  // Helmet の基本設定
  app.use(
    helmet({
      // Content Security Policy (CSP)
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"], // React 開発環境用（本番では削除）
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'", 'https:', 'wss:'],
          fontSrc: ["'self'", 'data:'],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
        },
      },
      // X-Frame-Options: クリックジャッキング対策
      frameguard: {
        action: 'deny',
      },
      // X-Content-Type-Options: MIME スニッフィング対策
      noSniff: true,
      // X-XSS-Protection: XSS フィルター有効化
      xssFilter: true,
      // Referrer-Policy: リファラー情報の制限
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
      },
      // Strict-Transport-Security (HSTS)
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      },
      // Permissions-Policy (旧 Feature-Policy)
      permittedCrossDomainPolicies: false,
    })
  );

  console.log('[Security] Helmet security headers configured');
}
