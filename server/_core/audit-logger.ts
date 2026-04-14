/**
 * audit-logger.ts
 * ================
 * [M-2] Cookie sameSite 設定
 * [M-3] 監査ログに IP/UA を含める
 *
 * セキュアな Cookie 設定と、詳細な監査ログを実装
 */

import type { Express, Request, Response } from 'express';
import session from 'express-session';

/**
 * [M-2] セキュアな Cookie 設定で Express Session を初期化
 */
export function setupSecureSession(app: Express, sessionStore: any): void {
  app.use(
    session({
      store: sessionStore,
      secret: process.env.SESSION_SECRET || 'your-secret-key',
      resave: false,
      saveUninitialized: false,
      cookie: {
        // [M-2] sameSite: "none" から "strict" に変更（CSRF 対策）
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production', // HTTPS のみで送信
        httpOnly: true, // JavaScript からアクセス不可
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      },
    })
  );

  console.log('[Security] Secure session cookie configured');
}

/**
 * 監査ログエントリの型定義
 */
export interface AuditLogEntry {
  timestamp: string;
  userId: string;
  action: string;
  resource: string;
  status: 'success' | 'failure';
  ipAddress: string;
  userAgent: string;
  details?: Record<string, any>;
}

/**
 * [M-3] 監査ログを記録
 */
export function logAuditEvent(
  req: Request,
  userId: string,
  action: string,
  resource: string,
  status: 'success' | 'failure',
  details?: Record<string, any>
): AuditLogEntry {
  const entry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    userId,
    action,
    resource,
    status,
    ipAddress: extractClientIp(req),
    userAgent: req.get('user-agent') || 'unknown',
    details,
  };

  // ログをコンソールに出力（実運用では DB に保存）
  console.log(
    `[Audit] ${entry.timestamp} | User: ${entry.userId} | Action: ${entry.action} | Resource: ${entry.resource} | Status: ${entry.status} | IP: ${entry.ipAddress}`
  );

  return entry;
}

/**
 * クライアント IP アドレスを抽出
 */
export function extractClientIp(req: Request): string {
  const trustProxy = process.env.TRUST_PROXY === 'true' || process.env.TRUST_PROXY === '1';

  if (trustProxy) {
    const forwarded = req.get('x-forwarded-for');
    if (forwarded) {
      return forwarded.split(',')[0].trim();
    }
  }

  return req.ip || req.socket.remoteAddress || 'unknown';
}

/**
 * 監査ログミドルウェア
 */
export function auditLogMiddleware(req: Request, res: Response, next: Function): void {
  // レスポンス送信後に監査ログを記録
  res.on('finish', () => {
    const userId = (req as any).user?.id || 'anonymous';
    const action = `${req.method} ${req.path}`;
    const status = res.statusCode < 400 ? 'success' : 'failure';

    logAuditEvent(req, userId, action, req.path, status, {
      statusCode: res.statusCode,
      method: req.method,
    });
  });

  next();
}
