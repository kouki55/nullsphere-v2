/**
 * jwt-middleware.ts
 * ==================
 * JWT トークン検証とレート制限を行うミドルウェア
 */

import { TRPCError } from '@trpc/server';
import type { TrpcContext } from './context';

/**
 * JWT トークンの有効期限を検証
 */
export function validateTokenExpiry(token: any): boolean {
  if (!token || typeof token !== 'object') {
    return false;
  }

  // トークンに exp (expiration) フィールドがある場合、チェック
  if (token.exp) {
    const now = Math.floor(Date.now() / 1000);
    if (token.exp < now) {
      return false;
    }
  }

  return true;
}

/**
 * ユーザーの権限をチェック
 */
export function checkUserRole(
  user: any,
  requiredRoles: string[]
): boolean {
  if (!user || !user.role) {
    return false;
  }

  return requiredRoles.includes(user.role);
}

/**
 * レート制限用のトークンバケット実装
 */
class TokenBucket {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillRate: number; // tokens per second
  private lastRefillTime: number;

  constructor(capacity: number, refillRate: number) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillRate = refillRate;
    this.lastRefillTime = Date.now();
  }

  /**
   * トークンを消費できるかチェック
   */
  canConsume(tokens: number = 1): boolean {
    this.refill();
    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    return false;
  }

  /**
   * トークンを補充
   */
  private refill(): void {
    const now = Date.now();
    const timePassed = (now - this.lastRefillTime) / 1000;
    const tokensToAdd = timePassed * this.refillRate;

    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefillTime = now;
  }
}

/**
 * クライアント IP ごとのレート制限を管理
 */
class RateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();
  private readonly capacity: number;
  private readonly refillRate: number;
  private readonly cleanupInterval: number;

  constructor(capacity: number = 100, refillRate: number = 10) {
    this.capacity = capacity;
    this.refillRate = refillRate;
    this.cleanupInterval = 60000; // 1 minute

    // 定期的に古いバケットをクリーンアップ
    setInterval(() => this.cleanup(), this.cleanupInterval);
  }

  /**
   * レート制限をチェック
   */
  checkLimit(clientId: string, tokens: number = 1): boolean {
    if (!this.buckets.has(clientId)) {
      this.buckets.set(clientId, new TokenBucket(this.capacity, this.refillRate));
    }

    const bucket = this.buckets.get(clientId)!;
    return bucket.canConsume(tokens);
  }

  /**
   * 古いバケットをクリーンアップ
   */
  private cleanup(): void {
    // 実装: 最後にアクセスされてから一定時間経過したバケットを削除
    // 簡略版では全バケットを保持
  }
}

// グローバルレート制限インスタンス
export const globalRateLimiter = new RateLimiter(100, 10); // 100 tokens, 10 tokens/sec

/**
 * クライアント IP を取得
 */
export function getClientIp(ctx: TrpcContext): string {
  const forwarded = ctx.req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return ctx.req.socket.remoteAddress || 'unknown';
}

/**
 * レート制限エラーをスロー
 */
export function throwRateLimitError(): never {
  throw new TRPCError({
    code: 'TOO_MANY_REQUESTS',
    message: 'Too many requests. Please try again later.',
  });
}

/**
 * トークン検証エラーをスロー
 */
export function throwTokenError(reason: string): never {
  throw new TRPCError({
    code: 'UNAUTHORIZED',
    message: `Token validation failed: ${reason}`,
  });
}
