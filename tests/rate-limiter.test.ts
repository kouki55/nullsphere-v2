import { describe, it, expect, beforeEach } from 'vitest';

/**
 * トークンバケットアルゴリズムのシンプルな実装（テスト用）
 */
class TokenBucket {
  private tokens: number;
  private readonly capacity: number;
  private readonly refillRate: number; // tokens per second
  private lastRefillTime: number;

  constructor(capacity: number, refillRate: number) {
    this.capacity = capacity;
    this.refillRate = refillRate;
    this.tokens = capacity;
    this.lastRefillTime = Date.now();
  }

  private refill(): void {
    const now = Date.now();
    const timePassed = (now - this.lastRefillTime) / 1000; // seconds
    const tokensToAdd = timePassed * this.refillRate;

    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefillTime = now;
  }

  public tryConsume(tokens: number = 1): boolean {
    this.refill();

    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }

    return false;
  }

  public getTokens(): number {
    this.refill();
    return this.tokens;
  }
}

describe('Rate Limiter (Token Bucket)', () => {
  let bucket: TokenBucket;

  beforeEach(() => {
    // 容量: 10 トークン、補充レート: 1 トークン/秒
    bucket = new TokenBucket(10, 1);
  });

  describe('Token Consumption', () => {
    it('should allow requests within capacity', () => {
      expect(bucket.tryConsume(1)).toBe(true);
      expect(bucket.tryConsume(1)).toBe(true);
      expect(bucket.tryConsume(1)).toBe(true);
    });

    it('should reject requests exceeding capacity', () => {
      // 容量 10 を消費
      for (let i = 0; i < 10; i++) {
        expect(bucket.tryConsume(1)).toBe(true);
      }

      // 11 番目のリクエストは拒否
      expect(bucket.tryConsume(1)).toBe(false);
    });

    it('should allow multiple tokens per request', () => {
      expect(bucket.tryConsume(5)).toBe(true);
      // 浮動小数点数の誤差を考慮
      expect(bucket.getTokens()).toBeLessThanOrEqual(5.1);
    });

    it('should reject requests requiring more tokens than capacity', () => {
      expect(bucket.tryConsume(15)).toBe(false);
    });
  });

  describe('Token Refill', () => {
    it('should refill tokens over time', async () => {
      // 容量を消費
      for (let i = 0; i < 10; i++) {
        bucket.tryConsume(1);
      }

      expect(bucket.getTokens()).toBe(0);

      // 1.1 秒待機（1 トークン補充）
      await new Promise(resolve => setTimeout(resolve, 1100));

      expect(bucket.getTokens()).toBeGreaterThan(0);
    });

    it('should not exceed capacity after refill', async () => {
      // 初期状態で容量 10
      expect(bucket.getTokens()).toBeLessThanOrEqual(10);

      // 2 秒待機（2 トークン補充を試みるが、容量は 10 に制限）
      await new Promise(resolve => setTimeout(resolve, 2000));

      expect(bucket.getTokens()).toBeLessThanOrEqual(10);
    });
  });

  describe('Rate Limiting Scenarios', () => {
    it('should simulate API rate limiting (10 req/sec)', async () => {
      const bucket = new TokenBucket(10, 10); // 10 tokens/sec

      // 最初の 10 リクエストは許可
      for (let i = 0; i < 10; i++) {
        expect(bucket.tryConsume(1)).toBe(true);
      }

      // 11 番目は拒否
      expect(bucket.tryConsume(1)).toBe(false);

      // 0.1 秒待機（1 トークン補充）
      await new Promise(resolve => setTimeout(resolve, 100));

      // 1 つのリクエストが許可される
      expect(bucket.tryConsume(1)).toBe(true);
    });

    it('should prevent brute force attacks', () => {
      const bucket = new TokenBucket(5, 1); // 5 tokens/sec

      // 攻撃者が 100 回のリクエストを試みる
      let successCount = 0;
      for (let i = 0; i < 100; i++) {
        if (bucket.tryConsume(1)) {
          successCount++;
        }
      }

      // 最初の 5 リクエストのみ成功
      expect(successCount).toBe(5);
    });
  });
});
