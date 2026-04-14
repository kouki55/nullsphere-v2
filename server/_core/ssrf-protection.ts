/**
 * ssrf-protection.ts
 * ===================
 * [M-4] Webhook SSRF (Server-Side Request Forgery) 対策
 *
 * 外部 URL へのリクエストを制限し、内部ネットワークへのアクセスを防ぐ
 */

import { URL } from 'url';
import { TRPCError } from '@trpc/server';

/**
 * SSRF から保護する IP レンジ
 */
const BLOCKED_IP_RANGES = [
  // Loopback
  /^127\./,
  /^::1$/,
  // Private (RFC 1918)
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  // Link-local
  /^169\.254\./,
  /^fe80:/i,
  // Multicast
  /^224\./,
  /^ff00:/i,
  // Localhost
  /^localhost$/i,
];

/**
 * ホスト名から IP アドレスを解決（簡略版）
 * 実運用では、DNS ライブラリを使用してください
 */
async function resolveHostname(hostname: string): Promise<string> {
  // 簡略版: ホスト名をそのまま返す
  // 実運用では dns.promises.resolve4() などを使用
  return hostname;
}

/**
 * URL が SSRF 対象かチェック
 */
export async function isSsrfUrl(urlString: string): Promise<boolean> {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname;

    // プロトコルチェック: HTTP/HTTPS のみ許可
    if (!['http:', 'https:'].includes(url.protocol)) {
      return true;
    }

    // ブロック対象の IP レンジをチェック
    for (const pattern of BLOCKED_IP_RANGES) {
      if (pattern.test(hostname)) {
        return true;
      }
    }

    // ホスト名を解決して IP をチェック
    const resolvedIp = await resolveHostname(hostname);
    for (const pattern of BLOCKED_IP_RANGES) {
      if (pattern.test(resolvedIp)) {
        return true;
      }
    }

    return false;
  } catch {
    // URL パースエラーは SSRF と見なす
    return true;
  }
}

/**
 * Webhook URL を検証
 */
export async function validateWebhookUrl(webhookUrl: string): Promise<void> {
  if (!webhookUrl || typeof webhookUrl !== 'string') {
    throw new TRPCError({
      code: 'BAD_REQUEST',
      message: 'Webhook URL is required',
    });
  }

  if (webhookUrl.length > 2048) {
    throw new TRPCError({
      code: 'BAD_REQUEST',
      message: 'Webhook URL is too long',
    });
  }

  // SSRF チェック
  const isSsrf = await isSsrfUrl(webhookUrl);
  if (isSsrf) {
    throw new TRPCError({
      code: 'FORBIDDEN',
      message: 'Webhook URL is not allowed (SSRF protection)',
    });
  }
}

/**
 * 安全な HTTP リクエストを実行
 */
export async function makeSafeHttpRequest(
  url: string,
  options: {
    method?: string;
    timeout?: number;
    maxRedirects?: number;
  } = {}
): Promise<Response> {
  // SSRF チェック
  const isSsrf = await isSsrfUrl(url);
  if (isSsrf) {
    throw new TRPCError({
      code: 'FORBIDDEN',
      message: 'Request URL is not allowed (SSRF protection)',
    });
  }

  const { method = 'GET', maxRedirects = 0 } = options;

  try {
    const response = await fetch(url, {
      method,
      redirect: maxRedirects > 0 ? 'follow' : 'error',
      signal: AbortSignal.timeout(5000), // タイムアウト設定
    });

    return response;
  } catch (error) {
    throw new TRPCError({
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Failed to make HTTP request',
    });
  }
}
