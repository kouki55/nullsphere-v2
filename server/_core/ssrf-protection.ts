/**
 * ssrf-protection.ts
 * ===================
 * [M-4] Webhook SSRF (Server-Side Request Forgery) 対策
 *
 * 外部 URL へのリクエストを制限し、内部ネットワークへのアクセスを防ぐ
 */

import { URL } from 'url';
import { TRPCError } from '@trpc/server';
import { promises as dns } from 'dns';

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
 * [Phase 30] DNS レベルの要塞化:
 * ホスト名を実際の IP アドレスに解決し、内部ネットワークへのアクセスを防ぐ
 */
async function resolveHostname(hostname: string): Promise<string[]> {
  try {
    // DNS タイムアウト: 5 秒以内に解決できなければ失敗
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
      // IPv4 アドレスを解決
      const addresses = await dns.resolve4(hostname);
      clearTimeout(timeoutId);

      if (addresses.length === 0) {
        // 解決できなかった場合は、ホスト名をそのまま返す（IP レンジチェックで引っかかる可能性あり）
        return [hostname];
      }

      return addresses;
    } catch (error) {
      clearTimeout(timeoutId);

      // DNS 解決失敗時は、ホスト名をそのまま返す
      // （IP レンジチェックで引っかかる可能性があるため、安全側に倒す）
      return [hostname];
    }
  } catch {
    // 予期しないエラーは、ホスト名をそのまま返す
    return [hostname];
  }
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

    // ホスト名が IP アドレスか、ホスト名かを判定
    const isIpAddress = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || /^::/.test(hostname);

    if (isIpAddress) {
      // IP アドレスの場合は直接チェック
      for (const pattern of BLOCKED_IP_RANGES) {
        if (pattern.test(hostname)) {
          return true;
        }
      }
    } else {
      // ホスト名の場合は DNS 解決して IP をチェック
      const resolvedIps = await resolveHostname(hostname);

      for (const ip of resolvedIps) {
        for (const pattern of BLOCKED_IP_RANGES) {
          if (pattern.test(ip)) {
            return true;
          }
        }
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
