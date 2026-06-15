/**
 * query-limiter.ts
 * =================
 * [H-5] 無制限 SELECT 対策
 *
 * データベースクエリに自動的に LIMIT と OFFSET を適用し、
 * 大量データ取得による DoS を防ぐ
 */

/**
 * クエリ制限の設定
 */
export const QUERY_LIMITS = {
  DEFAULT_LIMIT: 100,
  MAX_LIMIT: 1000,
  DEFAULT_OFFSET: 0,
};

/**
 * ページネーションパラメータを検証・正規化
 */
export function validatePaginationParams(
  limit?: number,
  offset?: number
): { limit: number; offset: number } {
  // LIMIT の検証
  let validLimit = QUERY_LIMITS.DEFAULT_LIMIT;
  if (limit !== undefined && limit !== null) {
    const parsedLimit = parseInt(String(limit), 10);
    if (parsedLimit > 0 && parsedLimit <= QUERY_LIMITS.MAX_LIMIT) {
      validLimit = parsedLimit;
    }
  }

  // OFFSET の検証
  let validOffset = QUERY_LIMITS.DEFAULT_OFFSET;
  if (offset !== undefined && offset !== null) {
    const parsedOffset = parseInt(String(offset), 10);
    if (parsedOffset >= 0) {
      validOffset = parsedOffset;
    }
  }

  return { limit: validLimit, offset: validOffset };
}

/**
 * tRPC ルーターで使用するヘルパー関数
 */
export function createPaginatedQuery<T>(
  items: T[],
  limit: number,
  offset: number
): { items: T[]; total: number; limit: number; offset: number } {
  return {
    items: items.slice(offset, offset + limit),
    total: items.length,
    limit,
    offset,
  };
}
