/**
 * ownership-check.ts
 * ===================
 * [H-1] IDOR (Insecure Direct Object Reference) 対策
 *
 * ユーザーが自分のデータのみにアクセスできるよう、所有権チェックを実装
 */

import { TRPCError } from '@trpc/server';

/**
 * リソースの所有権をチェック
 */
export function checkOwnership(
  resourceOwnerId: string,
  requestingUserId: string,
  resourceType: string = 'resource'
): void {
  if (resourceOwnerId !== requestingUserId) {
    throw new TRPCError({
      code: 'FORBIDDEN',
      message: `You do not have permission to access this ${resourceType}`,
    });
  }
}

/**
 * 複数リソースの所有権をチェック
 */
export function checkMultipleOwnership(
  resources: Array<{ ownerId: string }>,
  requestingUserId: string,
  resourceType: string = 'resources'
): void {
  const unauthorized = resources.some((r) => r.ownerId !== requestingUserId);
  if (unauthorized) {
    throw new TRPCError({
      code: 'FORBIDDEN',
      message: `You do not have permission to access some of these ${resourceType}`,
    });
  }
}

/**
 * 通知の既読状態を更新する際の所有権チェック
 */
export function checkNotificationOwnership(
  notificationOwnerId: string,
  requestingUserId: string
): void {
  if (notificationOwnerId !== requestingUserId) {
    throw new TRPCError({
      code: 'FORBIDDEN',
      message: 'You cannot modify notifications that do not belong to you',
    });
  }
}
