/**
 * threat-feed-handler.ts
 * ======================
 * Socket.io 接続時の脅威フィード・ハンドラー
 *
 * [NEW-3] セキュリティ修正:
 *   - threat:feed:reset と threat:feed:get に認証チェックを追加
 *   - admin ロールのみ実行可能
 */

import { Server as SocketIOServer, Socket } from 'socket.io';
import type { KernelBridge } from '../kernel-bridge';
import { THREAT_FEED_EVENTS } from './types/threat-feed';
import { persistThreatFeed } from './threat-persistence';

/**
 * Socket.io 接続時に脅威フィード・ハンドラーを設定
 */
export function setupThreatFeedHandlers(
  io: SocketIOServer,
  kernelBridge: KernelBridge
) {
  io.on('connection', (socket: Socket) => {
    const user = socket.data.user;
    console.log(
      `[ThreatFeed] Client connected: ${socket.id} (user: ${user?.id}, role: ${user?.role})`
    );

    // クライアント接続時に脅威フィード・バッファを送信
    const threatBuffer = kernelBridge.getThreatFeedBuffer();
    if (threatBuffer.length > 0) {
      socket.emit(THREAT_FEED_EVENTS.THREAT_FEED_INIT, {
        events: threatBuffer,
        timestamp: new Date().toISOString(),
        count: threatBuffer.length,
      });
      console.log(
        `[ThreatFeed] Sent ${threatBuffer.length} buffered events to ${socket.id}`
      );
    }

    // [NEW-3] クライアントからのリクエスト: 脅威フィード・バッファをリセット
    // 認証チェック: admin ロールのみ実行可
    socket.on('threat:feed:reset', () => {
      if (!user || user.role !== 'admin') {
        socket.emit('threat:feed:reset:ack', {
          success: false,
          error: 'Forbidden: admin role required',
        });
        console.warn(
          `[ThreatFeed] Unauthorized reset attempt by user ${user?.id} (role: ${user?.role})`
        );
        return;
      }

      console.log(`[ThreatFeed] Reset request from admin ${user.id}`);
      kernelBridge.clearThreatFeedBuffer();
      socket.emit('threat:feed:reset:ack', { success: true });
    });

    // [NEW-3] クライアントからのリクエスト: 脅威フィード・バッファを取得
    // 認証チェック: admin ロールのみ実行可
    socket.on('threat:feed:get', (callback: (data: any) => void) => {
      if (!user || user.role !== 'admin') {
        callback({
          success: false,
          error: 'Forbidden: admin role required',
        });
        console.warn(
          `[ThreatFeed] Unauthorized get attempt by user ${user?.id} (role: ${user?.role})`
        );
        return;
      }

      const buffer = kernelBridge.getThreatFeedBuffer();
      callback({
        success: true,
        events: buffer,
        timestamp: new Date().toISOString(),
        count: buffer.length,
      });
    });

    // クライアント切断時
    socket.on('disconnect', () => {
      console.log(`[ThreatFeed] Client disconnected: ${socket.id}`);
    });
  });
}

/**
 * 脅威フィード・イベントをフィルタリングして送信・永続化
 */
export async function broadcastFilteredThreatFeed(
  io: SocketIOServer,
  threatFeedEvent: any,
  options?: {
    minSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    excludeInfo?: boolean;
    persistToDb?: boolean;
  }
) {
  const { minSeverity = 'low', excludeInfo = false, persistToDb = true } = options || {};

  // 深刻度フィルタリング
  const severityOrder: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };

  const eventLevel = severityOrder[threatFeedEvent.severity] || 0;
  const minLevel = severityOrder[minSeverity] || 0;

  if (eventLevel < minLevel) {
    return;
  }

  // Info レベルを除外する場合
  if (excludeInfo && threatFeedEvent.severity === 'info') {
    return;
  }

  // ブロードキャスト
  io.emit(THREAT_FEED_EVENTS.THREAT_FEED, threatFeedEvent);

  // データベースに永続化（非同期）
  if (persistToDb) {
    persistThreatFeed(threatFeedEvent).catch((err) => {
      console.error('[ThreatFeedHandler] Failed to persist threat feed:', err);
    });
  }
}
