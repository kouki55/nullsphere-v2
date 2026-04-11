/**
 * threat-feed-handler.ts
 * ======================
 * Socket.io 接続時の脅威フィード・ハンドラー
 */

import { Server as SocketIOServer, Socket } from 'socket.io';
import type { KernelBridge } from '../kernel-bridge';
import { THREAT_FEED_EVENTS } from './types/threat-feed';

/**
 * Socket.io 接続時に脅威フィード・ハンドラーを設定
 */
export function setupThreatFeedHandlers(
  io: SocketIOServer,
  kernelBridge: KernelBridge
) {
  io.on('connection', (socket: Socket) => {
    console.log(`[ThreatFeed] Client connected: ${socket.id}`);

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

    // クライアントからのリクエスト: 脅威フィード・バッファをリセット
    socket.on('threat:feed:reset', () => {
      console.log(`[ThreatFeed] Reset request from ${socket.id}`);
      kernelBridge.clearThreatFeedBuffer();
      socket.emit('threat:feed:reset:ack', { success: true });
    });

    // クライアントからのリクエスト: 脅威フィード・バッファを取得
    socket.on('threat:feed:get', (callback: (data: any) => void) => {
      const buffer = kernelBridge.getThreatFeedBuffer();
      callback({
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
 * 脅威フィード・イベントをフィルタリングして送信
 */
export function broadcastFilteredThreatFeed(
  io: SocketIOServer,
  threatFeedEvent: any,
  options?: {
    minSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    excludeInfo?: boolean;
  }
) {
  const { minSeverity = 'low', excludeInfo = false } = options || {};

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
}
