/**
 * packet-filter.ts
 * =================
 * パケットフィルタリングとレート制限の実装
 * DoS 攻撃（大量ログ送信）を検知・遮断する
 */

import type { TLSSocket } from 'tls';

/**
 * パケット統計情報
 */
export interface PacketStats {
  totalPackets: number;
  totalBytes: number;
  lastPacketTime: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  suspiciousCount: number;
}

/**
 * クライアント統計情報
 */
export interface ClientStats {
  clientId: string;
  certificate: any;
  stats: PacketStats;
  isBlocked: boolean;
  blockReason?: string;
  blockTime?: number;
}

/**
 * パケットフィルタリングエンジン
 */
export class PacketFilter {
  private clientStats: Map<string, ClientStats> = new Map();
  private readonly maxPacketsPerSecond: number;
  private readonly maxBytesPerSecond: number;
  private readonly maxSuspiciousCount: number;
  private readonly blockDuration: number; // milliseconds
  private readonly anomalyThreshold: number; // 異常判定の閾値

  constructor(
    maxPacketsPerSecond: number = 100,
    maxBytesPerSecond: number = 1024 * 1024, // 1 MB/s
    maxSuspiciousCount: number = 5,
    blockDuration: number = 60000, // 1 minute
    anomalyThreshold: number = 0.8
  ) {
    this.maxPacketsPerSecond = maxPacketsPerSecond;
    this.maxBytesPerSecond = maxBytesPerSecond;
    this.maxSuspiciousCount = maxSuspiciousCount;
    this.blockDuration = blockDuration;
    this.anomalyThreshold = anomalyThreshold;

    // 定期的にブロック状態をクリア
    setInterval(() => this.clearExpiredBlocks(), 30000);
  }

  /**
   * クライアントを登録
   */
  registerClient(clientId: string, certificate: any): void {
    if (!this.clientStats.has(clientId)) {
      this.clientStats.set(clientId, {
        clientId,
        certificate,
        stats: {
          totalPackets: 0,
          totalBytes: 0,
          lastPacketTime: Date.now(),
          packetsPerSecond: 0,
          bytesPerSecond: 0,
          suspiciousCount: 0,
        },
        isBlocked: false,
      });
    }
  }

  /**
   * パケットをフィルタリング
   */
  filterPacket(clientId: string, packetSize: number): boolean {
    // クライアントが登録されていない場合は登録
    if (!this.clientStats.has(clientId)) {
      this.registerClient(clientId, null);
    }

    const clientStats = this.clientStats.get(clientId)!;

    // ブロック中の場合
    if (clientStats.isBlocked) {
      const blockAge = Date.now() - (clientStats.blockTime || 0);
      if (blockAge < this.blockDuration) {
        console.warn(
          `[PacketFilter] Packet rejected: Client ${clientId} is blocked (${blockAge}ms)`
        );
        return false;
      } else {
        // ブロック期間が終了したのでリセット
        clientStats.isBlocked = false;
        clientStats.blockReason = undefined;
        clientStats.blockTime = undefined;
        clientStats.stats.suspiciousCount = 0;
      }
    }

    // 統計情報を更新
    const now = Date.now();
    const timeDelta = (now - clientStats.stats.lastPacketTime) / 1000;

    clientStats.stats.totalPackets++;
    clientStats.stats.totalBytes += packetSize;
    clientStats.stats.lastPacketTime = now;

    // 1 秒ごとのレートを計算
    if (timeDelta >= 1) {
      clientStats.stats.packetsPerSecond = clientStats.stats.totalPackets / timeDelta;
      clientStats.stats.bytesPerSecond = clientStats.stats.totalBytes / timeDelta;
    }

    // 異常検知
    const anomalies = this.detectAnomalies(clientStats);

    if (anomalies.length > 0) {
      clientStats.stats.suspiciousCount++;
      console.warn(
        `[PacketFilter] Anomaly detected for ${clientId}: ${anomalies.join(', ')}`
      );

      // 疑わしい活動が多い場合はブロック
      if (clientStats.stats.suspiciousCount >= this.maxSuspiciousCount) {
        this.blockClient(clientId, `Too many anomalies (${anomalies.join(', ')})`);
        return false;
      }
    }

    return true;
  }

  /**
   * 異常を検知
   */
  private detectAnomalies(clientStats: ClientStats): string[] {
    const anomalies: string[] = [];
    const stats = clientStats.stats;

    // パケットレート異常
    if (stats.packetsPerSecond > this.maxPacketsPerSecond) {
      anomalies.push(
        `High packet rate (${stats.packetsPerSecond.toFixed(2)} pps > ${this.maxPacketsPerSecond} pps)`
      );
    }

    // バイトレート異常
    if (stats.bytesPerSecond > this.maxBytesPerSecond) {
      anomalies.push(
        `High byte rate (${(stats.bytesPerSecond / 1024).toFixed(2)} KB/s > ${(this.maxBytesPerSecond / 1024).toFixed(2)} KB/s)`
      );
    }

    // 小さいパケットの大量送信（ハートビート攻撃）
    if (stats.totalPackets > 0) {
      const avgPacketSize = stats.totalBytes / stats.totalPackets;
      if (avgPacketSize < 10 && stats.packetsPerSecond > 50) {
        anomalies.push(
          `Tiny packet flood (avg size: ${avgPacketSize.toFixed(2)} bytes, rate: ${stats.packetsPerSecond.toFixed(2)} pps)`
        );
      }
    }

    return anomalies;
  }

  /**
   * クライアントをブロック
   */
  private blockClient(clientId: string, reason: string): void {
    const clientStats = this.clientStats.get(clientId);
    if (clientStats) {
      clientStats.isBlocked = true;
      clientStats.blockReason = reason;
      clientStats.blockTime = Date.now();
      console.error(`[PacketFilter] Client ${clientId} blocked: ${reason}`);
    }
  }

  /**
   * 期限切れのブロック状況をクリア
   */
  private clearExpiredBlocks(): void {
    const now = Date.now();
    this.clientStats.forEach((stats, clientId) => {
      if (stats.isBlocked && stats.blockTime) {
        const blockAge = now - stats.blockTime;
        if (blockAge >= this.blockDuration) {
          stats.isBlocked = false;
          stats.blockReason = undefined;
          stats.blockTime = undefined;
          stats.stats.suspiciousCount = 0;
          console.log(`[PacketFilter] Client ${clientId} unblocked`);
        }
      }
    });
  }

  /**
   * クライアント統計を取得
   */
  getClientStats(clientId: string): ClientStats | undefined {
    return this.clientStats.get(clientId);
  }

  /**
   * すべてのクライアント統計を取得
   */
  getAllStats(): ClientStats[] {
    const result: ClientStats[] = [];
    this.clientStats.forEach((stats) => {
      result.push(stats);
    });
    return result;
  }

  /**
   * クライアントを削除
   */
  removeClient(clientId: string): void {
    this.clientStats.delete(clientId);
    console.log(`[PacketFilter] Client ${clientId} removed`);
  }
}

/**
 * グローバルパケットフィルター インスタンス
 */
export const globalPacketFilter = new PacketFilter(
  100, // max 100 packets/sec
  1024 * 1024, // max 1 MB/sec
  5, // max 5 anomalies
  60000, // block for 1 minute
  0.8 // anomaly threshold
);
