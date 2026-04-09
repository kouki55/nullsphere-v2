/**
 * eBPF リングバッファ管理・異常検知モジュール
 * Event Storming 攻撃（段階1）から守る
 * 
 * 攻撃者が getpid() などを秒間数千万回実行してバッファをパンクさせても、
 * システムは重要なイベントを保護し続ける。
 */

export type EventPriority = "critical" | "high" | "normal" | "low";

export interface BPFEvent {
  pid: number;
  comm: string;
  syscall: string;
  timestamp: number;
  priority: EventPriority;
  data?: any;
}

export interface RingBufferStats {
  totalCapacity: number;
  currentUsage: number;
  usagePercentage: number;
  droppedEvents: number;
  priorityDistribution: Record<EventPriority, number>;
  anomalies: string[];
}

/**
 * イベント優先度の定義
 */
const EVENT_PRIORITY_SCORES: Record<EventPriority, number> = {
  critical: 1000,
  high: 100,
  normal: 10,
  low: 1,
};

/**
 * 疑わしいシステムコール（Event Storming に使用される）
 */
const SUSPICIOUS_SYSCALLS = [
  "getpid",
  "gettid",
  "getppid",
  "getuid",
  "getgid",
  "stat",
  "fstat",
  "lstat",
  "access",
  "faccessat",
  "clock_gettime",
  "gettimeofday",
];

/**
 * eBPF リングバッファマネージャー
 */
export class EBPFRingBufferManager {
  private capacity: number;
  private buffer: BPFEvent[] = [];
  private stats: RingBufferStats;
  private anomalyThresholds = {
    usagePercentage: 80, // 80% 以上で警告
    eventsPerSecond: 100000, // 秒間 100,000 イベント以上で警告
    suspiciousEventRatio: 0.9, // 疑わしいイベントが 90% 以上で警告
  };

  constructor(capacityMB: number = 256) {
    this.capacity = capacityMB * 1024 * 1024; // バイト単位に変換
    this.stats = {
      totalCapacity: this.capacity,
      currentUsage: 0,
      usagePercentage: 0,
      droppedEvents: 0,
      priorityDistribution: { critical: 0, high: 0, normal: 0, low: 0 },
      anomalies: [],
    };
  }

  /**
   * イベントをバッファに追加
   * @param event BPF イベント
   * @returns 追加成功時 true、バッファ満杯時 false
   */
  addEvent(event: BPFEvent): boolean {
    // イベントのサイズを推定（バイト単位）
    const eventSize = JSON.stringify(event).length;

    // バッファ使用率をチェック
    const newUsage = this.stats.currentUsage + eventSize;

    if (newUsage > this.capacity) {
      // バッファが満杯 → 低優先度イベントを削除
      this.evictLowPriorityEvents(eventSize);

      // それでも満杯の場合はイベントを破棄
      if (this.stats.currentUsage + eventSize > this.capacity) {
        this.stats.droppedEvents++;
        return false;
      }
    }

    // イベントを追加
    this.buffer.push(event);
    this.stats.currentUsage += eventSize;
    this.stats.priorityDistribution[event.priority]++;

    // 異常を検知
    this.detectAnomalies();

    return true;
  }

  /**
   * 低優先度イベントを削除してスペースを確保
   * @param requiredSpace 必要なスペース（バイト単位）
   */
  private evictLowPriorityEvents(requiredSpace: number): void {
    // 優先度の低い順にソート
    const sorted = [...this.buffer].sort((a, b) => {
      const scoreA = EVENT_PRIORITY_SCORES[a.priority];
      const scoreB = EVENT_PRIORITY_SCORES[b.priority];
      return scoreA - scoreB;
    });

    let freedSpace = 0;
    const toRemove: BPFEvent[] = [];

    for (const event of sorted) {
      if (freedSpace >= requiredSpace) break;

      const eventSize = JSON.stringify(event).length;
      freedSpace += eventSize;
      toRemove.push(event);
    }

    // バッファから削除
    for (const event of toRemove) {
      const index = this.buffer.indexOf(event);
      if (index !== -1) {
        this.buffer.splice(index, 1);
        this.stats.currentUsage -= JSON.stringify(event).length;
        this.stats.priorityDistribution[event.priority]--;
      }
    }
  }

  /**
   * 異常を検知
   */
  private detectAnomalies(): void {
    this.stats.anomalies = [];

    // 1. バッファ使用率チェック
    const usagePercentage = (this.stats.currentUsage / this.capacity) * 100;
    this.stats.usagePercentage = usagePercentage;

    if (usagePercentage > this.anomalyThresholds.usagePercentage) {
      this.stats.anomalies.push(
        `High buffer usage: ${usagePercentage.toFixed(2)}% (threshold: ${this.anomalyThresholds.usagePercentage}%)`
      );
    }

    // 2. 秒間イベント数チェック
    const now = Date.now();
    const oneSecondAgo = now - 1000;
    const recentEvents = this.buffer.filter((e) => e.timestamp > oneSecondAgo);

    if (recentEvents.length > this.anomalyThresholds.eventsPerSecond) {
      this.stats.anomalies.push(
        `Event storm detected: ${recentEvents.length} events/sec (threshold: ${this.anomalyThresholds.eventsPerSecond})`
      );
    }

    // 3. 疑わしいシステムコール比率チェック
    const suspiciousCount = recentEvents.filter((e) =>
      SUSPICIOUS_SYSCALLS.includes(e.syscall)
    ).length;

    if (recentEvents.length > 0) {
      const suspiciousRatio = suspiciousCount / recentEvents.length;

      if (suspiciousRatio > this.anomalyThresholds.suspiciousEventRatio) {
        this.stats.anomalies.push(
          `Suspicious syscall pattern: ${(suspiciousRatio * 100).toFixed(2)}% of recent events (threshold: ${this.anomalyThresholds.suspiciousEventRatio * 100}%)`
        );
      }
    }

    // 4. ドロップイベント数チェック
    if (this.stats.droppedEvents > 100) {
      this.stats.anomalies.push(
        `High event drop rate: ${this.stats.droppedEvents} events dropped`
      );
    }
  }

  /**
   * 統計情報を取得
   * @returns リングバッファ統計
   */
  getStats(): RingBufferStats {
    this.detectAnomalies();
    return { ...this.stats };
  }

  /**
   * バッファをクリア
   */
  clear(): void {
    this.buffer = [];
    this.stats.currentUsage = 0;
    this.stats.droppedEvents = 0;
    this.stats.priorityDistribution = { critical: 0, high: 0, normal: 0, low: 0 };
    this.stats.anomalies = [];
  }

  /**
   * 優先度に基づいてイベントをフィルタリング
   * @param minPriority 最小優先度
   * @returns フィルタリングされたイベント
   */
  getEventsByPriority(minPriority: EventPriority): BPFEvent[] {
    const minScore = EVENT_PRIORITY_SCORES[minPriority];
    return this.buffer.filter((e) => EVENT_PRIORITY_SCORES[e.priority] >= minScore);
  }

  /**
   * 時間範囲でイベントをフィルタリング
   * @param startTime 開始時刻（ミリ秒）
   * @param endTime 終了時刻（ミリ秒）
   * @returns フィルタリングされたイベント
   */
  getEventsByTimeRange(startTime: number, endTime: number): BPFEvent[] {
    return this.buffer.filter((e) => e.timestamp >= startTime && e.timestamp <= endTime);
  }

  /**
   * システムコール別にイベントをグループ化
   * @returns システムコール別のイベント数
   */
  getEventsBySyscall(): Record<string, number> {
    const result: Record<string, number> = {};

    for (const event of this.buffer) {
      result[event.syscall] = (result[event.syscall] || 0) + 1;
    }

    return result;
  }

  /**
   * Event Storming 攻撃を検知
   * @returns 攻撃が検知された場合 true
   */
  detectEventStorming(): boolean {
    // 1. 秒間イベント数が異常に多い
    const now = Date.now();
    const oneSecondAgo = now - 1000;
    const recentEvents = this.buffer.filter((e) => e.timestamp > oneSecondAgo);

    if (recentEvents.length > this.anomalyThresholds.eventsPerSecond) {
      return true;
    }

    // 2. 疑わしいシステムコールが大量に発生
    const suspiciousCount = recentEvents.filter((e) =>
      SUSPICIOUS_SYSCALLS.includes(e.syscall)
    ).length;

    if (recentEvents.length > 0) {
      const suspiciousRatio = suspiciousCount / recentEvents.length;
      if (suspiciousRatio > this.anomalyThresholds.suspiciousEventRatio) {
        return true;
      }
    }

    // 3. バッファが満杯に近い
    if (this.stats.usagePercentage > 90) {
      return true;
    }

    return false;
  }

  /**
   * 異常閾値を設定
   * @param thresholds 新しい閾値
   */
  setAnomalyThresholds(
    thresholds: Partial<typeof this.anomalyThresholds>
  ): void {
    this.anomalyThresholds = { ...this.anomalyThresholds, ...thresholds };
  }

  /**
   * バッファサイズを取得
   * @returns バッファ内のイベント数
   */
  size(): number {
    return this.buffer.length;
  }
}

/**
 * グローバル eBPF リングバッファマネージャー インスタンス
 */
export const ebpfRingBufferManager = new EBPFRingBufferManager(256); // 256 MB
