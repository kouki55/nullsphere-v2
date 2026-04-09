/**
 * io_uring 監視・ブロックモジュール
 * 攻撃段階2（io_uring 悪用による openat 迂回）から守る
 * 
 * io_uring は非同期 I/O 機能で、ユーザー空間からカーネルのワークキューに
 * 「これ読んでおいて」と依頼を渡す。従来の openat などのシステムコールが発生しないため、
 * eBPF フックが反応しない。
 * 
 * 対策：
 * 1. io_uring_setup syscall を監視
 * 2. io_uring_enter syscall を監視
 * 3. 疑わしい io_uring 操作をブロック
 * 4. 操作ログを記録
 */

export interface IoUringOperation {
  pid: number;
  comm: string;
  syscall: "io_uring_setup" | "io_uring_enter" | "io_uring_register";
  timestamp: number;
  flags?: number;
  entries?: number;
  minComplete?: number;
  minWait?: number;
  sigMask?: number;
}

export interface IoUringPolicy {
  allowedPids?: number[];
  allowedComms?: string[];
  maxEntriesPerSetup?: number;
  blockSuspiciousFlags?: boolean;
  maxOperationsPerSecond?: number;
}

/**
 * デフォルトの io_uring ポリシー
 * セキュリティ重視の設定
 */
const DEFAULT_POLICY: IoUringPolicy = {
  allowedComms: [
    "systemd",
    "kernel",
    "nullsphere",
    "postgres",
    "mysql",
    "redis",
    // 信頼できるシステムプロセスのみ
  ],
  maxEntriesPerSetup: 4096, // 大量の io_uring エントリは疑わしい
  blockSuspiciousFlags: true,
  maxOperationsPerSecond: 1000, // DoS 対策
};

/**
 * io_uring フラグの定義
 */
const IO_URING_SETUP_FLAGS = {
  IORING_SETUP_IOPOLL: 1 << 0, // I/O ポーリング（高負荷）
  IORING_SETUP_SQPOLL: 1 << 1, // SQ ポーリング（高負荷）
  IORING_SETUP_SQ_AFF: 1 << 2, // SQ CPU アフィニティ
  IORING_SETUP_CQSIZE: 1 << 3, // CQ サイズ指定
  IORING_SETUP_CLAMP: 1 << 4, // クランプモード
  IORING_SETUP_ATTACH_WQ: 1 << 5, // ワークキュー接続
  IORING_SETUP_R_DISABLED: 1 << 6, // リング無効化
  IORING_SETUP_SUBMIT_ALL: 1 << 7, // 全提出
  IORING_SETUP_COOP_TASKRUN: 1 << 8, // 協調タスク実行
  IORING_SETUP_TASKRUN_FLAG: 1 << 9, // タスク実行フラグ
};

/**
 * 疑わしいフラグの組み合わせ
 */
const SUSPICIOUS_FLAG_COMBINATIONS = [
  { flags: [IO_URING_SETUP_FLAGS.IORING_SETUP_IOPOLL, IO_URING_SETUP_FLAGS.IORING_SETUP_SQPOLL], reason: "Both IOPOLL and SQPOLL enabled" },
  { flags: [IO_URING_SETUP_FLAGS.IORING_SETUP_ATTACH_WQ], reason: "Workqueue attachment" },
];

/**
 * io_uring 操作の監視・検証
 */
export class IoUringMonitor {
  private policy: IoUringPolicy;
  private operationLog: Map<number, IoUringOperation[]> = new Map();
  private blockedPids: Set<number> = new Set();

  constructor(policy?: Partial<IoUringPolicy>) {
    this.policy = { ...DEFAULT_POLICY, ...policy };
  }

  /**
   * io_uring_setup syscall を検証
   * @param operation io_uring 操作
   * @returns { allowed: boolean, reason?: string }
   */
  validateSetup(operation: IoUringOperation): { allowed: boolean; reason?: string } {
    // 1. ブロック済み PID をチェック
    if (this.blockedPids.has(operation.pid)) {
      return { allowed: false, reason: "PID is blocked" };
    }

    // 2. ホワイトリスト確認
    if (this.policy.allowedComms && !this.policy.allowedComms.includes(operation.comm)) {
      return { allowed: false, reason: `Process not in whitelist: ${operation.comm}` };
    }

    // 3. エントリ数チェック
    if (operation.entries && this.policy.maxEntriesPerSetup) {
      if (operation.entries > this.policy.maxEntriesPerSetup) {
        return {
          allowed: false,
          reason: `Too many entries: ${operation.entries} > ${this.policy.maxEntriesPerSetup}`,
        };
      }
    }

    // 4. フラグチェック
    if (this.policy.blockSuspiciousFlags && operation.flags) {
      const flagIssue = this.checkSuspiciousFlags(operation.flags);
      if (flagIssue) {
        return { allowed: false, reason: flagIssue };
      }
    }

    return { allowed: true };
  }

  /**
   * io_uring_enter syscall を検証
   * @param operation io_uring 操作
   * @returns { allowed: boolean, reason?: string }
   */
  validateEnter(operation: IoUringOperation): { allowed: boolean; reason?: string } {
    // 1. ブロック済み PID をチェック
    if (this.blockedPids.has(operation.pid)) {
      return { allowed: false, reason: "PID is blocked" };
    }

    // 2. レート制限チェック
    const rateCheck = this.checkRateLimit(operation.pid);
    if (!rateCheck.allowed) {
      return rateCheck;
    }

    // 3. 操作ログに記録
    this.logOperation(operation);

    return { allowed: true };
  }

  /**
   * 疑わしいフラグの組み合わせをチェック
   * @param flags フラグビット
   * @returns 疑わしい場合は理由、そうでなければ null
   */
  private checkSuspiciousFlags(flags: number): string | null {
    for (const combo of SUSPICIOUS_FLAG_COMBINATIONS) {
      const allFlagsSet = combo.flags.every((flag) => (flags & flag) !== 0);
      if (allFlagsSet) {
        return `Suspicious flags: ${combo.reason}`;
      }
    }

    // IOPOLL と SQPOLL は高負荷を引き起こす可能性
    if ((flags & IO_URING_SETUP_FLAGS.IORING_SETUP_IOPOLL) !== 0) {
      return "IOPOLL flag detected (high CPU usage)";
    }

    if ((flags & IO_URING_SETUP_FLAGS.IORING_SETUP_SQPOLL) !== 0) {
      return "SQPOLL flag detected (high CPU usage)";
    }

    return null;
  }

  /**
   * レート制限をチェック
   * @param pid プロセス ID
   * @returns { allowed: boolean, reason?: string }
   */
  private checkRateLimit(pid: number): { allowed: boolean; reason?: string } {
    if (!this.policy.maxOperationsPerSecond) {
      return { allowed: true };
    }

    const now = Date.now();
    const oneSecondAgo = now - 1000;

    // 操作ログを取得
    const operations = this.operationLog.get(pid) || [];

    // 1 秒以内の操作をカウント
    const recentOps = operations.filter((op) => op.timestamp > oneSecondAgo);

    if (recentOps.length >= this.policy.maxOperationsPerSecond) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: ${recentOps.length} operations in 1 second`,
      };
    }

    return { allowed: true };
  }

  /**
   * 操作をログに記録
   * @param operation io_uring 操作
   */
  private logOperation(operation: IoUringOperation): void {
    if (!this.operationLog.has(operation.pid)) {
      this.operationLog.set(operation.pid, []);
    }

    const operations = this.operationLog.get(operation.pid)!;
    operations.push(operation);

    // 古いエントリを削除（メモリ節約）
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    const filtered = operations.filter((op) => op.timestamp > oneHourAgo);
    this.operationLog.set(operation.pid, filtered);
  }

  /**
   * PID をブロック
   * @param pid プロセス ID
   * @param reason ブロック理由
   */
  blockPid(pid: number, reason: string): void {
    this.blockedPids.add(pid);
    console.warn(`[IoUringMonitor] Blocked PID ${pid}: ${reason}`);
  }

  /**
   * PID のブロックを解除
   * @param pid プロセス ID
   */
  unblockPid(pid: number): void {
    this.blockedPids.delete(pid);
    console.log(`[IoUringMonitor] Unblocked PID ${pid}`);
  }

  /**
   * ブロック済み PID を取得
   * @returns ブロック済み PID の配列
   */
  getBlockedPids(): number[] {
    return Array.from(this.blockedPids);
  }

  /**
   * 統計情報を取得
   * @returns 統計情報
   */
  getStats(): {
    totalOperations: number;
    blockedPids: number;
    monitoredPids: number;
  } {
    return {
      totalOperations: Array.from(this.operationLog.values()).reduce((sum, ops) => sum + ops.length, 0),
      blockedPids: this.blockedPids.size,
      monitoredPids: this.operationLog.size,
    };
  }
}

/**
 * グローバル io_uring モニター インスタンス
 */
export const ioUringMonitor = new IoUringMonitor();
