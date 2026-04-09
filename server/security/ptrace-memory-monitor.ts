/**
 * ptrace 制限・メモリアクセス監視モジュール
 * メモリハイジャック攻撃（段階3）から守る
 * 
 * 攻撃者が /proc/[pid]/mem を使用してメモリを直接吸い出そうとしても、
 * システムは即座に検知・ブロックする。
 */

export interface MemoryAccessAttempt {
  sourceUid: number;
  targetPid: number;
  targetUid: number;
  operation: "ptrace" | "mem_read" | "mem_write" | "process_vm_read" | "process_vm_write";
  timestamp: number;
  allowed: boolean;
  reason?: string;
}

export interface PtraceMonitorStats {
  totalAttempts: number;
  blockedAttempts: number;
  allowedAttempts: number;
  suspiciousPatterns: string[];
  whitelistedProcesses: Set<string>;
}

/**
 * 信頼できるプロセス（ptrace を許可）
 */
const TRUSTED_PROCESSES = new Set([
  "gdb",
  "strace",
  "ltrace",
  "valgrind",
  "debugger",
  "systemd-debugger",
  "lldb",
  "rr",
]);

/**
 * ptrace 制限・メモリアクセス監視
 */
export class PtraceMemoryMonitor {
  private attempts: MemoryAccessAttempt[] = [];
  private stats: PtraceMonitorStats = {
    totalAttempts: 0,
    blockedAttempts: 0,
    allowedAttempts: 0,
    suspiciousPatterns: [],
    whitelistedProcesses: new Set(TRUSTED_PROCESSES),
  };

  /**
   * ptrace アクセスを検証
   * @param sourceUid ソースプロセスの UID
   * @param targetPid ターゲットプロセスの PID
   * @param targetUid ターゲットプロセスの UID
   * @param operation 操作種別
   * @returns アクセス許可時 true
   */
  validatePtraceAccess(
    sourceUid: number,
    targetPid: number,
    targetUid: number,
    operation: MemoryAccessAttempt["operation"]
  ): boolean {
    const timestamp = Date.now();

    // 1. UID チェック（同じユーザーのプロセスのみ ptrace 可能）
    if (sourceUid !== targetUid && sourceUid !== 0) {
      const attempt: MemoryAccessAttempt = {
        sourceUid,
        targetPid,
        targetUid,
        operation,
        timestamp,
        allowed: false,
        reason: "UID mismatch: ptrace only allowed for same user or root",
      };

      this.recordAttempt(attempt);
      return false;
    }

    // 2. 特殊な操作チェック（mem_read/mem_write は特に危騎）
    if (operation === "mem_read" || operation === "mem_write") {
      // mem_read/mem_write は root のみ許可
      if (sourceUid !== 0) {
        const attempt: MemoryAccessAttempt = {
          sourceUid,
          targetPid,
          targetUid,
          operation,
          timestamp,
          allowed: false,
          reason: "Blocked: mem_read/mem_write requires root privileges",
        };

        this.recordAttempt(attempt);
        return false;
      }

      // root ユーザーのプロセスへのアクセスはブロック
      if (targetUid === 0) {
        const attempt: MemoryAccessAttempt = {
          sourceUid,
          targetPid,
          targetUid,
          operation,
          timestamp,
          allowed: false,
          reason: "Blocked: Cannot access memory of root process",
        };

        this.recordAttempt(attempt);
        return false;
      }

      // 疑わしいプロセスへのアクセスをブロック
      if (this.isSuspiciousProcess(targetPid)) {
        const attempt: MemoryAccessAttempt = {
          sourceUid,
          targetPid,
          targetUid,
          operation,
          timestamp,
          allowed: false,
          reason: "Blocked: Suspicious process memory access",
        };

        this.recordAttempt(attempt);
        return false;
      }
    }

    // 3. process_vm_read/write は特に制限
    if (
      operation === "process_vm_read" ||
      operation === "process_vm_write"
    ) {
      // root のみ許可
      if (sourceUid !== 0) {
        const attempt: MemoryAccessAttempt = {
          sourceUid,
          targetPid,
          targetUid,
          operation,
          timestamp,
          allowed: false,
          reason: "Blocked: process_vm_* requires root privileges",
        };

        this.recordAttempt(attempt);
        return false;
      }
    }

    // 4. 許可
    const attempt: MemoryAccessAttempt = {
      sourceUid,
      targetPid,
      targetUid,
      operation,
      timestamp,
      allowed: true,
    };

    this.recordAttempt(attempt);
    return true;
  }

  /**
   * /proc/[pid]/mem アクセスを検証
   * @param sourceUid ソースプロセスの UID
   * @param targetPid ターゲットプロセスの PID
   * @param targetUid ターゲットプロセスの UID
   * @returns アクセス許可時 true
   */
  validateMemFileAccess(
    sourceUid: number,
    targetPid: number,
    targetUid: number
  ): boolean {
    const timestamp = Date.now();

    // /proc/[pid]/mem は非常に危険なので、root のみ許可
    if (sourceUid !== 0) {
      const attempt: MemoryAccessAttempt = {
        sourceUid,
        targetPid,
        targetUid,
        operation: "mem_read",
        timestamp,
        allowed: false,
        reason: "Blocked: /proc/[pid]/mem requires root privileges",
      };

      this.recordAttempt(attempt);
      return false;
    }

    // root でも疑わしいプロセスへのアクセスはブロック
    if (this.isSuspiciousProcess(targetPid)) {
      const attempt: MemoryAccessAttempt = {
        sourceUid,
        targetPid,
        targetUid,
        operation: "mem_read",
        timestamp,
        allowed: false,
        reason: "Blocked: Suspicious process memory access",
      };

      this.recordAttempt(attempt);
      return false;
    }

    const attempt: MemoryAccessAttempt = {
      sourceUid,
      targetPid,
      targetUid,
      operation: "mem_read",
      timestamp,
      allowed: true,
    };

    this.recordAttempt(attempt);
    return true;
  }

  /**
   * 疑わしいプロセスかどうかを判定
   * @param pid プロセス ID
   * @returns 疑わしい場合 true
   */
  private isSuspiciousProcess(pid: number): boolean {
    // システムプロセス（PID < 1000）へのアクセスは疑わしい
    if (pid < 1000) {
      return true;
    }

    // 今後、プロセス名やシグネチャベースの検査を追加可能
    return false;
  }

  /**
   * アクセス試行を記録
   * @param attempt アクセス試行
   */
  private recordAttempt(attempt: MemoryAccessAttempt): void {
    this.attempts.push(attempt);
    this.stats.totalAttempts++;

    if (attempt.allowed) {
      this.stats.allowedAttempts++;
    } else {
      this.stats.blockedAttempts++;

      // 疑わしいパターンを検知
      if (attempt.reason) {
        this.detectSuspiciousPatterns(attempt);
      }
    }
  }

  /**
   * 疑わしいパターンを検知
   * @param attempt アクセス試行
   */
  private detectSuspiciousPatterns(attempt: MemoryAccessAttempt): void {
    // 1. 同じソースから複数のターゲットへのアクセス試行
    const sameSourceAttempts = this.attempts.filter(
      (a) => a.sourceUid === attempt.sourceUid && !a.allowed
    );

    if (sameSourceAttempts.length > 5) {
      const pattern = `Multiple blocked ptrace attempts from UID ${attempt.sourceUid}`;
      if (!this.stats.suspiciousPatterns.includes(pattern)) {
        this.stats.suspiciousPatterns.push(pattern);
      }
    }

    // 2. mem_read/mem_write の集中的な試行
    const memAccessAttempts = this.attempts.filter(
      (a) =>
        (a.operation === "mem_read" || a.operation === "mem_write") &&
        !a.allowed
    );

    if (memAccessAttempts.length > 10) {
      const pattern = "High frequency memory access attempts detected";
      if (!this.stats.suspiciousPatterns.includes(pattern)) {
        this.stats.suspiciousPatterns.push(pattern);
      }
    }

    // 3. root プロセスへのアクセス試行
    if (attempt.targetUid === 0 && !attempt.allowed) {
      const pattern = `Attempt to access root process memory (PID ${attempt.targetPid})`;
      if (!this.stats.suspiciousPatterns.includes(pattern)) {
        this.stats.suspiciousPatterns.push(pattern);
      }
    }
  }

  /**
   * 統計情報を取得
   * @returns 監視統計
   */
  getStats(): PtraceMonitorStats {
    return { ...this.stats };
  }

  /**
   * ホワイトリストにプロセスを追加
   * @param processName プロセス名
   */
  addWhitelistedProcess(processName: string): void {
    this.stats.whitelistedProcesses.add(processName);
  }

  /**
   * ホワイトリストからプロセスを削除
   * @param processName プロセス名
   */
  removeWhitelistedProcess(processName: string): void {
    this.stats.whitelistedProcesses.delete(processName);
  }

  /**
   * ホワイトリストをクリア
   */
  clearWhitelist(): void {
    this.stats.whitelistedProcesses.clear();
    // デフォルトのプロセスを再追加
    TRUSTED_PROCESSES.forEach((proc) => {
      this.stats.whitelistedProcesses.add(proc);
    });
  }

  /**
   * メモリハイジャック攻撃を検知
   * @returns 攻撃が検知された場合 true
   */
  detectMemoryHijackingAttack(): boolean {
    // 1. 複数のプロセスへの集中的なメモリアクセス試行
    const blockedMemAttempts = this.attempts.filter(
      (a) =>
        (a.operation === "mem_read" || a.operation === "mem_write") &&
        !a.allowed
    );

    if (blockedMemAttempts.length > 10) {
      return true;
    }

    // 2. /proc/[pid]/mem へのアクセス試行が複数回
    const procMemAttempts = this.attempts.filter(
      (a) => a.operation === "mem_read" && !a.allowed
    );

    if (procMemAttempts.length > 5) {
      return true;
    }

    // 3. root プロセスへのアクセス試行
    const rootAccessAttempts = this.attempts.filter(
      (a) => a.targetUid === 0 && !a.allowed
    );

    if (rootAccessAttempts.length > 3) {
      return true;
    }

    return false;
  }

  /**
   * 最近のアクセス試行を取得
   * @param limit 取得件数
   * @returns 最近のアクセス試行
   */
  getRecentAttempts(limit: number = 100): MemoryAccessAttempt[] {
    return this.attempts.slice(-limit);
  }

  /**
   * ブロックされたアクセス試行を取得
   * @returns ブロックされたアクセス試行
   */
  getBlockedAttempts(): MemoryAccessAttempt[] {
    return this.attempts.filter((a) => !a.allowed);
  }

  /**
   * 統計をリセット
   */
  resetStats(): void {
    this.attempts = [];
    this.stats = {
      totalAttempts: 0,
      blockedAttempts: 0,
      allowedAttempts: 0,
      suspiciousPatterns: [],
      whitelistedProcesses: new Set(TRUSTED_PROCESSES),
    };
  }
}

/**
 * グローバル ptrace・メモリアクセス監視インスタンス
 */
export const ptraceMemoryMonitor = new PtraceMemoryMonitor();
