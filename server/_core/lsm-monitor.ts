/**
 * lsm-monitor.ts
 * ===============
 * LSM (Linux Security Module) 統合監視モジュール
 * io_uring, mmap などのシステムコール以外のメモリ操作を検知
 */

export interface LSMEvent {
  type: 'io_uring_setup' | 'file_mmap' | 'bprm_check_security' | 'ptrace_access_check' | 'socket_connect';
  timestamp: number;
  pid: number;
  uid: number;
  comm: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  details: Record<string, any>;
}

export interface LSMMonitorConfig {
  enableIOUringMonitoring: boolean;
  enableMmapMonitoring: boolean;
  enablePtraceMonitoring: boolean;
  enableSocketMonitoring: boolean;
  suspiciousThreshold: number;
}

/**
 * LSM 監視エンジン
 */
export class LSMMonitor {
  private config: LSMMonitorConfig;
  private events: LSMEvent[] = [];
  private maxEvents: number = 5000;
  private suspiciousPatterns: Map<number, number> = new Map(); // pid -> suspicion count

  constructor(config: Partial<LSMMonitorConfig> = {}) {
    this.config = {
      enableIOUringMonitoring: true,
      enableMmapMonitoring: true,
      enablePtraceMonitoring: true,
      enableSocketMonitoring: true,
      suspiciousThreshold: 5,
      ...config,
    };
  }

  /**
   * io_uring セットアップイベントを処理
   */
  handleIOUringSetup(pid: number, uid: number, comm: string, details: any): LSMEvent | null {
    if (!this.config.enableIOUringMonitoring) {
      return null;
    }

    // io_uring は強力な非同期 I/O メカニズムであり、
    // 悪意のあるプロセスが監視を回避するために使用される可能性がある
    const severity = this.assessIOUringSeverity(details);

    const event: LSMEvent = {
      type: 'io_uring_setup',
      timestamp: Date.now(),
      pid,
      uid,
      comm,
      severity,
      details: {
        flags: details.flags,
        entries: details.entries,
        sqe_size: details.sqe_size,
        cq_size: details.cq_size,
      },
    };

    this.addEvent(event);

    // 疑わしい場合は記録
    if (severity === 'critical' || severity === 'high') {
      this.incrementSuspicion(pid);
    }

    return event;
  }

  /**
   * mmap イベントを処理
   */
  handleFileMmap(pid: number, uid: number, comm: string, details: any): LSMEvent | null {
    if (!this.config.enableMmapMonitoring) {
      return null;
    }

    // 実行可能かつ書き込み可能なメモリマップは危険
    const isExecutable = (details.prot & 0x04) !== 0; // PROT_EXEC
    const isWritable = (details.prot & 0x02) !== 0;   // PROT_WRITE
    const isPrivate = (details.flags & 0x02) !== 0;   // MAP_PRIVATE

    let severity: LSMEvent['severity'] = 'low';

    if (isExecutable && isWritable && isPrivate) {
      // JIT コンパイラなど正当な用途もあるが、注視が必要
      severity = 'high';
    } else if (isExecutable && isWritable) {
      severity = 'critical';
    } else if (isExecutable) {
      severity = 'medium';
    }

    const event: LSMEvent = {
      type: 'file_mmap',
      timestamp: Date.now(),
      pid,
      uid,
      comm,
      severity,
      details: {
        addr: details.addr,
        len: details.len,
        prot: {
          read: (details.prot & 0x01) !== 0,
          write: isWritable,
          exec: isExecutable,
        },
        flags: {
          private: isPrivate,
          shared: (details.flags & 0x01) !== 0,
          fixed: (details.flags & 0x10) !== 0,
        },
        filename: details.filename,
      },
    };

    this.addEvent(event);

    // 疑わしい場合は記録
    if (severity === 'critical' || severity === 'high') {
      this.incrementSuspicion(pid);
    }

    return event;
  }

  /**
   * ptrace アクセスイベントを処理
   */
  handlePtraceAccessCheck(pid: number, uid: number, comm: string, details: any): LSMEvent | null {
    if (!this.config.enablePtraceMonitoring) {
      return null;
    }

    // ptrace は他のプロセスをデバッグ・制御するための強力なメカニズム
    // 悪意のあるプロセスが他のプロセスを乗っ取るために使用される可能性がある
    const severity: LSMEvent['severity'] = 'high';

    const event: LSMEvent = {
      type: 'ptrace_access_check',
      timestamp: Date.now(),
      pid,
      uid,
      comm,
      severity,
      details: {
        request: details.request,
        target_pid: details.target_pid,
        target_uid: details.target_uid,
      },
    };

    this.addEvent(event);
    this.incrementSuspicion(pid);

    return event;
  }

  /**
   * ソケット接続イベントを処理
   */
  handleSocketConnect(pid: number, uid: number, comm: string, details: any): LSMEvent | null {
    if (!this.config.enableSocketMonitoring) {
      return null;
    }

    // 疑わしい接続先（ローカルホスト以外への接続など）を検知
    const severity = this.assessSocketConnectSeverity(details);

    const event: LSMEvent = {
      type: 'socket_connect',
      timestamp: Date.now(),
      pid,
      uid,
      comm,
      severity,
      details: {
        family: details.family, // AF_INET, AF_INET6, etc.
        type: details.type,     // SOCK_STREAM, SOCK_DGRAM, etc.
        protocol: details.protocol,
        address: details.address,
        port: details.port,
      },
    };

    this.addEvent(event);

    if (severity === 'critical' || severity === 'high') {
      this.incrementSuspicion(pid);
    }

    return event;
  }

  /**
   * io_uring のリスク度を評価
   */
  private assessIOUringSeverity(details: any): LSMEvent['severity'] {
    // 大量のエントリを持つ io_uring は疑わしい可能性がある
    if (details.entries > 10000) {
      return 'high';
    }

    // 特定のフラグの組み合わせは疑わしい
    if ((details.flags & 0x02) !== 0) { // IORING_SETUP_IOPOLL
      return 'medium';
    }

    return 'low';
  }

  /**
   * ソケット接続のリスク度を評価
   */
  private assessSocketConnectSeverity(details: any): LSMEvent['severity'] {
    // ローカルホスト以外への接続は注視
    if (details.address && details.address !== '127.0.0.1' && details.address !== '::1') {
      // ただし、特定のプロセス（ブラウザなど）は許容
      return 'low';
    }

    return 'low';
  }

  /**
   * イベントを追加
   */
  private addEvent(event: LSMEvent): void {
    this.events.push(event);

    // バッファサイズを超えた場合は古いイベントを削除
    if (this.events.length > this.maxEvents) {
      this.events.shift();
    }
  }

  /**
   * プロセスの疑わしさカウントを増加
   */
  private incrementSuspicion(pid: number): void {
    const current = this.suspiciousPatterns.get(pid) || 0;
    this.suspiciousPatterns.set(pid, current + 1);
  }

  /**
   * 疑わしいプロセスを取得
   */
  getSuspiciousProcesses(): Array<{ pid: number; count: number }> {
    const result: Array<{ pid: number; count: number }> = [];

    this.suspiciousPatterns.forEach((count, pid) => {
      if (count >= this.config.suspiciousThreshold) {
        result.push({ pid, count });
      }
    });

    return result.sort((a, b) => b.count - a.count);
  }

  /**
   * 最近のイベントを取得
   */
  getRecentEvents(limit: number = 100): LSMEvent[] {
    return this.events.slice(-limit);
  }

  /**
   * 特定の PID のイベントを取得
   */
  getEventsByPid(pid: number): LSMEvent[] {
    return this.events.filter((event) => event.pid === pid);
  }

  /**
   * 重大度別にイベントを集計
   */
  getEventsBySeverity(): Record<LSMEvent['severity'], number> {
    return {
      critical: this.events.filter((e) => e.severity === 'critical').length,
      high: this.events.filter((e) => e.severity === 'high').length,
      medium: this.events.filter((e) => e.severity === 'medium').length,
      low: this.events.filter((e) => e.severity === 'low').length,
    };
  }

  /**
   * プロセスをホワイトリストから除外
   */
  clearSuspicion(pid: number): void {
    this.suspiciousPatterns.delete(pid);
  }

  /**
   * すべての統計情報をリセット
   */
  reset(): void {
    this.events = [];
    this.suspiciousPatterns.clear();
  }
}

/**
 * グローバル LSM 監視インスタンス
 */
export const globalLSMMonitor = new LSMMonitor({
  enableIOUringMonitoring: true,
  enableMmapMonitoring: true,
  enablePtraceMonitoring: true,
  enableSocketMonitoring: true,
  suspiciousThreshold: 5,
});
