/**
 * advanced-threat-detector.ts
 * ============================
 * LSM 監視と DNS トンネリング検知を統合した高度な脅威検知エンジン
 */

import { globalLSMMonitor, type LSMEvent } from './lsm-monitor';
import { globalDNSTunnelDetector, type DNSQuery, type DNSAnomalyScore } from './dns-tunnel-detector';
import { EventEmitter } from 'events';

export interface AdvancedThreatAlert {
  id: string;
  timestamp: number;
  type: 'lsm_anomaly' | 'dns_tunnel' | 'combined';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  details: {
    lsmEvents?: LSMEvent[];
    dnsQueries?: DNSQuery[];
    anomalyScores?: DNSAnomalyScore[];
  };
  recommendedAction: string;
}

/**
 * 高度な脅威検知エンジン
 */
export class AdvancedThreatDetector extends EventEmitter {
  private alerts: AdvancedThreatAlert[] = [];
  private maxAlerts: number = 5000;
  private correlationWindow: number = 60000; // 1 minute

  constructor() {
    super();
  }

  /**
   * LSM イベントから脅威を検知
   */
  detectLSMThreats(): AdvancedThreatAlert[] {
    const alerts: AdvancedThreatAlert[] = [];
    const suspiciousProcesses = globalLSMMonitor.getSuspiciousProcesses();

    for (const process of suspiciousProcesses) {
      const events = globalLSMMonitor.getEventsByPid(process.pid);
      const severity = this.assessLSMSeverity(events);

      const alert: AdvancedThreatAlert = {
        id: `lsm-${process.pid}-${Date.now()}`,
        timestamp: Date.now(),
        type: 'lsm_anomaly',
        severity,
        description: `Suspicious LSM activity detected for PID ${process.pid} (${process.count} anomalies)`,
        details: {
          lsmEvents: events.slice(-10), // 最新 10 件
        },
        recommendedAction: this.getRecommendedActionForLSM(severity, process.pid),
      };

      alerts.push(alert);
      this.addAlert(alert);
    }

    return alerts;
  }

  /**
   * DNS トンネリングから脅威を検知
   */
  detectDNSTunnels(): AdvancedThreatAlert[] {
    const alerts: AdvancedThreatAlert[] = [];
    const anomalousQueries = globalDNSTunnelDetector.getAnomalousQueries();

    // クライアント別に集計
    const clientAnomalies: Map<string, Array<{ query: DNSQuery; score: DNSAnomalyScore }>> = new Map();

    for (const { query, score } of anomalousQueries) {
      const clientId = query.clientId || `${query.sourceIp}:${query.sourcePort}`;
      if (!clientAnomalies.has(clientId)) {
        clientAnomalies.set(clientId, []);
      }
      clientAnomalies.get(clientId)!.push({ query, score });
    }

    // クライアント別に集計
    clientAnomalies.forEach((queries, clientId) => {
      if (queries.length > 5) {
        // 5 件以上の異常クエリがある場合はアラート
        const alert: AdvancedThreatAlert = {
          id: `dns-${clientId}-${Date.now()}`,
          timestamp: Date.now(),
          type: 'dns_tunnel',
          severity: this.assessDNSTunnelSeverity(queries),
          description: `Possible DNS tunneling detected from ${clientId} (${queries.length} anomalous queries)`,
          details: {
            dnsQueries: queries.map((q: any) => q.query).slice(-10),
            anomalyScores: queries.map((q: any) => q.score).slice(-10),
          },
          recommendedAction: this.getRecommendedActionForDNSTunnel(queries.length),
        };

        alerts.push(alert);
        this.addAlert(alert);
      }
    });

    return alerts;
  }

  /**
   * LSM と DNS 脅威を相関分析
   */
  detectCorrelatedThreats(): AdvancedThreatAlert[] {
    const alerts: AdvancedThreatAlert[] = [];
    const now = Date.now();

    // 最近の LSM イベントを取得
    const recentLSMEvents = globalLSMMonitor.getRecentEvents(100);
    const recentDNSQueries = globalDNSTunnelDetector.getRecentQueries(100);
    const dnsAnomalousQueries = globalDNSTunnelDetector.getAnomalousQueries();

    // 時間窓内で相関するイベントを探す
    for (const lsmEvent of recentLSMEvents) {
      if (now - lsmEvent.timestamp > this.correlationWindow) {
        continue;
      }

      // 同じ PID からの DNS クエリを探す
      const correlatedDNS = recentDNSQueries.filter(
        (q) => now - q.timestamp <= this.correlationWindow
      );

      if (correlatedDNS.length > 0 && lsmEvent.severity === 'critical') {
        const alert: AdvancedThreatAlert = {
          id: `corr-${lsmEvent.pid}-${Date.now()}`,
          timestamp: Date.now(),
          type: 'combined',
          severity: 'critical',
          description: `CRITICAL: Correlated LSM and DNS tunnel activity detected. PID ${lsmEvent.pid} showing suspicious system activity combined with DNS tunneling.`,
          details: {
            lsmEvents: [lsmEvent],
            dnsQueries: correlatedDNS.slice(0, 5),
          },
          recommendedAction: 'IMMEDIATE ACTION: Isolate process and investigate for data exfiltration',
        };

        alerts.push(alert);
        this.addAlert(alert);
      }
    }

    return alerts;
  }

  /**
   * LSM イベントの重大度を評価
   */
  private assessLSMSeverity(events: LSMEvent[]): AdvancedThreatAlert['severity'] {
    const criticalCount = events.filter((e) => e.severity === 'critical').length;
    const highCount = events.filter((e) => e.severity === 'high').length;

    if (criticalCount > 0) {
      return 'critical';
    } else if (highCount > 2) {
      return 'high';
    } else if (highCount > 0) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * DNS トンネリングの重大度を評価
   */
  private assessDNSTunnelSeverity(
    queries: Array<{ query: DNSQuery; score: DNSAnomalyScore }>
  ): AdvancedThreatAlert['severity'] {
    const avgScore = queries.reduce((sum, q) => sum + q.score.totalScore, 0) / queries.length;

    if (avgScore > 0.9) {
      return 'critical';
    } else if (avgScore > 0.8) {
      return 'high';
    } else if (avgScore > 0.7) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * LSM 脅威に対する推奨アクション
   */
  private getRecommendedActionForLSM(severity: AdvancedThreatAlert['severity'], pid: number): string {
    switch (severity) {
      case 'critical':
        return `CRITICAL: Kill process ${pid} immediately and investigate for privilege escalation`;
      case 'high':
        return `HIGH: Monitor process ${pid} closely and prepare for isolation`;
      case 'medium':
        return `MEDIUM: Log and monitor process ${pid} for further suspicious activity`;
      default:
        return `LOW: Monitor process ${pid}`;
    }
  }

  /**
   * DNS トンネリングに対する推奨アクション
   */
  private getRecommendedActionForDNSTunnel(queryCount: number): string {
    if (queryCount > 100) {
      return 'CRITICAL: Block DNS queries from this client and investigate for data exfiltration';
    } else if (queryCount > 50) {
      return 'HIGH: Rate-limit DNS queries and monitor for data exfiltration';
    } else if (queryCount > 10) {
      return 'MEDIUM: Log DNS queries and investigate for tunneling';
    }

    return 'LOW: Monitor DNS activity';
  }

  /**
   * アラートを追加
   */
  private addAlert(alert: AdvancedThreatAlert): void {
    this.alerts.push(alert);

    // バッファサイズを超えた場合は古いアラートを削除
    if (this.alerts.length > this.maxAlerts) {
      this.alerts.shift();
    }

    // アラートイベントを発行
    this.emit('alert', alert);
  }

  /**
   * 最近のアラートを取得
   */
  getRecentAlerts(limit: number = 100): AdvancedThreatAlert[] {
    return this.alerts.slice(-limit);
  }

  /**
   * 重大度別にアラートを集計
   */
  getAlertsBySeverity(): Record<AdvancedThreatAlert['severity'], number> {
    return {
      critical: this.alerts.filter((a) => a.severity === 'critical').length,
      high: this.alerts.filter((a) => a.severity === 'high').length,
      medium: this.alerts.filter((a) => a.severity === 'medium').length,
      low: this.alerts.filter((a) => a.severity === 'low').length,
    };
  }

  /**
   * 統計情報を取得
   */
  getStatistics() {
    return {
      totalAlerts: this.alerts.length,
      alertsBySeverity: this.getAlertsBySeverity(),
      lsmStatistics: {
        suspiciousProcesses: globalLSMMonitor.getSuspiciousProcesses(),
        eventsBySeverity: globalLSMMonitor.getEventsBySeverity(),
      },
      dnsStatistics: {
        clientStatistics: globalDNSTunnelDetector.getClientStatistics(),
        domainStatistics: globalDNSTunnelDetector.getDomainStatistics().slice(0, 20),
      },
    };
  }
}

/**
 * グローバル高度な脅威検知インスタンス
 */
export const globalAdvancedThreatDetector = new AdvancedThreatDetector();
