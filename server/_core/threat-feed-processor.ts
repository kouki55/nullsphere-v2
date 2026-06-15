/**
 * threat-feed-processor.ts
 * ========================
 * カーネルイベントを脅威フィード・イベントに変換するロジック
 */

import { nanoid } from 'nanoid';
import type { KernelEvent } from '../kernel-bridge';
import type { ThreatFeedEvent } from './types/threat-feed';

/**
 * カーネルイベントを脅威フィード・イベントに変換
 */
export function convertKernelEventToThreatFeed(
  kernelEvent: KernelEvent
): ThreatFeedEvent {
  const feedId = `feed-${nanoid()}`;
  const timestamp = new Date(kernelEvent.ts).toISOString();

  // 脅威タイプのマッピング
  const threatTypeMap: Record<string, ThreatFeedEvent['type']> = {
    exec: 'reconnaissance',
    file: 'data_exfiltration',
    net: 'lateral_movement',
    kill: 'privilege_escalation',
    module_load: 'malware',
    ptrace: 'intrusion',
  };

  // 深刻度のマッピング
  const severityMap: Record<number, ThreatFeedEvent['severity']> = {
    4: 'critical',
    3: 'high',
    2: 'medium',
    1: 'low',
    0: 'info',
  };

  const threatType = threatTypeMap[kernelEvent.type] || 'unknown';
  const severity = severityMap[kernelEvent.threat_level] || 'info';

  // 人間が読める脅威タイトルを生成
  const title = generateThreatTitle(threatType, kernelEvent);

  // 詳細なメッセージを生成
  const description = generateThreatDescription(kernelEvent, threatType);

  return {
    feedId,
    timestamp,
    type: threatType,
    severity,
    title,
    description,
    sourceIp: kernelEvent.net?.daddr || 'unknown',
    sourceCountry: undefined, // 後でジオロケーション情報で補充可能
    targetHost: kernelEvent.comm,
    targetPort: kernelEvent.net?.dport,
    command: kernelEvent.filename,
    status: 'detected',
    metadata: {
      pid: kernelEvent.pid,
      ppid: kernelEvent.ppid,
      uid: kernelEvent.uid,
      gid: kernelEvent.gid,
      inode: kernelEvent.inode,
      args: kernelEvent.args,
      containerId: kernelEvent.container_id,
      threatName: kernelEvent.threat_name,
      actionName: kernelEvent.action_name,
    },
  };
}

/**
 * 脅威タイトルを生成
 */
function generateThreatTitle(
  threatType: ThreatFeedEvent['type'],
  kernelEvent: KernelEvent
): string {
  const titleMap: Record<string, string> = {
    intrusion: `🔴 Intrusion Attempt Detected`,
    malware: `⚠️ Potential Malware Activity`,
    privilege_escalation: `🔒 Privilege Escalation Attempt`,
    data_exfiltration: `📤 Data Exfiltration Detected`,
    lateral_movement: `🔄 Lateral Movement Detected`,
    reconnaissance: `🔍 Reconnaissance Activity`,
    unknown: `❓ Unknown Threat Activity`,
  };

  return titleMap[threatType] || `Threat Detected: ${kernelEvent.threat_name}`;
}

/**
 * 詳細な脅威説明を生成
 */
function generateThreatDescription(
  kernelEvent: KernelEvent,
  threatType: ThreatFeedEvent['type']
): string {
  const parts: string[] = [];

  // 基本情報
  parts.push(`Process: ${kernelEvent.comm} (PID: ${kernelEvent.pid})`);

  if (kernelEvent.filename) {
    parts.push(`File/Command: ${kernelEvent.filename}`);
  }

  if (kernelEvent.args) {
    parts.push(`Arguments: ${kernelEvent.args.slice(0, 100)}${kernelEvent.args.length > 100 ? '...' : ''}`);
  }

  // ネットワーク情報
  if (kernelEvent.net) {
    parts.push(
      `Network: ${kernelEvent.net.daddr}:${kernelEvent.net.dport} (Protocol: ${kernelEvent.net.proto})`
    );
  }

  // ユーザー情報
  if (kernelEvent.uid !== undefined) {
    parts.push(`User: UID ${kernelEvent.uid}`);
  }

  // 脅威レベル
  const threatLevelNames: Record<number, string> = {
    4: 'CRITICAL',
    3: 'HIGH',
    2: 'MEDIUM',
    1: 'LOW',
    0: 'INFO',
  };
  parts.push(`Threat Level: ${threatLevelNames[kernelEvent.threat_level] || 'UNKNOWN'}`);

  return parts.join(' | ');
}

/**
 * 複数のカーネルイベントをバッチ変換
 */
export function convertKernelEventsBatch(
  kernelEvents: KernelEvent[]
): ThreatFeedEvent[] {
  return kernelEvents.map(convertKernelEventToThreatFeed);
}

/**
 * 脅威フィード・イベントをフィルタリング（深刻度ベース）
 */
export function filterThreatFeedBySeverity(
  events: ThreatFeedEvent[],
  minSeverity: ThreatFeedEvent['severity'] = 'low'
): ThreatFeedEvent[] {
  const severityOrder: Record<ThreatFeedEvent['severity'], number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };

  const minLevel = severityOrder[minSeverity];
  return events.filter((event) => severityOrder[event.severity] >= minLevel);
}

/**
 * 脅威フィード・イベントをソート（タイムスタンプ降順）
 */
export function sortThreatFeedByTimestamp(
  events: ThreatFeedEvent[],
  descending: boolean = true
): ThreatFeedEvent[] {
  return [...events].sort((a, b) => {
    const timeA = new Date(a.timestamp).getTime();
    const timeB = new Date(b.timestamp).getTime();
    return descending ? timeB - timeA : timeA - timeB;
  });
}
