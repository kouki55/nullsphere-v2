/**
 * threat-feed.ts
 * ==============
 * WebSocket リアルタイム脅威フィード用の型定義
 */

/**
 * リアルタイム脅威フィード・イベント
 * KernelBridge から受信したイベントをユーザーフレンドリーな形式に変換
 */
export interface ThreatFeedEvent {
  /** 一意のイベントID */
  feedId: string;
  
  /** タイムスタンプ（ISO 8601形式） */
  timestamp: string;
  
  /** 脅威の種類 */
  type: 'intrusion' | 'malware' | 'privilege_escalation' | 'data_exfiltration' | 'lateral_movement' | 'reconnaissance' | 'unknown';
  
  /** 深刻度 */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  
  /** 人間が読める脅威説明 */
  title: string;
  
  /** 詳細なメッセージ */
  description: string;
  
  /** 攻撃元IP */
  sourceIp: string;
  
  /** 攻撃元国（利用可能な場合） */
  sourceCountry?: string;
  
  /** 対象ホスト */
  targetHost?: string;
  
  /** 対象ポート */
  targetPort?: number;
  
  /** 関連するプロセス/コマンド */
  command?: string;
  
  /** 関連する脅威ID（データベース内） */
  threatId?: string;
  
  /** 関連するイベントID（データベース内） */
  eventId?: string;
  
  /** 攻撃者プロファイルID（利用可能な場合） */
  attackerId?: string;
  
  /** ステータス */
  status: 'detected' | 'blocked' | 'isolated' | 'deceived' | 'traced' | 'resolved';
  
  /** 追加のメタデータ */
  metadata?: Record<string, any>;
}

/**
 * WebSocket イベントペイロード
 */
export interface SocketIOEvent {
  /** イベント名 */
  event: string;
  
  /** ペイロード */
  data: ThreatFeedEvent | ThreatFeedEvent[];
  
  /** タイムスタンプ */
  timestamp: string;
}

/**
 * クライアント側で購読する脅威フィード・イベント
 */
export const THREAT_FEED_EVENTS = {
  /** 新しい脅威が検出された */
  THREAT_DETECTED: 'threat:detected',
  
  /** 脅威が解決された */
  THREAT_RESOLVED: 'threat:resolved',
  
  /** 脅威が隔離された */
  THREAT_ISOLATED: 'threat:isolated',
  
  /** リアルタイム脅威フィード（ストリーム） */
  THREAT_FEED: 'threat:feed',
  
  /** 脅威フィードの初期化（バッチ） */
  THREAT_FEED_INIT: 'threat:feed:init',
  
  /** 脅威フィードのクリア */
  THREAT_FEED_CLEAR: 'threat:feed:clear',
} as const;
