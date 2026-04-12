/**
 * threat-persistence.ts
 * ======================
 * 脅威データをデータベースに永続化するロジック
 */

import { getDb } from '../db';
import { threatFeeds, threatAnalytics } from '../../drizzle/schema';
import { eq, desc, and, gte, lte } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import type { ThreatFeedEvent } from './types/threat-feed';

/**
 * 脅威フィード・イベントをデータベースに保存
 */
export async function persistThreatFeed(event: ThreatFeedEvent): Promise<void> {
  try {
    const db = await getDb();
    if (!db) throw new Error('Database not available');
    
    await db.insert(threatFeeds).values({
      feedId: event.feedId || `feed-${uuidv4()}`,
      type: (event.type as any) || 'reconnaissance',
      severity: event.severity,
      title: event.title,
      description: event.description,
      sourceIp: event.sourceIp,
      sourceCountry: event.sourceCountry,
      targetHost: event.targetHost,
      targetPort: event.targetPort,
      command: event.command,
      status: 'detected',
      metadata: event.metadata || {},
      detectedAt: new Date(event.timestamp),
    });

    console.log(`[ThreatPersistence] Saved threat feed: ${event.feedId}`);
  } catch (error) {
    console.error('[ThreatPersistence] Error saving threat feed:', error);
    throw error;
  }
}

/**
 * 複数の脅威フィード・イベントをバッチで保存
 */
export async function persistThreatFeedBatch(events: ThreatFeedEvent[]): Promise<void> {
  try {
    const db = await getDb();
    if (!db) throw new Error('Database not available');
    
    const values = events.map((event) => ({
      feedId: event.feedId || `feed-${uuidv4()}`,
      type: (event.type as any) || 'reconnaissance',
      severity: event.severity,
      title: event.title,
      description: event.description,
      sourceIp: event.sourceIp,
      sourceCountry: event.sourceCountry,
      targetHost: event.targetHost,
      targetPort: event.targetPort,
      command: event.command,
      status: 'detected' as const,
      metadata: event.metadata || {},
      detectedAt: new Date(event.timestamp),
    }));

    if (values.length > 0) {
      await db.insert(threatFeeds).values(values);
      console.log(`[ThreatPersistence] Saved ${values.length} threat feeds`);
    }
  } catch (error) {
    console.error('[ThreatPersistence] Error saving threat feed batch:', error);
    throw error;
  }
}

/**
 * 脅威フィード・イベントのステータスを更新
 */
export async function updateThreatFeedStatus(
  feedId: string,
  status: 'detected' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive',
  resolvedAt?: Date
): Promise<void> {
  try {
    const db = await getDb();
    if (!db) throw new Error('Database not available');
    
    const updates: any = { status };
    if (status === 'resolved' && resolvedAt) {
      updates.resolvedAt = resolvedAt;
    }

    await db
      .update(threatFeeds)
      .set(updates)
      .where(eq(threatFeeds.feedId, feedId));

    console.log(`[ThreatPersistence] Updated threat feed status: ${feedId} -> ${status}`);
  } catch (error) {
    console.error('[ThreatPersistence] Error updating threat feed status:', error);
    throw error;
  }
}

/**
 * 指定期間の脅威フィード・イベントを取得
 */
export async function getThreatFeedsInPeriod(
  startDate: Date,
  endDate: Date,
  filters?: {
    severity?: string;
    sourceIp?: string;
    type?: string;
  }
): Promise<any[]> {
  try {
    const db = await getDb();
    if (!db) throw new Error('Database not available');
    
    const conditions: any[] = [
      gte(threatFeeds.detectedAt, startDate),
      lte(threatFeeds.detectedAt, endDate),
    ];

    if (filters?.severity) {
      conditions.push(eq(threatFeeds.severity, filters.severity as any));
    }

    if (filters?.sourceIp) {
      conditions.push(eq(threatFeeds.sourceIp, filters.sourceIp));
    }

    if (filters?.type) {
      conditions.push(eq(threatFeeds.type, filters.type as any));
    }

    const results = await db
      .select()
      .from(threatFeeds)
      .where(and(...conditions))
      .orderBy(desc(threatFeeds.detectedAt));
    
    return results;
  } catch (error) {
    console.error('[ThreatPersistence] Error fetching threat feeds:', error);
    throw error;
  }
}

/**
 * 脅威分析データを計算して保存
 */
export async function calculateAndSaveThreatAnalytics(
  period: 'hourly' | 'daily' | 'weekly' | 'monthly',
  timestamp: Date
): Promise<void> {
  try {
    const db = await getDb();
    if (!db) throw new Error('Database not available');
    
    // 期間の開始と終了を計算
    const startDate = getPeriodStart(period, timestamp);
    const endDate = getPeriodEnd(period, timestamp);

    // 該当期間の脅威データを取得
    const threats = await getThreatFeedsInPeriod(startDate, endDate);

    // 統計情報を計算
    const stats = {
      totalThreats: threats.length,
      criticalCount: threats.filter((t) => t.severity === 'critical').length,
      highCount: threats.filter((t) => t.severity === 'high').length,
      mediumCount: threats.filter((t) => t.severity === 'medium').length,
      lowCount: threats.filter((t) => t.severity === 'low').length,
      infoCount: threats.filter((t) => t.severity === 'info').length,
      blockedCount: threats.filter((t) => t.status === 'resolved').length,
      resolvedCount: threats.filter((t) => t.status === 'resolved').length,
      uniqueAttackers: new Set(threats.map((t) => t.sourceIp)).size,
    };

    // 最も多い攻撃タイプと攻撃元国を取得
    const typeMap = new Map<string, number>();
    const countryMap = new Map<string, number>();

    threats.forEach((threat) => {
      typeMap.set(threat.type, (typeMap.get(threat.type) || 0) + 1);
      if (threat.sourceCountry) {
        countryMap.set(threat.sourceCountry, (countryMap.get(threat.sourceCountry) || 0) + 1);
      }
    });

    const topAttackType = Array.from(typeMap.entries()).sort((a, b) => b[1] - a[1])[0]?.[0];
    const topSourceCountry = Array.from(countryMap.entries()).sort((a, b) => b[1] - a[1])[0]?.[0];

    // データベースに保存
    await db.insert(threatAnalytics).values({
      analyticsId: `analytics-${uuidv4()}`,
      period,
      timestamp,
      totalThreats: stats.totalThreats,
      criticalCount: stats.criticalCount,
      highCount: stats.highCount,
      mediumCount: stats.mediumCount,
      lowCount: stats.lowCount,
      infoCount: stats.infoCount,
      blockedCount: stats.blockedCount,
      resolvedCount: stats.resolvedCount,
      uniqueAttackers: stats.uniqueAttackers,
      topAttackType,
      topSourceCountry,
    });

    console.log(`[ThreatPersistence] Saved threat analytics for ${period} period`);
  } catch (error) {
    console.error('[ThreatPersistence] Error calculating threat analytics:', error);
    throw error;
  }
}

/**
 * 期間の開始日時を取得
 */
function getPeriodStart(period: string, date: Date): Date {
  const d = new Date(date);
  switch (period) {
    case 'hourly':
      d.setMinutes(0, 0, 0);
      break;
    case 'daily':
      d.setHours(0, 0, 0, 0);
      break;
    case 'weekly':
      d.setDate(d.getDate() - d.getDay());
      d.setHours(0, 0, 0, 0);
      break;
    case 'monthly':
      d.setDate(1);
      d.setHours(0, 0, 0, 0);
      break;
  }
  return d;
}

/**
 * 期間の終了日時を取得
 */
function getPeriodEnd(period: string, date: Date): Date {
  const d = new Date(date);
  switch (period) {
    case 'hourly':
      d.setHours(d.getHours() + 1);
      d.setMinutes(0, 0, 0);
      break;
    case 'daily':
      d.setDate(d.getDate() + 1);
      d.setHours(0, 0, 0, 0);
      break;
    case 'weekly':
      d.setDate(d.getDate() - d.getDay() + 7);
      d.setHours(0, 0, 0, 0);
      break;
    case 'monthly':
      d.setMonth(d.getMonth() + 1);
      d.setDate(1);
      d.setHours(0, 0, 0, 0);
      break;
  }
  return d;
}

/**
 * 脅威分析データを取得
 */
export async function getThreatAnalytics(
  period: 'hourly' | 'daily' | 'weekly' | 'monthly',
  limit: number = 30
): Promise<any[]> {
  try {
    const db = await getDb();
    if (!db) throw new Error('Database not available');
    
    const results = await db
      .select()
      .from(threatAnalytics)
      .where(eq(threatAnalytics.period, period))
      .orderBy(desc(threatAnalytics.timestamp))
      .limit(limit);

    return results;
  } catch (error) {
    console.error('[ThreatPersistence] Error fetching threat analytics:', error);
    throw error;
  }
}
