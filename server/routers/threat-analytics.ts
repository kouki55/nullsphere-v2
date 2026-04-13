/**
 * threat-analytics.ts
 * ====================
 * 脅威分析用 tRPC ルーター
 */

import { z } from 'zod';
import { protectedProcedure, router } from '../_core/trpc';
import {
  getThreatFeedsInPeriod,
  getThreatAnalytics,
  calculateAndSaveThreatAnalytics,
} from '../_core/threat-persistence';

export const threatAnalyticsRouter = router({
  /**
   * 指定期間の脅威フィード・イベントを取得
   */
  getThreatsByPeriod: protectedProcedure
    .input(
      z.object({
        startDate: z.string().datetime(),
        endDate: z.string().datetime(),
        severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
        sourceIp: z.string().optional(),
        type: z.string().optional(),
        limit: z.number().min(1).max(1000).default(100),
      })
    )
    .query(async ({ input }: any) => {
      try {
        const threats = await getThreatFeedsInPeriod(
          new Date(input.startDate),
          new Date(input.endDate),
          {
            severity: input.severity,
            sourceIp: input.sourceIp,
            type: input.type,
          }
        );

        return {
          success: true,
          data: threats.slice(0, input.limit),
          count: threats.length,
        };
      } catch (error) {
        console.error('[ThreatAnalyticsRouter] Error fetching threats:', error);
        return {
          success: false,
          error: 'Failed to fetch threats',
          data: [],
          count: 0,
        };
      }
    }),

  /**
   * 脅威分析データを取得（時系列）
   */
  getAnalyticsByPeriod: protectedProcedure
    .input(
      z.object({
        period: z.enum(['hourly', 'daily', 'weekly', 'monthly']),
        limit: z.number().min(1).max(365).default(30),
      })
    )
    .query(async ({ input }: any) => {
      try {
        const analytics = await getThreatAnalytics(input.period, input.limit);

        return {
          success: true,
          data: analytics,
          count: analytics.length,
        };
      } catch (error) {
        console.error('[ThreatAnalyticsRouter] Error fetching analytics:', error);
        return {
          success: false,
          error: 'Failed to fetch analytics',
          data: [],
          count: 0,
        };
      }
    }),

  /**
   * 脅威分析データを計算して保存
   */
  calculateAnalytics: protectedProcedure
    .input(
      z.object({
        period: z.enum(['hourly', 'daily', 'weekly', 'monthly']),
        timestamp: z.string().datetime().optional(),
      })
    )
    .mutation(async ({ input }: any) => {
      try {
        const timestamp = input.timestamp ? new Date(input.timestamp) : new Date();

        await calculateAndSaveThreatAnalytics(input.period, timestamp);

        return {
          success: true,
          message: `Analytics calculated for ${input.period} period`,
        };
      } catch (error) {
        console.error('[ThreatAnalyticsRouter] Error calculating analytics:', error);
        return {
          success: false,
          error: 'Failed to calculate analytics',
        };
      }
    }),

  /**
   * 脅威統計サマリーを取得
   */
  getSummary: protectedProcedure
    .input(
      z.object({
        days: z.number().min(1).max(365).default(7),
      })
    )
    .query(async ({ input }: any) => {
      try {
        const now = new Date();
        const startDate = new Date(now.getTime() - input.days * 24 * 60 * 60 * 1000);

        const threats: any[] = await getThreatFeedsInPeriod(startDate, now);

        const summary = {
          totalThreats: threats.length,
          criticalCount: threats.filter((t: any) => t.severity === 'critical').length,
          highCount: threats.filter((t: any) => t.severity === 'high').length,
          mediumCount: threats.filter((t: any) => t.severity === 'medium').length,
          lowCount: threats.filter((t: any) => t.severity === 'low').length,
          infoCount: threats.filter((t: any) => t.severity === 'info').length,
          resolvedCount: threats.filter((t: any) => t.status === 'resolved').length,
          uniqueAttackers: new Set(threats.map((t: any) => t.sourceIp)).size,
          period: `${input.days} days`,
        };

        return {
          success: true,
          data: summary,
        };
      } catch (error) {
        console.error('[ThreatAnalyticsRouter] Error fetching summary:', error);
        return {
          success: false,
          error: 'Failed to fetch summary',
          data: null,
        };
      }
    }),

  /**
   * 攻撃タイプ別の統計を取得
   */
  getAttackTypeDistribution: protectedProcedure
    .input(
      z.object({
        days: z.number().min(1).max(365).default(7),
      })
    )
    .query(async ({ input }: any) => {
      try {
        const now = new Date();
        const startDate = new Date(now.getTime() - input.days * 24 * 60 * 60 * 1000);

        const threats: any[] = await getThreatFeedsInPeriod(startDate, now);

        const distribution = new Map<string, number>();
        threats.forEach((threat: any) => {
          distribution.set(threat.type, (distribution.get(threat.type) || 0) + 1);
        });

        const data = Array.from(distribution.entries()).map(([type, count]) => ({
          type,
          count,
          percentage: ((count / threats.length) * 100).toFixed(2),
        }));

        return {
          success: true,
          data: data.sort((a, b) => b.count - a.count),
        };
      } catch (error) {
        console.error('[ThreatAnalyticsRouter] Error fetching attack type distribution:', error);
        return {
          success: false,
          error: 'Failed to fetch attack type distribution',
          data: [],
        };
      }
    }),

  /**
   * 攻撃元国別の統計を取得
   */
  getSourceCountryDistribution: protectedProcedure
    .input(
      z.object({
        days: z.number().min(1).max(365).default(7),
        limit: z.number().min(1).max(50).default(10),
      })
    )
    .query(async ({ input }: any) => {
      try {
        const now = new Date();
        const startDate = new Date(now.getTime() - input.days * 24 * 60 * 60 * 1000);

        const threats: any[] = await getThreatFeedsInPeriod(startDate, now);

        const distribution = new Map<string, number>();
        threats.forEach((threat: any) => {
          if (threat.sourceCountry) {
            distribution.set(threat.sourceCountry, (distribution.get(threat.sourceCountry) || 0) + 1);
          }
        });

        const data = Array.from(distribution.entries())
          .map(([country, count]) => ({
            country: country || 'Unknown',
            count,
            percentage: ((count / threats.length) * 100).toFixed(2),
          }))
          .sort((a, b) => b.count - a.count)
          .slice(0, input.limit);

        return {
          success: true,
          data,
        };
      } catch (error) {
        console.error('[ThreatAnalyticsRouter] Error fetching source country distribution:', error);
        return {
          success: false,
          error: 'Failed to fetch source country distribution',
          data: [],
        };
      }
    }),

  /**
   * 時系列の脅威発生数を取得
   */
  getThreatTimeSeries: protectedProcedure
    .input(
      z.object({
        days: z.number().min(1).max(365).default(30),
        granularity: z.enum(['hourly', 'daily']).default('daily'),
      })
    )
    .query(async ({ input }: any) => {
      try {
        const now = new Date();
        const startDate = new Date(now.getTime() - input.days * 24 * 60 * 60 * 1000);

        const threats: any[] = await getThreatFeedsInPeriod(startDate, now);

        // 時系列データを集計
        const timeSeries = new Map<string, any>();

        threats.forEach((threat: any) => {
          const date = new Date(threat.detectedAt);
          let key: string;

          if (input.granularity === 'hourly') {
            key = date.toISOString().slice(0, 13) + ':00:00Z';
          } else {
            key = date.toISOString().slice(0, 10);
          }

          if (!timeSeries.has(key)) {
            timeSeries.set(key, {
              timestamp: key,
              total: 0,
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              info: 0,
            });
          }

          const entry = timeSeries.get(key);
          entry.total++;
          entry[threat.severity]++;
        });

        const data = Array.from(timeSeries.values()).sort(
          (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
        );

        return {
          success: true,
          data,
        };
      } catch (error) {
        console.error('[ThreatAnalyticsRouter] Error fetching threat time series:', error);
        return {
          success: false,
          error: 'Failed to fetch threat time series',
          data: [],
        };
      }
    }),
});
