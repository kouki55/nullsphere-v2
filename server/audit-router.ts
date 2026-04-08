import { z } from "zod";
import { adminProcedure, router } from "./_core/trpc";
import { getDb } from "./db";
import { auditLogs } from "../drizzle/schema";
import { desc, eq, gte, lte, and, sql } from "drizzle-orm";
import { TRPCError } from "@trpc/server";

export const auditRouter = router({
  /**
   * 監査ログ一覧を取得（admin のみ）
   */
  list: adminProcedure
    .input(
      z.object({
        limit: z.number().int().min(1).max(100).default(50),
        offset: z.number().int().min(0).default(0),
        userId: z.number().optional(),
        action: z.string().optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
      })
    )
    .query(async ({ input }) => {
      try {
        const db = await getDb();
        if (!db) {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: "Database not available",
          });
        }

        // フィルター条件を構築
        const conditions = [];

        if (input.userId) {
          conditions.push(eq(auditLogs.userId, input.userId));
        }

        if (input.action) {
          conditions.push(eq(auditLogs.action, input.action as any));
        }

        if (input.startDate) {
          conditions.push(gte(auditLogs.timestamp, input.startDate));
        }

        if (input.endDate) {
          conditions.push(lte(auditLogs.timestamp, input.endDate));
        }

        // WHERE 句を構築
        const whereClause =
          conditions.length > 0 ? and(...conditions) : undefined;

        // ログを取得
        const logs = await db
          .select()
          .from(auditLogs)
          .where(whereClause)
          .orderBy(desc(auditLogs.timestamp))
          .limit(input.limit)
          .offset(input.offset);

        // 合計件数を取得
        const countResult = await db
          .select({ count: sql<number>`COUNT(*)` })
          .from(auditLogs)
          .where(whereClause);
        const total = countResult[0]?.count ?? 0;

        return {
          logs,
          total,
          limit: input.limit,
          offset: input.offset,
          hasMore: input.offset + input.limit < total,
        };
      } catch (error) {
        if (error instanceof TRPCError) throw error;
        console.error("[Audit] Error listing audit logs:", error);
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to list audit logs",
        });
      }
    }),

  /**
   * 特定のユーザーの監査ログを取得
   */
  getByUser: adminProcedure
    .input(z.object({ userId: z.number() }))
    .query(async ({ input }) => {
      try {
        const db = await getDb();
        if (!db) {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: "Database not available",
          });
        }

        const logs = await db
          .select()
          .from(auditLogs)
          .where(eq(auditLogs.userId, input.userId))
          .orderBy(desc(auditLogs.timestamp))
          .limit(100);

        return logs;
      } catch (error) {
        if (error instanceof TRPCError) throw error;
        console.error("[Audit] Error getting user audit logs:", error);
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to get user audit logs",
        });
      }
    }),

  /**
   * 特定の日付範囲の監査ログを取得
   */
  getByDateRange: adminProcedure
    .input(
      z.object({
        startDate: z.date(),
        endDate: z.date(),
      })
    )
    .query(async ({ input }) => {
      try {
        const db = await getDb();
        if (!db) {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: "Database not available",
          });
        }

        const logs = await db
          .select()
          .from(auditLogs)
          .where(
            and(
              gte(auditLogs.timestamp, input.startDate),
              lte(auditLogs.timestamp, input.endDate)
            )
          )
          .orderBy(desc(auditLogs.timestamp));

        return logs;
      } catch (error) {
        if (error instanceof TRPCError) throw error;
        console.error("[Audit] Error getting audit logs by date range:", error);
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to get audit logs by date range",
        });
      }
    }),
});
