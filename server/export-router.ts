import { z } from "zod";
import { adminProcedure, router } from "./_core/trpc";
import { getDb } from "./db";
import { auditLogs } from "../drizzle/schema";
import { eq, and, gte, lte } from "drizzle-orm";

export const exportRouter = router({
  /**
   * 監査ログを CSV 形式でエクスポート
   */
  auditLogsAsCSV: adminProcedure
    .input(
      z.object({
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        userId: z.number().optional(),
        action: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database connection failed");

      // フィルタ条件を構築
      const conditions = [];
      if (input.startDate) {
        conditions.push(gte(auditLogs.timestamp, input.startDate));
      }
      if (input.endDate) {
        conditions.push(lte(auditLogs.timestamp, input.endDate));
      }
      if (input.userId) {
        conditions.push(eq(auditLogs.userId, input.userId));
      }
      if (input.action) {
        conditions.push(eq(auditLogs.action, input.action as any));
      }

      // 監査ログを取得
      let query: any = db.select().from(auditLogs);
      if (conditions.length > 0) {
        query = query.where(and(...conditions));
      }
      const logs = await query.orderBy((t: any) => t.timestamp);

      // CSV ヘッダー
      const headers = [
        "Log ID",
        "User ID",
        "User Name",
        "Action",
        "Resource Type",
        "Resource ID",
        "Resource Name",
        "Status",
        "Error Message",
        "IP Address",
        "User Agent",
        "Timestamp",
        "Created At",
      ];

      // CSV データ行
      const rows = logs.map((log: any) => [
        log.logId,
        log.userId,
        log.userName || "",
        log.action,
        log.resourceType || "",
        log.resourceId || "",
        log.resourceName || "",
        log.status,
        log.errorMessage || "",
        log.ipAddress || "",
        log.userAgent || "",
        log.timestamp.toISOString(),
        log.createdAt.toISOString(),
      ]);

      // CSV 文字列を生成
      const csv = [
        headers.map((h: any) => `"${h}"`).join(","),
        ...rows.map((row: any) => row.map((cell: any) => `"${String(cell).replace(/"/g, '""')}"`).join(",")),
      ].join("\n");

      return {
        filename: `audit-logs-${new Date().toISOString().split("T")[0]}.csv`,
        content: csv,
        mimeType: "text/csv",
      };
    }),

  /**
   * 監査ログを JSON 形式でエクスポート
   */
  auditLogsAsJSON: adminProcedure
    .input(
      z.object({
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        userId: z.number().optional(),
        action: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database connection failed");

      // フィルタ条件を構築
      const conditions = [];
      if (input.startDate) {
        conditions.push(gte(auditLogs.timestamp, input.startDate));
      }
      if (input.endDate) {
        conditions.push(lte(auditLogs.timestamp, input.endDate));
      }
      if (input.userId) {
        conditions.push(eq(auditLogs.userId, input.userId));
      }
      if (input.action) {
        conditions.push(eq(auditLogs.action, input.action as any));
      }

      // 監査ログを取得
      let query: any = db.select().from(auditLogs);
      if (conditions.length > 0) {
        query = query.where(and(...conditions));
      }
      const logs = await query.orderBy((t: any) => t.timestamp);

      // JSON オブジェクトを生成
      const json = {
        exportedAt: new Date().toISOString(),
        totalRecords: logs.length,
        filters: {
          startDate: input.startDate?.toISOString(),
          endDate: input.endDate?.toISOString(),
          userId: input.userId,
          action: input.action,
        },
        data: logs,
      };

      return {
        filename: `audit-logs-${new Date().toISOString().split("T")[0]}.json`,
        content: JSON.stringify(json, null, 2),
        mimeType: "application/json",
      };
    }),

  /**
   * 監査ログを JSON Lines 形式でエクスポート（大規模データ向け）
   */
  auditLogsAsJSONL: adminProcedure
    .input(
      z.object({
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        userId: z.number().optional(),
        action: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database connection failed");

      // フィルタ条件を構築
      const conditions = [];
      if (input.startDate) {
        conditions.push(gte(auditLogs.timestamp, input.startDate));
      }
      if (input.endDate) {
        conditions.push(lte(auditLogs.timestamp, input.endDate));
      }
      if (input.userId) {
        conditions.push(eq(auditLogs.userId, input.userId));
      }
      if (input.action) {
        conditions.push(eq(auditLogs.action, input.action as any));
      }

      // 監査ログを取得
      let query: any = db.select().from(auditLogs);
      if (conditions.length > 0) {
        query = query.where(and(...conditions));
      }
      const logs = await query.orderBy((t: any) => t.timestamp);

      // JSON Lines 形式で生成
      const jsonl = logs.map((log: any) => JSON.stringify(log)).join("\n");

      return {
        filename: `audit-logs-${new Date().toISOString().split("T")[0]}.jsonl`,
        content: jsonl,
        mimeType: "application/x-ndjson",
      };
    }),
});
