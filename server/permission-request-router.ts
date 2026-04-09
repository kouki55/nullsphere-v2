import { z } from "zod";
import { protectedProcedure, adminProcedure } from "./_core/trpc";
import { router } from "./_core/trpc";
import { getDb } from "./db";
import { permissionRequests, users } from "../drizzle/schema";
import { eq, and } from "drizzle-orm";
import { logAudit } from "./audit";
import { randomUUID } from "crypto";

export const permissionRequestRouter = router({
  /**
   * ユーザーが権限リクエストを作成
   */
  create: protectedProcedure
    .input(
      z.object({
        requestedRole: z.enum(["admin", "analyst", "operator"]),
        reason: z.string().min(10).max(500),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database connection failed");

      // 既存のペンディングリクエストをチェック
      const existingRequest = await db
        .select()
        .from(permissionRequests)
        .where(
          and(
            eq(permissionRequests.userId, ctx.user.id),
            eq(permissionRequests.status, "pending")
          )
        )
        .limit(1);

      if (existingRequest.length > 0) {
        throw new Error("ペンディング中のリクエストが既に存在します");
      }

      const requestId = randomUUID();
      const now = new Date();

      await db.insert(permissionRequests).values({
        requestId,
        userId: ctx.user.id,
        requestedRole: input.requestedRole,
        reason: input.reason,
        status: "pending",
        createdAt: now,
        updatedAt: now,
      });

      // 監査ログ記録
      await logAudit({
        userId: ctx.user.id,
        userName: ctx.user.name || "Unknown",
        action: "permission_request_create",
        resourceType: "permission_request",
        resourceId: requestId,
        resourceName: `Request for ${input.requestedRole}`,
        status: "success",
        ipAddress: ctx.req.ip || "unknown",
        userAgent: ctx.req.headers["user-agent"] || "unknown",
      });

      return { success: true, requestId };
    }),

  /**
   * ユーザーが自分のリクエスト一覧を取得
   */
  listMy: protectedProcedure.query(async ({ ctx }) => {
    const db = await getDb();
    if (!db) throw new Error("Database connection failed");

    const requests = await db
      .select()
      .from(permissionRequests)
      .where(eq(permissionRequests.userId, ctx.user.id))
      .orderBy((t) => t.createdAt);

    return requests;
  }),

  /**
   * 管理者がすべてのリクエストを取得
   */
  listAll: adminProcedure.query(async ({ ctx }) => {
    const db = await getDb();
    if (!db) throw new Error("Database connection failed");

    const requests = await db
      .select()
      .from(permissionRequests)
      .orderBy((t) => t.createdAt);

    // ユーザー情報を結合
    const enriched = await Promise.all(
      requests.map(async (req) => {
        const user = await db
          .select()
          .from(users)
          .where(eq(users.id, req.userId))
          .limit(1);
        return {
          ...req,
          userName: user[0]?.name || "Unknown",
          userEmail: user[0]?.email || "Unknown",
        };
      })
    );

    return enriched;
  }),

  /**
   * 管理者がリクエストを承認
   */
  approve: adminProcedure
    .input(z.object({ requestId: z.string() }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database connection failed");

      // リクエストを取得
      const request = await db
        .select()
        .from(permissionRequests)
        .where(eq(permissionRequests.requestId, input.requestId))
        .limit(1);

      if (request.length === 0) {
        throw new Error("リクエストが見つかりません");
      }

      const req = request[0];
      const now = new Date();

      // リクエストを承認に更新
      await db
        .update(permissionRequests)
        .set({
          status: "approved",
          reviewedBy: ctx.user.id,
          reviewedAt: now,
          updatedAt: now,
        })
        .where(eq(permissionRequests.requestId, input.requestId));

      // ユーザーの権限を更新
      await db
        .update(users)
        .set({
          role: req.requestedRole as "admin" | "analyst" | "operator",
          updatedAt: now,
        })
        .where(eq(users.id, req.userId));

      // 監査ログ記録
      const user = await db
        .select()
        .from(users)
        .where(eq(users.id, req.userId))
        .limit(1);

      await logAudit({
        userId: ctx.user.id,
        userName: ctx.user.name || "Unknown",
        action: "permission_request_approve",
        resourceType: "permission_request",
        resourceId: input.requestId,
        resourceName: `Approved ${req.requestedRole} for ${user[0]?.name}`,
        status: "success",
        ipAddress: ctx.req.ip || "unknown",
        userAgent: ctx.req.headers["user-agent"] || "unknown",
      });

      return { success: true };
    }),

  /**
   * 管理者がリクエストを却下
   */
  reject: adminProcedure
    .input(
      z.object({
        requestId: z.string(),
        reason: z.string().min(1).max(500),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) throw new Error("Database connection failed");

      // リクエストを取得
      const request = await db
        .select()
        .from(permissionRequests)
        .where(eq(permissionRequests.requestId, input.requestId))
        .limit(1);

      if (request.length === 0) {
        throw new Error("リクエストが見つかりません");
      }

      const req = request[0];
      const now = new Date();

      // リクエストを却下に更新
      await db
        .update(permissionRequests)
        .set({
          status: "rejected",
          reviewedBy: ctx.user.id,
          reviewedAt: now,
          rejectionReason: input.reason,
          updatedAt: now,
        })
        .where(eq(permissionRequests.requestId, input.requestId));

      // 監査ログ記録
      const user = await db
        .select()
        .from(users)
        .where(eq(users.id, req.userId))
        .limit(1);

      await logAudit({
        userId: ctx.user.id,
        userName: ctx.user.name || "Unknown",
        action: "permission_request_reject",
        resourceType: "permission_request",
        resourceId: input.requestId,
        resourceName: `Rejected ${req.requestedRole} for ${user[0]?.name}`,
        status: "success",
        ipAddress: ctx.req.ip || "unknown",
        userAgent: ctx.req.headers["user-agent"] || "unknown",
      });

      return { success: true };
    }),
});
