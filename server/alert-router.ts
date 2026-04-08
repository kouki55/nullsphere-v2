/**
 * alert-router.ts
 * ================
 * 監査ログアラート設定の tRPC ルーター
 */

import { z } from "zod";
import { adminProcedure, router } from "./_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "./db";
import { alertSettings } from "../drizzle/schema";
import { eq, and } from "drizzle-orm";
import { randomUUID } from "crypto";

export const alertRouter = router({
  /**
   * アラート設定を作成
   */
  createAlert: adminProcedure
    .input(
      z.object({
        actionType: z.enum([
          "user_promote",
          "user_demote",
          "vm_start",
          "vm_stop",
          "vm_reboot",
          "decoy_create",
          "decoy_delete",
          "decoy_activate",
          "decoy_deactivate",
          "process_isolate",
          "network_block",
          "tracing_enable",
          "tracing_disable",
          "threat_resolve",
          "threat_block",
          "settings_change",
          "all",
        ]),
        notificationMethod: z.enum(["email", "in-app", "webhook"]).default("in-app"),
        webhookUrl: z.string().url().optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Database not available",
        });
      }
      const alertId = randomUUID();

      try {
        await db.insert(alertSettings).values({
          alertId,
          userId: ctx.user.id,
          actionType: input.actionType,
          notificationMethod: input.notificationMethod,
          webhookUrl: input.webhookUrl,
          isActive: true,
        });

        return {
          success: true,
          alertId,
          message: `Alert created for action: ${input.actionType}`,
        };
      } catch (error: any) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to create alert",
        });
      }
    }),

  /**
   * アラート設定一覧を取得
   */
  listAlerts: adminProcedure.query(async ({ ctx }) => {
    const db = await getDb();
    if (!db) {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Database not available",
      });
    }

    try {
      const alerts = await db
        .select()
        .from(alertSettings)
        .where(eq(alertSettings.userId, ctx.user.id));

      return alerts;
    } catch (error: any) {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to fetch alerts",
      });
    }
  }),

  /**
   * アラート設定を更新
   */
  updateAlert: adminProcedure
    .input(
      z.object({
        alertId: z.string(),
        notificationMethod: z.enum(["email", "in-app", "webhook"]).optional(),
        webhookUrl: z.string().url().optional(),
        isActive: z.boolean().optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Database not available",
        });
      }

      try {
        const alert = await db
          .select()
          .from(alertSettings)
          .where(
            and(
              eq(alertSettings.alertId, input.alertId),
              eq(alertSettings.userId, ctx.user.id)
            )
          );

        if (alert.length === 0) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "Alert not found",
          });
        }

        const updateData: any = {};
        if (input.notificationMethod) updateData.notificationMethod = input.notificationMethod;
        if (input.webhookUrl) updateData.webhookUrl = input.webhookUrl;
        if (input.isActive !== undefined) updateData.isActive = input.isActive;

        await db
          .update(alertSettings)
          .set(updateData)
          .where(eq(alertSettings.alertId, input.alertId));

        return {
          success: true,
          message: "Alert updated",
        };
      } catch (error: any) {
        if (error.code === "NOT_FOUND") throw error;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to update alert",
        });
      }
    }),

  /**
   * アラート設定を削除
   */
  deleteAlert: adminProcedure
    .input(
      z.object({
        alertId: z.string(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const db = await getDb();
      if (!db) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Database not available",
        });
      }

      try {
        const alert = await db
          .select()
          .from(alertSettings)
          .where(
            and(
              eq(alertSettings.alertId, input.alertId),
              eq(alertSettings.userId, ctx.user.id)
            )
          );

        if (alert.length === 0) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "Alert not found",
          });
        }

        await db.delete(alertSettings).where(eq(alertSettings.alertId, input.alertId));

        return {
          success: true,
          message: "Alert deleted",
        };
      } catch (error: any) {
        if (error.code === "NOT_FOUND") throw error;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to delete alert",
        });
      }
    }),
});
