import { z } from "zod";
import { adminProcedure, router } from "./_core/trpc";
import { getDb } from "./db";
import { users } from "../drizzle/schema";
import { eq } from "drizzle-orm";
import { TRPCError } from "@trpc/server";
import { logUserPromote, logUserDemote } from "./audit";

export const adminRouter = router({
  /**
   * 全ユーザー一覧を取得（admin のみ）
   */
  listUsers: adminProcedure.query(async ({ ctx }) => {
    try {
      const db = await getDb();
      if (!db) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Database not available",
        });
      }
      const allUsers = await db.select({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        createdAt: users.createdAt,
        lastSignedIn: users.lastSignedIn,
      }).from(users);
      return allUsers;
    } catch (error) {
      if (error instanceof TRPCError) throw error;
      console.error("[Admin] Error listing users:", error);
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "Failed to list users",
      });
    }
  }),

  /**
   * ユーザーを admin に昇格（admin のみ）
   */
  promoteUser: adminProcedure
    .input(z.object({ userId: z.number() }))
    .mutation(async ({ ctx, input }) => {
      // 自分自身の権限は変更不可
      if (input.userId === ctx.user.id) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Cannot change your own role",
        });
      }

      try {
        const db = await getDb();
        if (!db) {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: "Database not available",
          });
        }

        const [user] = await db.select().from(users).where(eq(users.id, input.userId));

        if (!user) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "User not found",
          });
        }

        if (user.role === "admin") {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "User is already an admin",
          });
        }

        await db
          .update(users)
          .set({ role: "admin" })
          .where(eq(users.id, input.userId));

        console.log(`[Admin] User ${input.userId} promoted to admin by ${ctx.user.id}`);

        // 監査ログに記録
        await logUserPromote(
          ctx.user.id,
          ctx.user.name,
          input.userId,
          user.name
        );

        return { success: true, message: `User promoted to admin` };
      } catch (error) {
        if (error instanceof TRPCError) throw error;
        console.error("[Admin] Error promoting user:", error);
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to promote user",
        });
      }
    }),

  /**
   * admin ユーザーを user に降格（admin のみ）
   */
  demoteUser: adminProcedure
    .input(z.object({ userId: z.number() }))
    .mutation(async ({ ctx, input }) => {
      // 自分自身の権限は変更不可
      if (input.userId === ctx.user.id) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Cannot change your own role",
        });
      }

      try {
        const db = await getDb();
        if (!db) {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: "Database not available",
          });
        }

        const [user] = await db.select().from(users).where(eq(users.id, input.userId));

        if (!user) {
          throw new TRPCError({
            code: "NOT_FOUND",
            message: "User not found",
          });
        }

        if (user.role === "user") {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "User is already a regular user",
          });
        }

        await db
          .update(users)
          .set({ role: "user" })
          .where(eq(users.id, input.userId));

        console.log(`[Admin] User ${input.userId} demoted to user by ${ctx.user.id}`);

        // 監査ログに記録
        await logUserDemote(
          ctx.user.id,
          ctx.user.name,
          input.userId,
          user.name
        );

        return { success: true, message: `User demoted to regular user` };
      } catch (error) {
        if (error instanceof TRPCError) throw error;
        console.error("[Admin] Error demoting user:", error);
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to demote user",
        });
      }
    }),
});
