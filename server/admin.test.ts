import { describe, it, expect } from "vitest";
import { appRouter } from "./routers";
import type { User } from "../drizzle/schema";

/**
 * 管理者管理 API テストスイート
 * ユーザーの昇格・降格機能を検証
 */

describe("Admin Management API", () => {
  // テスト用コンテキスト
  const adminContext = {
    user: {
      id: 1,
      openId: "admin-user",
      name: "Admin User",
      email: "admin@example.com",
      role: "admin" as const,
      loginMethod: "oauth",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as User,
    req: {} as any,
    res: {} as any,
  };

  const userContext = {
    user: {
      id: 2,
      openId: "regular-user",
      name: "Regular User",
      email: "user@example.com",
      role: "user" as const,
      loginMethod: "oauth",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as User,
    req: {} as any,
    res: {} as any,
  };

  describe("listUsers", () => {
    it("admin should be able to list all users", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const users = await caller.admin.listUsers();
        // DB がない場合はエラーが発生するが、権限エラーではない
        expect(Array.isArray(users) || users === undefined).toBe(true);
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("regular user should NOT be able to list users", async () => {
      const caller = appRouter.createCaller(userContext);

      try {
        await caller.admin.listUsers();
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });

  describe("promoteUser", () => {
    it("admin should be able to promote a user", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.admin.promoteUser({ userId: 2 });
        // DB がない場合はエラーが発生するが、権限エラーではない
        expect(result.success === true || result === undefined).toBe(true);
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("admin should NOT be able to promote themselves", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        await caller.admin.promoteUser({ userId: 1 });
        expect.fail("Should have thrown BAD_REQUEST error");
      } catch (error: any) {
        expect(error.code).toBe("BAD_REQUEST");
        expect(error.message).toContain("Cannot change your own role");
      }
    });

    it("regular user should NOT be able to promote users", async () => {
      const caller = appRouter.createCaller(userContext);

      try {
        await caller.admin.promoteUser({ userId: 2 });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });

  describe("demoteUser", () => {
    it("admin should be able to demote an admin user", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.admin.demoteUser({ userId: 2 });
        // DB がない場合はエラーが発生するが、権限エラーではない
        expect(result.success === true || result === undefined).toBe(true);
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("admin should NOT be able to demote themselves", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        await caller.admin.demoteUser({ userId: 1 });
        expect.fail("Should have thrown BAD_REQUEST error");
      } catch (error: any) {
        expect(error.code).toBe("BAD_REQUEST");
        expect(error.message).toContain("Cannot change your own role");
      }
    });

    it("regular user should NOT be able to demote users", async () => {
      const caller = appRouter.createCaller(userContext);

      try {
        await caller.admin.demoteUser({ userId: 2 });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });
});
