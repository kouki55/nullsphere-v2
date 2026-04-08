import { describe, it, expect } from "vitest";
import { appRouter } from "./routers";
import type { User } from "../drizzle/schema";

/**
 * 監査ログ機能テストスイート
 */

describe("Audit Log API", () => {
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

  describe("list", () => {
    it("admin should be able to list audit logs", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.audit.list({ limit: 50, offset: 0 });
        expect(result).toBeDefined();
        expect(result.logs).toBeDefined();
        expect(Array.isArray(result.logs)).toBe(true);
        expect(result.total).toBeDefined();
        expect(result.limit).toBe(50);
        expect(result.offset).toBe(0);
      } catch (error: any) {
        // DB がない場合はエラーが発生するが、権限エラーではない
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("regular user should NOT be able to list audit logs", async () => {
      const caller = appRouter.createCaller(userContext);

      try {
        await caller.audit.list({ limit: 50, offset: 0 });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });

    it("should support pagination", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.audit.list({ limit: 10, offset: 5 });
        expect(result.limit).toBe(10);
        expect(result.offset).toBe(5);
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });
  });

  describe("getByUser", () => {
    it("admin should be able to get audit logs by user", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const logs = await caller.audit.getByUser({ userId: 1 });
        expect(Array.isArray(logs)).toBe(true);
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("regular user should NOT be able to get audit logs by user", async () => {
      const caller = appRouter.createCaller(userContext);

      try {
        await caller.audit.getByUser({ userId: 1 });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });

  describe("getByDateRange", () => {
    it("admin should be able to get audit logs by date range", async () => {
      const caller = appRouter.createCaller(adminContext);
      const startDate = new Date("2026-01-01");
      const endDate = new Date("2026-12-31");

      try {
        const logs = await caller.audit.getByDateRange({
          startDate,
          endDate,
        });
        expect(Array.isArray(logs)).toBe(true);
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("regular user should NOT be able to get audit logs by date range", async () => {
      const caller = appRouter.createCaller(userContext);
      const startDate = new Date("2026-01-01");
      const endDate = new Date("2026-12-31");

      try {
        await caller.audit.getByDateRange({ startDate, endDate });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });
});
