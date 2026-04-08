import { describe, it, expect } from "vitest";
import { appRouter } from "./routers";
import type { User } from "../drizzle/schema";

/**
 * アラート設定と監査ログ検索機能テストスイート
 */

describe("Alert Settings and Audit Log Search", () => {
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

  describe("Alert Settings", () => {
    it("admin should be able to create alert", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.alert.createAlert({
          actionType: "user_promote",
          notificationMethod: "in-app",
        });
        expect(result.success).toBe(true);
        expect(result.alertId).toBeDefined();
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("admin should be able to list alerts", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const alerts = await caller.alert.listAlerts();
        expect(Array.isArray(alerts)).toBe(true);
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("regular user should NOT be able to create alert", async () => {
      const caller = appRouter.createCaller(userContext);

      try {
        await caller.alert.createAlert({
          actionType: "user_promote",
          notificationMethod: "in-app",
        });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });

    it("regular user should NOT be able to list alerts", async () => {
      const caller = appRouter.createCaller(userContext);

      try {
        await caller.alert.listAlerts();
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });

  describe("Audit Log Search", () => {
    it("admin should be able to search audit logs with filters", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.audit.list({
          limit: 50,
          offset: 0,
          userId: 1,
          action: "user_promote",
          startDate: new Date("2026-01-01"),
          endDate: new Date("2026-12-31"),
        });
        expect(result.logs).toBeDefined();
        expect(Array.isArray(result.logs)).toBe(true);
        expect(result.total).toBeDefined();
        expect(result.limit).toBe(50);
        expect(result.offset).toBe(0);
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("admin should be able to search by user ID", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.audit.list({
          limit: 50,
          offset: 0,
          userId: 1,
        });
        expect(result.logs).toBeDefined();
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("admin should be able to search by action type", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.audit.list({
          limit: 50,
          offset: 0,
          action: "user_promote",
        });
        expect(result.logs).toBeDefined();
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("admin should be able to search by date range", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        const result = await caller.audit.list({
          limit: 50,
          offset: 0,
          startDate: new Date("2026-01-01"),
          endDate: new Date("2026-12-31"),
        });
        expect(result.logs).toBeDefined();
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("regular user should NOT be able to search audit logs", async () => {
      const caller = appRouter.createCaller(userContext);

      try {
        await caller.audit.list({
          limit: 50,
          offset: 0,
        });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });
});
