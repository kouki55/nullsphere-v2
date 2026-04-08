import { describe, it, expect } from "vitest";
import { appRouter } from "./routers";
import type { User } from "../drizzle/schema";

/**
 * RBAC テストスイート
 * admin と analyst の権限分離を検証
 */

describe("RBAC - Role-Based Access Control", () => {
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

  const analystContext = {
    user: {
      id: 2,
      openId: "analyst-user",
      name: "Analyst User",
      email: "analyst@example.com",
      role: "user" as const,
      loginMethod: "oauth",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as User,
    req: {} as any,
    res: {} as any,
  };

  describe("VM Management - updateStatus", () => {
    it("admin should be able to update VM status", async () => {
      const caller = appRouter.createCaller(adminContext);

      // adminProcedure なので admin は成功する
      // 注: 実際のDB操作は行わないため、エラーハンドリングのみ確認
      try {
        await caller.vms.updateStatus({ id: 1, status: "running" });
        // DB がない場合はエラーが発生するが、権限エラーではない
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("analyst should NOT be able to update VM status", async () => {
      const caller = appRouter.createCaller(analystContext);

      // adminProcedure なので analyst は FORBIDDEN エラー
      try {
        await caller.vms.updateStatus({ id: 1, status: "running" });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
        expect(error.message).toContain("permission");
      }
    });
  });

  describe("Decoy Control - create", () => {
    it("admin should be able to create decoy", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        await caller.decoys.create({
          type: "password_file",
          name: "test-decoy",
          content: "fake password",
          vmId: "VM-001",
        });
        // DB がない場合はエラーが発生するが、権限エラーではない
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("analyst should NOT be able to create decoy", async () => {
      const caller = appRouter.createCaller(analystContext);

      try {
        await caller.decoys.create({
          type: "password_file",
          name: "test-decoy",
          content: "fake password",
          vmId: "VM-001",
        });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
        expect(error.message).toContain("permission");
      }
    });
  });

  describe("Kernel Control - isolateProcess", () => {
    it("admin should be able to isolate process", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        await caller.kernel.isolateProcess({
          pid: 1234,
          reason: "Suspicious activity",
        });
        // デモモードで成功するか、DB エラーが発生
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("analyst should NOT be able to isolate process", async () => {
      const caller = appRouter.createCaller(analystContext);

      try {
        await caller.kernel.isolateProcess({
          pid: 1234,
          reason: "Suspicious activity",
        });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });

  describe("Kernel Control - blockNetwork", () => {
    it("admin should be able to block network", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        await caller.kernel.blockNetwork({
          pid: 1234,
          duration_seconds: 300,
        });
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("analyst should NOT be able to block network", async () => {
      const caller = appRouter.createCaller(analystContext);

      try {
        await caller.kernel.blockNetwork({
          pid: 1234,
          duration_seconds: 300,
        });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });

  describe("Kernel Control - enableTracing", () => {
    it("admin should be able to enable tracing", async () => {
      const caller = appRouter.createCaller(adminContext);

      try {
        await caller.kernel.enableTracing({ pid: 1234 });
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("analyst should NOT be able to enable tracing", async () => {
      const caller = appRouter.createCaller(analystContext);

      try {
        await caller.kernel.enableTracing({ pid: 1234 });
        expect.fail("Should have thrown FORBIDDEN error");
      } catch (error: any) {
        expect(error.code).toBe("FORBIDDEN");
      }
    });
  });

  describe("Read-only operations - should be accessible to both roles", () => {
    it("analyst should be able to read threats", async () => {
      const caller = appRouter.createCaller(analystContext);

      try {
        await caller.threats.list();
      } catch (error: any) {
        // DB エラーは許容、権限エラーは不許容
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("analyst should be able to read events", async () => {
      const caller = appRouter.createCaller(analystContext);

      try {
        await caller.events.list();
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("analyst should be able to read VM list", async () => {
      const caller = appRouter.createCaller(analystContext);

      try {
        await caller.vms.list();
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });

    it("analyst should be able to read decoy list", async () => {
      const caller = appRouter.createCaller(analystContext);

      try {
        await caller.decoys.list();
      } catch (error: any) {
        expect(error.code).not.toBe("FORBIDDEN");
      }
    });
  });
});
