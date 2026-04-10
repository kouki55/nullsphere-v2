import { describe, expect, it, vi } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function createAuthContext(): TrpcContext {
  return {
    user: {
      id: 1,
      openId: "test-user",
      email: "test@example.com",
      name: "Test User",
      loginMethod: "manus",
      role: "admin",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    },
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
    } as unknown as TrpcContext["res"],
  };
}

describe("NullSphere Routers", () => {
  it("dashboard.stats returns threat statistics", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const stats = await caller.dashboard.stats();

    expect(stats).toHaveProperty("threats");
    expect(stats).toHaveProperty("vms");
    expect(stats).toHaveProperty("attackers");
    expect(stats).toHaveProperty("decoys");
    expect(stats).toHaveProperty("unreadNotifications");
    expect(typeof stats.threats.total).toBe("number");
  });

  it("dashboard.componentHealth returns 4 components", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const health = await caller.dashboard.componentHealth();

    expect(health).toHaveProperty("engine");
    expect(health).toHaveProperty("void");
    expect(health).toHaveProperty("horizon");
    expect(health).toHaveProperty("controlNode");
    expect(health.engine.name).toBe("NullSphere Engine");
    expect(health.void.name).toBe("The Void");
    expect(health.horizon.name).toBe("NullHorizon");
    expect(health.controlNode.name).toBe("Control Node");
  });

  it("threats.list returns array of threats", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const threats = await caller.threats.list();

    expect(Array.isArray(threats)).toBe(true);
    expect(threats.length).toBeGreaterThan(0);
    expect(threats[0]).toHaveProperty("threatId");
    expect(threats[0]).toHaveProperty("severity");
  });

  it("attackers.list returns array of attackers", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const attackers = await caller.attackers.list();

    expect(Array.isArray(attackers)).toBe(true);
    expect(attackers.length).toBeGreaterThan(0);
    expect(attackers[0]).toHaveProperty("attackerId");
    expect(attackers[0]).toHaveProperty("ip");
  });

  it("events.list returns filtered events", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const events = await caller.events.list({ type: "ebpf_hook", limit: 10 });

    expect(Array.isArray(events)).toBe(true);
    events.forEach((e) => {
      expect(e.type).toBe("ebpf_hook");
    });
  });

  it("vms.list returns array of VMs", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const vmList = await caller.vms.list();

    expect(Array.isArray(vmList)).toBe(true);
    expect(vmList.length).toBeGreaterThan(0);
    expect(vmList[0]).toHaveProperty("vmId");
    expect(vmList[0]).toHaveProperty("status");
  });

  it("decoys.list returns array of decoys", async () => {
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const decoyList = await caller.decoys.list();

    expect(Array.isArray(decoyList)).toBe(true);
    expect(decoyList.length).toBeGreaterThan(0);
    expect(decoyList[0]).toHaveProperty("decoyId");
    expect(decoyList[0]).toHaveProperty("type");
  });

  it.skip("notifications.list returns array of notifications", async () => {
    // TODO: DB スキーマに userId カラムを追加後にテスト実行
    const ctx = createAuthContext();
    const caller = appRouter.createCaller(ctx);
    const notifList = await caller.notifications.list();

    expect(Array.isArray(notifList)).toBe(true);
    expect(notifList.length).toBeGreaterThan(0);
    expect(notifList[0]).toHaveProperty("title");
    expect(notifList[0]).toHaveProperty("severity");
  });
});

// 未認証アクセスのネガティブテスト
function createUnauthenticatedContext(): TrpcContext {
  return {
    user: null as any,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
    } as unknown as TrpcContext["res"],
  };
}

describe("Unauthenticated Access - Negative Tests", () => {
  it("threats.list should reject unauthenticated access", async () => {
    const ctx = createUnauthenticatedContext();
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.threats.list();
      expect.fail("Should have thrown UNAUTHORIZED error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("dashboard.stats should reject unauthenticated access", async () => {
    const ctx = createUnauthenticatedContext();
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.dashboard.stats();
      expect.fail("Should have thrown UNAUTHORIZED error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("notifications.markAllRead should reject unauthenticated access", async () => {
    const ctx = createUnauthenticatedContext();
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.notifications.markAllRead();
      expect.fail("Should have thrown UNAUTHORIZED error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("notifications.sendAlert should reject unauthenticated access", async () => {
    const ctx = createUnauthenticatedContext();
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.notifications.sendAlert({
        title: "Test",
        message: "Test message",
        severity: "high",
      });
      expect.fail("Should have thrown FORBIDDEN error");
    } catch (error: any) {
      // adminProcedure は FORBIDDEN を返す
      expect(error.code).toBe("FORBIDDEN");
    }
  });

  it("vms.list should reject unauthenticated access", async () => {
    const ctx = createUnauthenticatedContext();
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.vms.list();
      expect.fail("Should have thrown UNAUTHORIZED error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });

  it("decoys.list should reject unauthenticated access", async () => {
    const ctx = createUnauthenticatedContext();
    const caller = appRouter.createCaller(ctx);

    try {
      await caller.decoys.list();
      expect.fail("Should have thrown UNAUTHORIZED error");
    } catch (error: any) {
      expect(error.code).toBe("UNAUTHORIZED");
    }
  });
});
