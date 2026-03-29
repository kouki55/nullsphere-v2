import { desc, eq, sql, and, like } from "drizzle-orm";
import { z } from "zod";
import { threats, attackers, events, vms, decoys, notifications } from "../drizzle/schema";
import { getDb } from "./db";
import { invokeLLM } from "./_core/llm";
import { notifyOwner } from "./_core/notification";
import { publicProcedure, router } from "./_core/trpc";

// ─── Dashboard Stats ───
export const dashboardRouter = router({
  stats: publicProcedure.query(async () => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");

    const [threatStats] = await db.select({
      total: sql<number>`COUNT(*)`,
      critical: sql<number>`SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END)`,
      high: sql<number>`SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END)`,
      medium: sql<number>`SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END)`,
      low: sql<number>`SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END)`,
      active: sql<number>`SUM(CASE WHEN status NOT IN ('resolved') THEN 1 ELSE 0 END)`,
      blocked: sql<number>`SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END)`,
      isolated: sql<number>`SUM(CASE WHEN status = 'isolated' THEN 1 ELSE 0 END)`,
    }).from(threats);

    const [vmStats] = await db.select({
      total: sql<number>`COUNT(*)`,
      running: sql<number>`SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END)`,
      avgCpu: sql<number>`AVG(cpuUsage)`,
      avgMemory: sql<number>`AVG(memoryUsage)`,
    }).from(vms);

    const [attackerStats] = await db.select({
      total: sql<number>`COUNT(*)`,
      active: sql<number>`SUM(CASE WHEN isActive = true THEN 1 ELSE 0 END)`,
    }).from(attackers);

    const [decoyStats] = await db.select({
      total: sql<number>`COUNT(*)`,
      triggered: sql<number>`SUM(CASE WHEN status = 'triggered' THEN 1 ELSE 0 END)`,
      active: sql<number>`SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END)`,
    }).from(decoys);

    const [unreadNotifs] = await db.select({
      count: sql<number>`COUNT(*)`,
    }).from(notifications).where(eq(notifications.isRead, false));

    return { threats: threatStats, vms: vmStats, attackers: attackerStats, decoys: decoyStats, unreadNotifications: unreadNotifs.count };
  }),

  // Component health
  componentHealth: publicProcedure.query(async () => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");

    const [vmHealth] = await db.select({
      running: sql<number>`SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END)`,
      total: sql<number>`COUNT(*)`,
    }).from(vms);

    return {
      engine: { name: "NullSphere Engine", status: "operational", description: "eBPFカーネルフック稼働中", uptime: 99.97 },
      void: { name: "The Void", status: vmHealth.running > 0 ? "operational" : "degraded", description: `Micro-VM ${vmHealth.running}/${vmHealth.total} 稼働中`, uptime: 99.82 },
      horizon: { name: "NullHorizon", status: "operational", description: "囮生成・逆探知エンジン稼働中", uptime: 99.95 },
      controlNode: { name: "Control Node", status: "operational", description: "ダッシュボード・API正常", uptime: 100 },
    };
  }),
});

// ─── Threats ───
export const threatRouter = router({
  list: publicProcedure.query(async () => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    return db.select().from(threats).orderBy(desc(threats.detectedAt));
  }),

  getById: publicProcedure.input(z.object({ id: z.number() })).query(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    const [result] = await db.select().from(threats).where(eq(threats.id, input.id));
    return result ?? null;
  }),
});

// ─── Attackers ───
export const attackerRouter = router({
  list: publicProcedure.query(async () => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    return db.select().from(attackers).orderBy(desc(attackers.lastSeen));
  }),

  getById: publicProcedure.input(z.object({ id: z.number() })).query(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    const [result] = await db.select().from(attackers).where(eq(attackers.id, input.id));
    return result ?? null;
  }),
});

// ─── Events ───
export const eventRouter = router({
  list: publicProcedure.input(z.object({
    type: z.enum(["ebpf_hook", "vm_transfer", "decoy_access", "block", "alert", "system", "trace"]).optional(),
    limit: z.number().min(1).max(100).default(50),
  }).optional()).query(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    const conditions = [];
    if (input?.type) conditions.push(eq(events.type, input.type));
    const query = conditions.length > 0
      ? db.select().from(events).where(and(...conditions)).orderBy(desc(events.createdAt)).limit(input?.limit ?? 50)
      : db.select().from(events).orderBy(desc(events.createdAt)).limit(input?.limit ?? 50);
    return query;
  }),
});

// ─── VMs ───
export const vmRouter = router({
  list: publicProcedure.query(async () => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    return db.select().from(vms).orderBy(desc(vms.updatedAt));
  }),

  updateStatus: publicProcedure.input(z.object({
    id: z.number(),
    status: z.enum(["running", "stopped", "spawning", "destroying"]),
  })).mutation(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    await db.update(vms).set({ status: input.status }).where(eq(vms.id, input.id));
    return { success: true };
  }),
});

// ─── Decoys ───
export const decoyRouter = router({
  list: publicProcedure.query(async () => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    return db.select().from(decoys).orderBy(desc(decoys.updatedAt));
  }),

  create: publicProcedure.input(z.object({
    type: z.enum(["password_file", "database", "ssh_key", "config_file", "api_key", "certificate"]),
    name: z.string().min(1),
    content: z.string().optional(),
    vmId: z.string().optional(),
  })).mutation(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    const decoyId = `DCY-${Date.now().toString(36).toUpperCase()}`;
    await db.insert(decoys).values({
      decoyId,
      type: input.type,
      name: input.name,
      status: "active",
      content: input.content ?? null,
      vmId: input.vmId ?? null,
    });
    return { success: true, decoyId };
  }),
});

// ─── Notifications ───
export const notificationRouter = router({
  list: publicProcedure.query(async () => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    return db.select().from(notifications).orderBy(desc(notifications.sentAt));
  }),

  markRead: publicProcedure.input(z.object({ id: z.number() })).mutation(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    await db.update(notifications).set({ isRead: true, readAt: new Date() }).where(eq(notifications.id, input.id));
    return { success: true };
  }),

  markAllRead: publicProcedure.mutation(async () => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    await db.update(notifications).set({ isRead: true, readAt: new Date() }).where(eq(notifications.isRead, false));
    return { success: true };
  }),

  sendAlert: publicProcedure.input(z.object({
    title: z.string(),
    message: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    threatId: z.string().optional(),
  })).mutation(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");
    const notificationId = `NTF-${Date.now().toString(36).toUpperCase()}`;
    await db.insert(notifications).values({
      notificationId,
      type: "in_app",
      severity: input.severity,
      title: input.title,
      message: input.message,
      threatId: input.threatId ?? null,
      isRead: false,
    });
    // Also send push notification to owner
    try {
      await notifyOwner({ title: `[${input.severity.toUpperCase()}] ${input.title}`, content: input.message });
    } catch (e) {
      console.warn("Failed to send push notification:", e);
    }
    return { success: true, notificationId };
  }),
});

// ─── LLM Analysis ───
export const analysisRouter = router({
  analyzeThreat: publicProcedure.input(z.object({
    threatId: z.string(),
  })).mutation(async ({ input }) => {
    const db = await getDb();
    if (!db) throw new Error("Database not available");

    const [threat] = await db.select().from(threats).where(eq(threats.threatId, input.threatId));
    if (!threat) throw new Error("Threat not found");

    let attacker = null;
    if (threat.attackerId) {
      const [a] = await db.select().from(attackers).where(eq(attackers.id, threat.attackerId));
      attacker = a ?? null;
    }

    const relatedEvents = await db.select().from(events).where(eq(events.threatId, input.threatId)).orderBy(desc(events.createdAt));

    const prompt = `あなたはサイバーセキュリティの専門家です。以下の脅威情報を分析し、日本語でレポートを生成してください。

## 脅威情報
- 脅威ID: ${threat.threatId}
- 種別: ${threat.type}
- 深刻度: ${threat.severity}
- ステータス: ${threat.status}
- 攻撃元IP: ${threat.sourceIp}
- 攻撃元: ${threat.sourceCountry}, ${threat.sourceCity}
- 標的: ${threat.targetHost}:${threat.targetPort}
- 実行コマンド: ${threat.command}
- 説明: ${threat.description}

## 攻撃者プロファイル
${attacker ? `- ID: ${attacker.attackerId}
- OS: ${attacker.os}
- ISP: ${attacker.isp}
- 脅威レベル: ${attacker.threatLevel}
- コマンド履歴: ${JSON.stringify(attacker.commandHistory)}
- プロファイル: ${JSON.stringify(attacker.profileData)}` : "不明"}

## 関連イベント (${relatedEvents.length}件)
${relatedEvents.map(e => `- [${e.severity}] ${e.message}`).join("\n")}

以下の項目について分析してください:
1. 攻撃パターンの分析
2. 攻撃者の意図の推定
3. 次の行動予測
4. 推奨される対策
5. リスク評価サマリー`;

    const result = await invokeLLM({
      messages: [
        { role: "system", content: "あなたはNullSphereセキュリティシステムのAI分析エンジンです。サイバー脅威を専門的に分析し、実用的なレポートを生成します。" },
        { role: "user", content: prompt },
      ],
      maxTokens: 4096,
    });

    const analysis = result.choices[0]?.message?.content ?? "分析結果を生成できませんでした。";
    return { threatId: input.threatId, analysis: typeof analysis === "string" ? analysis : JSON.stringify(analysis) };
  }),
});
