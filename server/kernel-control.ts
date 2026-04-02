/**
 * kernel-control.ts
 * =================
 * ダッシュボールからカーネルモジュールを操作するtRPCプロシージャ
 * /proc/nullsphere/config への実書き込みを実装
 */

import { z } from "zod";
import { publicProcedure, router } from "./_core/trpc";
import { TRPCError } from "@trpc/server";
import * as fs from "fs";
import * as path from "path";

// カーネル操作スキーマ
const KernelActionSchema = z.union([
  z.object({
    action: z.literal("isolate"),
    pid: z.number().min(1),
    reason: z.string().max(256),
  }),
  z.object({
    action: z.literal("whitelist"),
    process_name: z.string().max(256),
    ttl_seconds: z.number().min(60).max(86400),
  }),
  z.object({
    action: z.literal("block_network"),
    pid: z.number().min(1),
    duration_seconds: z.number().min(1).max(3600),
  }),
  z.object({
    action: z.literal("enable_tracing"),
    pid: z.number().min(1),
  }),
  z.object({
    action: z.literal("disable_tracing"),
    pid: z.number().min(1),
  }),
]);

type KernelAction = z.infer<typeof KernelActionSchema>;

/**
 * /proc/nullsphere/config にコマンドを書き込む
 * 実際の実装では、root権限で実行される必要があります
 */
async function writeKernelConfig(action: KernelAction): Promise<boolean> {
  try {
    const configPath = "/proc/nullsphere/config";

    // ファイルが存在するか確認
    if (!fs.existsSync(configPath)) {
      console.warn(`[KernelControl] ${configPath} not found. Running in demo mode.`);
      // デモモード: 実際のファイルがない場合はログのみ
      console.log("[KernelControl] Demo action:", JSON.stringify(action));
      return true;
    }

    // アクションを JSON 形式でシリアライズ
    const commandStr = JSON.stringify(action) + "\n";

    // /proc/nullsphere/config に書き込み
    // 注: 実運用では root 権限が必要
    fs.appendFileSync(configPath, commandStr);

    console.log("[KernelControl] Action written to kernel:", action);
    return true;
  } catch (error) {
    console.error("[KernelControl] Failed to write kernel config:", error);
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Failed to execute kernel action",
    });
  }
}

export const kernelControlRouter = router({
  /**
   * プロセスを隔離する
   */
  isolateProcess: publicProcedure
    .input(
      z.object({
        pid: z.number().min(1),
        reason: z.string().max(256),
      })
    )
    .mutation(async ({ input }) => {
      const success = await writeKernelConfig({
        action: "isolate",
        pid: input.pid,
        reason: input.reason,
      });

      return {
        success,
        message: `Process ${input.pid} isolation initiated`,
      };
    }),

  /**
   * プロセスをホワイトリストに追加
   */
  whitelistProcess: publicProcedure
    .input(
      z.object({
        process_name: z.string().max(256),
        ttl_seconds: z.number().min(60).max(86400).default(3600),
      })
    )
    .mutation(async ({ input }) => {
      const success = await writeKernelConfig({
        action: "whitelist",
        process_name: input.process_name,
        ttl_seconds: input.ttl_seconds,
      });

      return {
        success,
        message: `Process ${input.process_name} whitelisted for ${input.ttl_seconds}s`,
      };
    }),

  /**
   * プロセスのネットワークをブロック
   */
  blockNetwork: publicProcedure
    .input(
      z.object({
        pid: z.number().min(1),
        duration_seconds: z.number().min(1).max(3600),
      })
    )
    .mutation(async ({ input }) => {
      const success = await writeKernelConfig({
        action: "block_network",
        pid: input.pid,
        duration_seconds: input.duration_seconds,
      });

      return {
        success,
        message: `Network blocked for PID ${input.pid} for ${input.duration_seconds}s`,
      };
    }),

  /**
   * プロセスのトレーシングを有効化
   */
  enableTracing: publicProcedure
    .input(
      z.object({
        pid: z.number().min(1),
      })
    )
    .mutation(async ({ input }) => {
      const success = await writeKernelConfig({
        action: "enable_tracing",
        pid: input.pid,
      });

      return {
        success,
        message: `Tracing enabled for PID ${input.pid}`,
      };
    }),

  /**
   * プロセスのトレーシングを無効化
   */
  disableTracing: publicProcedure
    .input(
      z.object({
        pid: z.number().min(1),
      })
    )
    .mutation(async ({ input }) => {
      const success = await writeKernelConfig({
        action: "disable_tracing",
        pid: input.pid,
      });

      return {
        success,
        message: `Tracing disabled for PID ${input.pid}`,
      };
    }),

  /**
   * カーネルの状態を取得
   */
  getStatus: publicProcedure.query(async () => {
    try {
      const statusPath = "/proc/nullsphere/status";

      if (!fs.existsSync(statusPath)) {
        return {
          status: "offline",
          message: "Kernel module not loaded",
          components: [],
        };
      }

      const statusContent = fs.readFileSync(statusPath, "utf-8");
      const status = JSON.parse(statusContent);

      return {
        status: "online",
        message: "Kernel module operational",
        ...status,
      };
    } catch (error) {
      console.error("[KernelControl] Failed to read kernel status:", error);
      return {
        status: "error",
        message: "Failed to read kernel status",
      };
    }
  }),
});
