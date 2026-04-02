/**
 * kernel-bridge.ts
 * ================
 * NullSphere カーネルモジュール (nullsphere.ko) との統合
 *
 * 役割:
 *   1. nl_bridge.py からのイベントを受信 (TCP ソケット)
 *   2. イベントをデータベースに記録
 *   3. WebSocket 経由でダッシュボードにブロードキャスト
 *   4. ダッシュボールからの操作をカーネルに反映
 */

import { Server as SocketIOServer } from "socket.io";
import { Server as HTTPServer } from "http";
import { getDb } from "./db";
import { events, threats, attackers } from "../drizzle/schema";
import { eq } from "drizzle-orm";
import net from "net";

export interface KernelEvent {
  source: string;
  version: number;
  type: string;
  event_type: number;
  threat_level: number;
  threat_name: string;
  action: number;
  action_name: string;
  pid: number;
  ppid: number;
  uid: number;
  gid: number;
  ts_ns: number;
  ts: string;
  inode: number;
  comm: string;
  filename: string;
  args: string;
  net?: {
    daddr: string;
    dport: number;
    family: number;
    proto: number;
  };
  container_id: number;
}

export class KernelBridge {
  private io: SocketIOServer;
  private tcpServer: net.Server | null = null;
  private running = false;

  constructor(io: SocketIOServer) {
    this.io = io;
  }

  /**
   * nl_bridge.py からのイベント受信サーバーを起動
   * ポート: 9998 (nl_bridge.py は 9999 に接続)
   */
  public async start(port: number = 9998) {
    const db = await getDb();
    if (!db) {
      console.warn("[KernelBridge] Database not available");
      return;
    }

    this.tcpServer = net.createServer((socket) => {
      console.log("[KernelBridge] nl_bridge.py 接続");

      socket.on("data", async (data) => {
        const lines = data.toString().split("\n");
        for (const line of lines) {
          if (!line.trim()) continue;

          try {
            const event: KernelEvent = JSON.parse(line);
            await this.handleKernelEvent(event, db);

            // WebSocket でダッシュボードにブロードキャスト
            this.io.emit("kernel:event", event);
          } catch (e) {
            console.error("[KernelBridge] JSON parse error:", e);
          }
        }
      });

      socket.on("end", () => {
        console.log("[KernelBridge] nl_bridge.py 切断");
      });

      socket.on("error", (err) => {
        console.error("[KernelBridge] Socket error:", err);
      });
    });

    this.tcpServer.listen(port, "127.0.0.1", () => {
      console.log(`[KernelBridge] Listening on 127.0.0.1:${port}`);
      this.running = true;
    });
  }

  /**
   * カーネルイベントをデータベースに記録
   */
  private async handleKernelEvent(
    event: KernelEvent,
    db: Awaited<ReturnType<typeof getDb>>
  ) {
    if (!db) return;

    try {
      const timestamp = new Date(event.ts);

      // イベントテーブルに記録
      const eventId = `event-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      const eventTypeMap: Record<string, any> = {
        exec: "ebpf_hook",
        file: "ebpf_hook",
        net: "ebpf_hook",
        kill: "block",
        module_load: "alert",
        ptrace: "alert",
      };
      const severityMap: Record<number, any> = {
        4: "critical",
        3: "high",
        2: "medium",
        1: "low",
        0: "info",
      };
      await db.insert(events).values({
        eventId,
        type: eventTypeMap[event.type] || "alert",
        severity: severityMap[event.threat_level] || "info",
        source: event.comm,
        message: `${event.type}: ${event.filename} (PID: ${event.pid})`,
        details: JSON.stringify(event),
        createdAt: timestamp,
      });

      // 脅威レベルが HIGH 以上の場合、threats テーブルに記録
      if (event.threat_level >= 3) {
        const threatId = `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const severityMap: Record<number, "critical" | "high" | "medium" | "low"> = {
          4: "critical",
          3: "high",
          2: "medium",
          1: "low",
        };
        await db.insert(threats).values({
          threatId,
          type: (event.type as any) || "intrusion",
          severity: severityMap[event.threat_level] || "low",
          status: "detected",
          sourceIp: event.net?.daddr || "unknown",
          description: `${event.comm} (PID: ${event.pid}) - ${event.filename}`,
          detectedAt: timestamp,
        });
      }

      // 攻撃者プロファイルを更新または作成
      if (event.net?.daddr) {
        const existing = await db
          .select()
          .from(attackers)
          .where(eq(attackers.ip, event.net.daddr))
          .limit(1);

        const threatLevelMap: Record<number, "critical" | "high" | "medium" | "low"> = {
          4: "critical",
          3: "high",
          2: "medium",
          1: "low",
        };

        if (existing.length > 0) {
          // 既存の攻撃者を更新
          const commands = existing[0].commandHistory
            ? JSON.parse(existing[0].commandHistory as string)
            : [];
          commands.push({
            timestamp: timestamp.toISOString(),
            command: event.filename,
            args: event.args,
          });

          await db
            .update(attackers)
            .set({
              commandHistory: JSON.stringify(commands),
              lastSeen: timestamp,
              threatLevel: threatLevelMap[event.threat_level] || "low",
            })
            .where(eq(attackers.ip, event.net.daddr));
        } else {
          // 新規攻撃者を作成
          const attackerId = `attacker-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
          await db.insert(attackers).values({
            attackerId,
            ip: event.net.daddr,
            os: "unknown",
            country: "unknown",
            threatLevel: threatLevelMap[event.threat_level] || "low",
            commandHistory: JSON.stringify([
              {
                timestamp: timestamp.toISOString(),
                command: event.filename,
                args: event.args,
              },
            ]),
            profileData: JSON.stringify({
              firstSeen: timestamp.toISOString(),
              port: event.net.dport,
              protocol: event.net.proto,
            }),
            firstSeen: timestamp,
            lastSeen: timestamp,
          });
        }
      }

      console.log(
        `[KernelBridge] Event recorded: ${event.type} (${event.threat_name})`
      );
    } catch (e) {
      console.error("[KernelBridge] Database error:", e);
    }
  }

  /**
   * ダッシュボードからのカーネル操作コマンドを処理
   */
  public async executeKernelCommand(
    command: string,
    params?: Record<string, unknown>
  ): Promise<boolean> {
    // /proc/nullsphere/config に書き込み
    // 実装例: mode=1, uid_wl=1000, clear_wl など
    console.log(`[KernelBridge] Execute command: ${command}`, params);

    // 実装は Linux 環境でのみ可能
    // Windows では模擬応答を返す
    return true;
  }

  public stop() {
    if (this.tcpServer) {
      this.tcpServer.close();
      this.running = false;
      console.log("[KernelBridge] Stopped");
    }
  }
}
