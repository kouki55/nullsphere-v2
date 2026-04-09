import { nanoid } from "nanoid";
import { Server as SocketIOServer } from "socket.io";
import { Server as HTTPServer } from "http";
import { getDb } from "./db";
import { events, threats, attackers } from "../drizzle/schema";
import { eq } from "drizzle-orm";
import net from "net";
import { signLog, verifyLogSignature, generateAuthToken, validateLog, type SignedLogEntry } from "./security/log-signature";
import { applyKernelBridgeSecurity } from "./security/kernel-bridge-security";

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
            // ログ署名検証
            const logData = JSON.parse(line);
            const validation = validateLog(logData);
            if (!validation.valid) {
              console.warn(
                `[KernelBridge] Invalid log signature: ${validation.reason}`
              );
              continue;
            }

            const event: KernelEvent = logData;
            await this.handleKernelEvent(event, db);

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

  private async handleKernelEvent(
    event: KernelEvent,
    db: Awaited<ReturnType<typeof getDb>>
  ) {
    if (!db) return;

    try {
      const timestamp = new Date(event.ts);
      const eventId = `event-${nanoid()}`;
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

      if (event.threat_level >= 3) {
        const threatId = `threat-${nanoid()}`;
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
          let commands: any[] = Array.isArray(existing[0].commandHistory) ? existing[0].commandHistory : [];
          if (typeof commands === "string") {
            commands = JSON.parse(commands);
          }
          commands.push({
            timestamp: timestamp.toISOString(),
            command: event.filename,
            args: event.args,
          });

          await db
            .update(attackers)
            .set({
              commandHistory: commands,
              lastSeen: timestamp,
              threatLevel: threatLevelMap[event.threat_level] || "low",
            })
            .where(eq(attackers.ip, event.net.daddr));
        } else {
          const attackerId = `attacker-${nanoid()}`;
          await db.insert(attackers).values({
            attackerId,
            ip: event.net.daddr,
            os: "unknown",
            country: "unknown",
            threatLevel: threatLevelMap[event.threat_level] || "low",
            commandHistory: [
              {
                timestamp: timestamp.toISOString(),
                command: event.filename,
                args: event.args,
              },
            ],
            profileData: {
              firstSeen: timestamp.toISOString(),
              port: event.net.dport,
              protocol: event.net.proto,
            },
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

  public async executeKernelCommand(
    command: string,
    params?: Record<string, unknown>
  ): Promise<boolean> {
    console.log(`[KernelBridge] Execute command: ${command}`, params);
    return true;
  }

  public stop() {
    if (this.tcpServer) {
      this.tcpServer.close();
      this.running = false;
      console.log("[KernelBridge] Stopped");
    }
  }

  public generateLogSignature(logData: string): string {
    return JSON.stringify(signLog(JSON.parse(logData)));
  }

  public getAuthToken(): string {
    return generateAuthToken("kernel-bridge");
  }
}
