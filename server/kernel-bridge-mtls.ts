/**
 * kernel-bridge-mtls.ts
 * =====================
 * mTLS 対応の KernelBridge
 * nl_bridge との通信を暗号化・認証する
 */

import { Server as SocketIOServer } from "socket.io";
import { getDb } from "./db";
import { events, threats, attackers } from "../drizzle/schema";
import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import { signLog, verifyLogSignature, validateLog, type SignedLogEntry } from "./security/log-signature";
import { convertKernelEventToThreatFeed } from "./_core/threat-feed-processor";
import { initMTLSServer, getMTLSServer, type MTLSServer } from "./_core/mtls-server";
import type { KernelEvent } from "./kernel-bridge";

export class KernelBridgeMTLS {
  private io: SocketIOServer;
  private mtlsServer: MTLSServer | null = null;
  private running = false;
  private threatFeedBuffer: any[] = [];
  private maxBufferSize = 1000;

  constructor(io: SocketIOServer) {
    this.io = io;
  }

  /**
   * mTLS サーバーを起動
   */
  public async start(port: number = 9998) {
    const db = await getDb();
    if (!db) {
      console.warn("[KernelBridgeMTLS] Database not available");
      return;
    }

    try {
      // mTLS サーバーを初期化
      this.mtlsServer = await initMTLSServer(port);

      // クライアント接続時のハンドラ
      this.mtlsServer.on('connection', (socket, clientCert) => {
        console.log(`[KernelBridgeMTLS] nl_bridge connected: ${clientCert.subject.CN}`);
      });

      // メッセージ受信時のハンドラ
      this.mtlsServer.on('message', async (message, socket, clientCert) => {
        try {
          // ログ署名検証
          const validation = validateLog(message);
          if (!validation.valid) {
            console.warn(
              `[KernelBridgeMTLS] Invalid log signature: ${validation.reason}`
            );
            this.mtlsServer!.sendMessage(socket, {
              error: 'Invalid log signature',
              reason: validation.reason,
            });
            return;
          }

          const event: KernelEvent = message;
          await this.handleKernelEvent(event, db);

          // 脅威フィード・イベントを生成してブロードキャスト
          const threatFeedEvent = convertKernelEventToThreatFeed(event);
          this.broadcastThreatFeed(threatFeedEvent);

          // Socket.io でブロードキャスト
          this.io.emit("kernel:event", event);

          // クライアントに確認応答を送信
          this.mtlsServer!.sendMessage(socket, {
            success: true,
            eventId: event.ts,
          });
        } catch (error) {
          console.error("[KernelBridgeMTLS] Error handling message:", error);
          this.mtlsServer!.sendMessage(socket, {
            error: 'Failed to process message',
          });
        }
      });

      // クライアント切断時のハンドラ
      this.mtlsServer.on('disconnect', (clientCert) => {
        console.log(`[KernelBridgeMTLS] nl_bridge disconnected: ${clientCert.subject.CN}`);
      });

      // エラーハンドラ
      this.mtlsServer.on('error', (error) => {
        console.error("[KernelBridgeMTLS] Server error:", error);
      });

      this.running = true;
      console.log(`[KernelBridgeMTLS] Started on port ${port} with mTLS`);
    } catch (error) {
      console.error("[KernelBridgeMTLS] Failed to start:", error);
      throw error;
    }
  }

  /**
   * カーネルイベントを処理
   */
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
      };

      const eventType = eventTypeMap[event.type] || "ebpf_hook";

      // イベントをデータベースに保存
      await db.insert(events).values({
        eventId,
        type: eventType as any,
        severity: event.threat_level > 5 ? "high" : "low",
        source: event.comm,
        message: `${event.threat_name}: Process ${event.comm} (PID: ${event.pid})`,
        details: {
          pid: event.pid,
          ppid: event.ppid,
          uid: event.uid,
          gid: event.gid,
          inode: event.inode,
          container_id: event.container_id,
          sourceIp: event.net?.daddr,
          targetPort: event.net?.dport,
          args: event.args,
        },
      });

      // 脅威レベルに応じて threat レコードを作成
      if (event.threat_level > 5) {
        const threatId = `threat-${nanoid()}`;
        await db.insert(threats).values({
          threatId,
          type: "reconnaissance" as any,
          severity: "high",
          status: "detected",
          sourceIp: event.net?.daddr || "N/A",
          targetPort: event.net?.dport || 0,
          description: `Suspicious activity detected: ${event.threat_name}`,
          command: event.args,
          detectedAt: timestamp,
        });
      }
    } catch (error) {
      console.error("[KernelBridgeMTLS] Error handling kernel event:", error);
    }
  }

  /**
   * 脅威フィード・イベントをブロードキャスト
   */
  private broadcastThreatFeed(threatFeedEvent: any) {
    // バッファに追加
    this.threatFeedBuffer.push(threatFeedEvent);
    if (this.threatFeedBuffer.length > this.maxBufferSize) {
      this.threatFeedBuffer.shift();
    }

    // Socket.io でブロードキャスト
    this.io.emit("threat:feed", threatFeedEvent);
  }

  /**
   * サーバーを停止
   */
  public async stop() {
    if (this.mtlsServer) {
      await this.mtlsServer.stop();
      this.running = false;
      console.log("[KernelBridgeMTLS] Stopped");
    }
  }

  /**
   * 実行状態を確認
   */
  public isRunning(): boolean {
    return this.running;
  }
}

export default KernelBridgeMTLS;
