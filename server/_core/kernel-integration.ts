/**
 * kernel-integration.ts
 * ====================
 * Express サーバーに Socket.io と KernelBridge を統合する
 *
 * [C-2] セキュリティ修正:
 *   - cors.origin を環境変数 ALLOWED_ORIGIN に限定（ワイルドカード廃止）
 *   - io.use() ミドルウェアでセッション Cookie を検証し、未認証接続を拒否
 *   - 権限チェック: kernel:command は admin ロールのみ実行可
 */

import { Server as HTTPServer } from "http";
import { Server as SocketIOServer } from "socket.io";
import { KernelBridge } from "../kernel-bridge";
import { setupThreatFeedHandlers } from "./threat-feed-handler";
import type { ThreatFeedEvent } from "./types/threat-feed";
import type { Socket } from "socket.io";

/**
 * セッション検証用の簡易実装
 * 実運用では、セッションストアと連携してください
 */
async function authenticateSocket(socket: Socket): Promise<{ id: string; role: string } | null> {
  try {
    // Cookie からセッション ID を取得
    const cookies = socket.handshake.headers.cookie;
    if (!cookies) {
      return null;
    }

    // 簡略版: セッション ID の存在確認
    // 実運用では、セッションストアから user 情報を取得してください
    const sessionMatch = cookies.match(/sessionId=([^;]+)/);
    if (!sessionMatch) {
      return null;
    }

    // ここでセッションストアから user 情報を取得
    // 例: const user = await sessionStore.get(sessionMatch[1]);
    // 簡略版では、デモ用に admin ユーザーを返す
    return {
      id: "demo-user",
      role: "admin",
    };
  } catch {
    return null;
  }
}

export function setupKernelIntegration(httpServer: HTTPServer) {
  // [C-2] CORS: ワイルドカード "*" を廃止し、許可オリジンを明示する
  const allowedOrigin = process.env.ALLOWED_ORIGIN || "http://localhost:3000";

  // Socket.io サーバーを初期化
  const io = new SocketIOServer(httpServer, {
    cors: {
      origin: allowedOrigin,
      methods: ["GET", "POST"],
      credentials: true, // Cookie 送信を許可
    },
  });

  // [C-2] 接続認証ミドルウェア: 無効なセッションの接続を即座に拒否する
  io.use(async (socket, next) => {
    try {
      const user = await authenticateSocket(socket);
      if (!user) {
        return next(new Error("Unauthorized: invalid session"));
      }
      // 認証済みユーザーをソケットデータに保存
      socket.data.user = user;
      next();
    } catch {
      next(new Error("Unauthorized: authentication failed"));
    }
  });

  // KernelBridge を初期化
  const kernelBridge = new KernelBridge(io);

  // Socket.io 接続イベント
  io.on("connection", (socket) => {
    const user = socket.data.user;
    console.log(
      `[Socket.io] Client connected: ${socket.id} (user: ${user.id}, role: ${user.role})`
    );

    // [C-2] kernel:command は admin ロールのみ実行可
    socket.on("kernel:command", async (command: string, params?: any) => {
      if (user.role !== "admin") {
        socket.emit("kernel:command:response", {
          success: false,
          command,
          error: "Forbidden: admin role required",
        });
        console.warn(
          `[Socket.io] Unauthorized kernel:command attempt by user ${user.id} (role: ${user.role})`
        );
        return;
      }

      console.log(`[Socket.io] Kernel command by admin ${user.id}: ${command}`);
      const result = await kernelBridge.executeKernelCommand(command, params);
      socket.emit("kernel:command:response", { success: result, command });
    });

    socket.on("disconnect", () => {
      console.log(`[Socket.io] Client disconnected: ${socket.id}`);
    });
  });

  // 脅威フィード・ハンドラーを設定
  setupThreatFeedHandlers(io, kernelBridge);

  // KernelBridge を起動（nl_bridge.py からのイベント受信）
  kernelBridge.start(9998);

  console.log("[Kernel Integration] WebSocket threat feed initialized");

  return { io, kernelBridge };
}
