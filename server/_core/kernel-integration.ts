/**
 * kernel-integration.ts
 * ====================
 * Express サーバーに Socket.io と KernelBridge を統合する
 */

import { Server as HTTPServer } from "http";
import { Server as SocketIOServer } from "socket.io";
import { KernelBridge } from "../kernel-bridge";

export function setupKernelIntegration(httpServer: HTTPServer) {
  // Socket.io サーバーを初期化
  const io = new SocketIOServer(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"],
    },
  });

  // KernelBridge を初期化
  const kernelBridge = new KernelBridge(io);

  // Socket.io 接続イベント
  io.on("connection", (socket) => {
    console.log(`[Socket.io] Client connected: ${socket.id}`);

    // クライアントがカーネル操作をリクエスト
    socket.on("kernel:command", async (command: string, params?: any) => {
      console.log(`[Socket.io] Kernel command: ${command}`, params);
      const result = await kernelBridge.executeKernelCommand(command, params);
      socket.emit("kernel:command:response", { success: result, command });
    });

    socket.on("disconnect", () => {
      console.log(`[Socket.io] Client disconnected: ${socket.id}`);
    });
  });

  // KernelBridge を起動（nl_bridge.py からのイベント受信）
  kernelBridge.start(9998);

  return { io, kernelBridge };
}
