/**
 * useKernelEvents.ts
 * ==================
 * Socket.io 経由でカーネルイベントをリアルタイム受信するカスタムフック
 */

import { useEffect, useState, useCallback } from "react";
import { io, Socket } from "socket.io-client";

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

export function useKernelEvents() {
  const [events, setEvents] = useState<KernelEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    // Socket.io クライアントを初期化
    const newSocket = io(window.location.origin, {
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 5,
    });

    newSocket.on("connect", () => {
      console.log("[useKernelEvents] Connected to kernel bridge");
      setIsConnected(true);
    });

    newSocket.on("disconnect", () => {
      console.log("[useKernelEvents] Disconnected from kernel bridge");
      setIsConnected(false);
    });

    // カーネルイベント受信
    newSocket.on("kernel:event", (event: KernelEvent) => {
      console.log("[useKernelEvents] Received event:", event);
      setEvents((prev) => [event, ...prev.slice(0, 99)]); // 最新100件を保持
    });

    newSocket.on("connect_error", (error: any) => {
      console.error("[useKernelEvents] Connection error:", error);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, []);

  const sendCommand = useCallback(
    (command: string, params?: Record<string, unknown>) => {
      if (socket && isConnected) {
        socket.emit("kernel:command", command, params);
      }
    },
    [socket, isConnected]
  );

  return {
    events,
    isConnected,
    sendCommand,
  };
}
