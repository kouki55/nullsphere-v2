import { Server, Socket } from "socket.io";
import {
  signLog,
  verifyLogSignature,
  generateAuthToken,
  verifyAuthToken,
  validateLog,
  type LogEntry,
  type SignedLogEntry,
} from "./log-signature";

/**
 * カーネルブリッジセキュリティ層
 * 9999 ポートへの接続を認証・ログを署名検証
 * Event Storming 攻撃（ログ偽装）から守る
 */

interface AuthenticatedSocket extends Socket {
  authenticated?: boolean;
  clientId?: string;
  lastLogTime?: number;
}

/**
 * セキュリティミドルウェアを適用
 * @param io Socket.io インスタンス
 */
export function applyKernelBridgeSecurity(io: Server) {
  // 接続前の認証チェック
  io.use((socket: AuthenticatedSocket, next) => {
    const token = socket.handshake.auth.token;

    if (!token) {
      return next(new Error("Authentication token required"));
    }

    const result = verifyAuthToken(token);
    if (!result.valid) {
      return next(new Error("Invalid or expired token"));
    }

    socket.authenticated = true;
    socket.clientId = result.clientId;
    socket.lastLogTime = Date.now();

    console.log(`[KernelBridgeSecurity] Client authenticated: ${result.clientId}`);
    next();
  });

  // ログ受信時の検証
  io.on("connection", (socket: AuthenticatedSocket) => {
    console.log(`[KernelBridgeSecurity] Authenticated connection: ${socket.id}`);

    // ログ受信イベント
    socket.on("log", (data: SignedLogEntry) => {
      // 1. 認証確認
      if (!socket.authenticated) {
        console.warn(`[KernelBridgeSecurity] Unauthenticated log attempt from ${socket.id}`);
        socket.emit("error", { message: "Not authenticated" });
        return;
      }

      // 2. レート制限（DoS 対策）
      const now = Date.now();
      if (socket.lastLogTime && now - socket.lastLogTime < 10) {
        console.warn(`[KernelBridgeSecurity] Rate limit exceeded from ${socket.clientId}`);
        socket.emit("error", { message: "Rate limit exceeded" });
        return;
      }
      socket.lastLogTime = now;

      // 3. ログ検証
      const validation = validateLog(data);
      if (!validation.valid) {
        console.error(
          `[KernelBridgeSecurity] Invalid log from ${socket.clientId}: ${validation.reason}`
        );
        socket.emit("error", { message: `Invalid log: ${validation.reason}` });

        // 異常ログを記録（監査用）
        recordSecurityIncident({
          type: "invalid_log",
          clientId: socket.clientId,
          reason: validation.reason,
          logData: data,
          timestamp: now,
        });

        return;
      }

      // 4. ログを処理（署名検証済み）
      console.log(`[KernelBridgeSecurity] Valid log from ${socket.clientId}: ${data.message}`);
      socket.emit("ack", { success: true });

      // ブロードキャスト（他のリスナーに通知）
      socket.broadcast.emit("verified_log", data);
    });

    // 接続切断
    socket.on("disconnect", () => {
      console.log(`[KernelBridgeSecurity] Client disconnected: ${socket.clientId}`);
    });

    // エラーハンドリング
    socket.on("error", (error) => {
      console.error(`[KernelBridgeSecurity] Socket error from ${socket.clientId}:`, error);
    });
  });
}

/**
 * セキュリティインシデントを記録
 * @param incident インシデント情報
 */
function recordSecurityIncident(incident: {
  type: string;
  clientId?: string;
  reason?: string;
  logData?: any;
  timestamp: number;
}) {
  console.error("[KernelBridgeSecurity] SECURITY INCIDENT:", {
    type: incident.type,
    clientId: incident.clientId,
    reason: incident.reason,
    timestamp: new Date(incident.timestamp).toISOString(),
    // 本番環境では、このインシデントをセキュリティ監視システムに送信
  });

  // TODO: 本番環境では以下を実装
  // - インシデントを監査ログに記録
  // - 管理者に通知
  // - 必要に応じてクライアントを一時的にブロック
}

/**
 * ログを署名付きで送信（カーネルモジュール側で使用）
 * @param log ログエントリ
 * @returns 署名付きログエントリ
 */
export function prepareSignedLog(log: LogEntry): SignedLogEntry {
  return signLog(log);
}

/**
 * 初期認証トークンを生成（管理者が最初に実行）
 * @param clientId クライアント ID
 * @returns トークン
 */
export function generateInitialAuthToken(clientId: string): string {
  return generateAuthToken(clientId);
}

/**
 * トークンの有効期限を更新
 * @param oldToken 古いトークン
 * @returns 新しいトークン
 */
export function refreshAuthToken(oldToken: string): string | null {
  const result = verifyAuthToken(oldToken);
  if (!result.valid || !result.clientId) {
    return null;
  }

  return generateAuthToken(result.clientId);
}
