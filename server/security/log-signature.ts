import crypto from "crypto";

/**
 * ログ署名・認証モジュール
 * Event Storming 攻撃（ログ偽装）から守るため、全ログに HMAC-SHA256 署名を追加
 */

// 環境変数から署名キーを取得（本番環境では厳密に管理）
const SIGNATURE_SECRET = process.env.LOG_SIGNATURE_SECRET || "default-dev-secret-change-in-production";
const AUTH_TOKEN_SECRET = process.env.AUTH_TOKEN_SECRET || "default-dev-token-change-in-production";

/**
 * ログエントリの型定義
 */
export interface LogEntry {
  type: "info" | "warn" | "error" | "critical";
  comm: string;
  pid?: number;
  message: string;
  timestamp?: number;
  [key: string]: any;
}

/**
 * 署名付きログエントリ
 */
export interface SignedLogEntry extends LogEntry {
  signature: string;
  nonce: string;
}

/**
 * ログエントリに HMAC-SHA256 署名を追加
 * @param log ログエントリ
 * @returns 署名付きログエントリ
 */
export function signLog(log: LogEntry): SignedLogEntry {
  const nonce = crypto.randomBytes(16).toString("hex");
  const timestamp = log.timestamp || Date.now();

  // 署名対象のデータを正規化（順序を固定）
  const dataToSign = JSON.stringify({
    type: log.type,
    comm: log.comm,
    pid: log.pid,
    message: log.message,
    timestamp,
    nonce,
  });

  // HMAC-SHA256 署名を生成
  const signature = crypto
    .createHmac("sha256", SIGNATURE_SECRET)
    .update(dataToSign)
    .digest("hex");

  return {
    ...log,
    timestamp,
    signature,
    nonce,
  };
}

/**
 * ログエントリの署名を検証
 * @param log 署名付きログエントリ
 * @returns 署名が有効な場合 true、無効な場合 false
 */
export function verifyLogSignature(log: SignedLogEntry): boolean {
  if (!log.signature || !log.nonce) {
    console.warn("[LogSecurity] Missing signature or nonce");
    return false;
  }

  const timestamp = log.timestamp || Date.now();

  // 署名対象のデータを再構築
  const dataToSign = JSON.stringify({
    type: log.type,
    comm: log.comm,
    pid: log.pid,
    message: log.message,
    timestamp,
    nonce: log.nonce,
  });

  // 署名を再計算
  const expectedSignature = crypto
    .createHmac("sha256", SIGNATURE_SECRET)
    .update(dataToSign)
    .digest("hex");

  // タイムスタンプ検証（5分以内のログのみ受け入れ）
  const currentTime = Date.now();
  const timeDiff = Math.abs(currentTime - timestamp);
  if (timeDiff > 5 * 60 * 1000) {
    console.warn(`[LogSecurity] Timestamp out of range: ${timeDiff}ms`);
    return false;
  }

  // 署名を比較（タイミング攻撃対策）
  // バッファ長が異なる場合は false を返す
  if (log.signature.length !== expectedSignature.length) {
    return false;
  }
  return crypto.timingSafeEqual(
    Buffer.from(log.signature),
    Buffer.from(expectedSignature)
  );
}

/**
 * 認証トークンを生成
 * @param clientId クライアント ID
 * @returns トークン
 */
export function generateAuthToken(clientId: string): string {
  const payload = {
    clientId,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24時間有効
  };

  const payloadStr = JSON.stringify(payload);
  const signature = crypto
    .createHmac("sha256", AUTH_TOKEN_SECRET)
    .update(payloadStr)
    .digest("hex");

  return Buffer.from(`${payloadStr}.${signature}`).toString("base64");
}

/**
 * 認証トークンを検証
 * @param token トークン
 * @returns 有効な場合 { valid: true, clientId: string }、無効な場合 { valid: false }
 */
export function verifyAuthToken(
  token: string
): { valid: boolean; clientId?: string } {
  try {
    const decoded = Buffer.from(token, "base64").toString("utf-8");
    const [payloadStr, signature] = decoded.split(".");

    if (!payloadStr || !signature) {
      return { valid: false };
    }

    // 署名を検証
    const expectedSignature = crypto
      .createHmac("sha256", AUTH_TOKEN_SECRET)
      .update(payloadStr)
      .digest("hex");

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) {
      return { valid: false };
    }

    // ペイロードをパース
    const payload = JSON.parse(payloadStr);

    // 有効期限を確認
    if (payload.expiresAt < Date.now()) {
      return { valid: false };
    }

    return { valid: true, clientId: payload.clientId };
  } catch (error) {
    console.error("[LogSecurity] Token verification error:", error);
    return { valid: false };
  }
}

/**
 * ログの異常を検知
 * @param log ログエントリ
 * @returns 異常の種類（null = 正常）
 */
export function detectLogAnomaly(log: LogEntry): string | null {
  // 1. 疑わしいコマンド名（例：偽装された systemd）
  if (log.comm === "systemd" && log.message.includes("盗んだ")) {
    return "suspicious_command_name";
  }

  // 2. 異常に長いメッセージ（ペイロード注入の可能性）
  if (log.message.length > 10000) {
    return "oversized_message";
  }

  // 3. バイナリデータの混在（JSON 破損の可能性）
  if (!/^[\x20-\x7E\n\r\t]*$/.test(log.message)) {
    return "binary_data_detected";
  }

  // 4. SQLi や XSS パターン
  if (/['";`<>]/.test(log.message) && /union|select|script/i.test(log.message)) {
    return "injection_pattern_detected";
  }

  return null;
}

/**
 * ログ検証パイプライン
 * @param log ログエントリ
 * @returns { valid: boolean, reason?: string }
 */
export function validateLog(log: SignedLogEntry): { valid: boolean; reason?: string } {
  // 1. 署名検証
  if (!verifyLogSignature(log)) {
    return { valid: false, reason: "invalid_signature" };
  }

  // 2. 異常検知
  const anomaly = detectLogAnomaly(log);
  if (anomaly) {
    return { valid: false, reason: `anomaly_detected: ${anomaly}` };
  }

  return { valid: true };
}
