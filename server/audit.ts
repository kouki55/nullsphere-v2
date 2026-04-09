import { getDb } from "./db";
import { auditLogs } from "../drizzle/schema";
import { randomUUID } from "crypto";
import type { InsertAuditLog } from "../drizzle/schema";

/**
 * 監査ログを記録するヘルパー関数
 * @param log 監査ログの内容
 */
export async function logAudit(log: Omit<InsertAuditLog, "logId" | "createdAt">) {
  try {
    const db = await getDb();
    if (!db) {
      console.warn("[Audit] Database not available, skipping audit log");
      return;
    }

    const logId = randomUUID();
    await db.insert(auditLogs).values({
      ...log,
      logId,
    });

    console.log(`[Audit] ${log.action} by user ${log.userId}: ${log.resourceType}/${log.resourceId}`);
  } catch (error) {
    console.error("[Audit] Failed to log audit entry:", error);
    // 監査ログの失敗は操作を中断しない
  }
}

/**
 * ユーザー昇格を記録
 */
export async function logUserPromote(
  adminId: number,
  adminName: string | null | undefined,
  targetUserId: number,
  targetUserName: string | null | undefined,
  ipAddress?: string,
  userAgent?: string
) {
  await logAudit({
    userId: adminId,
    userName: adminName || `User ${adminId}`,
    action: "user_promote",
    resourceType: "user",
    resourceId: targetUserId.toString(),
    resourceName: targetUserName || `User ${targetUserId}`,
    details: { targetUserId, targetUserName },
    status: "success",
    ipAddress,
    userAgent,
  });
}

/**
 * ユーザー降格を記録
 */
export async function logUserDemote(
  adminId: number,
  adminName: string | null | undefined,
  targetUserId: number,
  targetUserName: string | null | undefined,
  ipAddress?: string,
  userAgent?: string
) {
  await logAudit({
    userId: adminId,
    userName: adminName || `User ${adminId}`,
    action: "user_demote",
    resourceType: "user",
    resourceId: targetUserId.toString(),
    resourceName: targetUserName || `User ${targetUserId}`,
    details: { targetUserId, targetUserName },
    status: "success",
    ipAddress,
    userAgent,
  });
}

/**
 * VM 操作を記録
 */
export async function logVmOperation(
  adminId: number,
  adminName: string | null | undefined,
  vmId: number,
  vmName: string | null | undefined,
  action: "vm_start" | "vm_stop" | "vm_reboot",
  ipAddress?: string,
  userAgent?: string
) {
  await logAudit({
    userId: adminId,
    userName: adminName || `User ${adminId}`,
    action,
    resourceType: "vm",
    resourceId: vmId.toString(),
    resourceName: vmName || `VM ${vmId}`,
    details: { vmId, vmName },
    status: "success",
    ipAddress,
    userAgent,
  });
}

/**
 * デコイ操作を記録
 */
export async function logDecoyOperation(
  adminId: number,
  adminName: string | null | undefined,
  decoyId: string,
  decoyName: string | null | undefined,
  action: "decoy_create" | "decoy_delete" | "decoy_activate" | "decoy_deactivate",
  ipAddress?: string,
  userAgent?: string
) {
  await logAudit({
    userId: adminId,
    userName: adminName || `User ${adminId}`,
    action,
    resourceType: "decoy",
    resourceId: decoyId,
    resourceName: decoyName || `Decoy ${decoyId}`,
    details: { decoyId, decoyName },
    status: "success",
    ipAddress,
    userAgent,
  });
}

/**
 * カーネル操作を記録
 */
export async function logKernelOperation(
  adminId: number,
  adminName: string | null | undefined,
  processId: string,
  processName: string | null | undefined,
  action: "process_isolate" | "network_block" | "tracing_enable" | "tracing_disable" | "process_whitelist",
  ipAddress?: string,
  userAgent?: string
) {
  await logAudit({
    userId: adminId,
    userName: adminName || `User ${adminId}`,
    action,
    resourceType: "process",
    resourceId: processId,
    resourceName: processName || `Process ${processId}`,
    details: { processId, processName },
    status: "success",
    ipAddress,
    userAgent,
  });
}

/**
 * 脅威操作を記録
 */
export async function logThreatOperation(
  adminId: number,
  adminName: string | null | undefined,
  threatId: string,
  threatName: string | null | undefined,
  action: "threat_resolve" | "threat_block",
  ipAddress?: string,
  userAgent?: string
) {
  await logAudit({
    userId: adminId,
    userName: adminName || `User ${adminId}`,
    action,
    resourceType: "threat",
    resourceId: threatId,
    resourceName: threatName || `Threat ${threatId}`,
    details: { threatId, threatName },
    status: "success",
    ipAddress,
    userAgent,
  });
}

/**
 * 操作失敗を記録
 */
export async function logAuditFailure(
  adminId: number,
  adminName: string | null | undefined,
  action: InsertAuditLog["action"],
  resourceType: string,
  resourceId: string,
  resourceName: string | null | undefined,
  errorMessage: string,
  ipAddress?: string,
  userAgent?: string
) {
  await logAudit({
    userId: adminId,
    userName: adminName || `User ${adminId}`,
    action,
    resourceType,
    resourceId,
    resourceName,
    status: "failure",
    errorMessage,
    ipAddress,
    userAgent,
  });
}
