import { TRPCError } from "@trpc/server";
import { User } from "@shared/types";

export type UserRole = "admin" | "analyst" | "operator" | "user";

/**
 * ロール別の権限定義
 */
export const rolePermissions: Record<UserRole, string[]> = {
  admin: [
    // 管理者操作
    "user:promote",
    "user:demote",
    "user:list",
    "admin:settings",
    "admin:view_logs",
    "admin:export_logs",
    "admin:manage_alerts",
    // VM 操作
    "vm:start",
    "vm:stop",
    "vm:reboot",
    "vm:manage",
    "vm:view",
    // デコイ操作
    "decoy:create",
    "decoy:delete",
    "decoy:activate",
    "decoy:deactivate",
    "decoy:manage",
    "decoy:view",
    // カーネル操作
    "kernel:isolate",
    "kernel:block",
    "kernel:trace",
    "kernel:manage",
    // 脅威管理
    "threat:resolve",
    "threat:block",
    "threat:manage",
    "threat:view",
    // 分析
    "analysis:view",
    "analysis:full",
    // イベント
    "event:view",
    "event:manage",
    // 通知
    "notification:view",
    "notification:manage",
  ],

  analyst: [
    // 読み取り専用操作
    "threat:view",
    "event:view",
    "vm:view",
    "decoy:view",
    "admin:view_logs",
    "analysis:view",
    "notification:view",
    // 分析機能
    "analysis:full",
  ],

  operator: [
    // VM 操作
    "vm:start",
    "vm:stop",
    "vm:reboot",
    "vm:view",
    // デコイ操作
    "decoy:create",
    "decoy:delete",
    "decoy:activate",
    "decoy:deactivate",
    "decoy:view",
    // カーネル操作
    "kernel:isolate",
    "kernel:block",
    "kernel:trace",
    // 脅威管理
    "threat:resolve",
    "threat:block",
    "threat:view",
    // 分析
    "analysis:view",
    // イベント
    "event:view",
    // 通知
    "notification:view",
  ],

  user: [
    // 基本的な読み取り操作のみ
    "threat:view",
    "event:view",
    "notification:view",
    "analysis:view",
  ],
};

/**
 * ユーザーが特定の権限を持っているかチェック
 */
export function hasPermission(user: User | null, permission: string): boolean {
  if (!user) return false;

  const role = (user.role || "user") as UserRole;
  const permissions = rolePermissions[role] || [];

  return permissions.includes(permission);
}

/**
 * ユーザーが複数の権限のいずれかを持っているかチェック
 */
export function hasAnyPermission(
  user: User | null,
  permissions: string[]
): boolean {
  return permissions.some((permission) => hasPermission(user, permission));
}

/**
 * ユーザーが全ての権限を持っているかチェック
 */
export function hasAllPermissions(
  user: User | null,
  permissions: string[]
): boolean {
  return permissions.every((permission) => hasPermission(user, permission));
}

/**
 * 権限チェック用ミドルウェア工場関数
 */
export function requirePermission(permission: string) {
  return (opts: any) => {
    if (!hasPermission(opts.ctx.user, permission)) {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: `Permission denied: ${permission}`,
      });
    }
    return opts.next(opts);
  };
}

/**
 * 複数権限チェック用ミドルウェア工場関数（OR）
 */
export function requireAnyPermission(permissions: string[]) {
  return (opts: any) => {
    if (!hasAnyPermission(opts.ctx.user, permissions)) {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: `Permission denied: requires one of ${permissions.join(", ")}`,
      });
    }
    return opts.next(opts);
  };
}

/**
 * 複数権限チェック用ミドルウェア工場関数（AND）
 */
export function requireAllPermissions(permissions: string[]) {
  return (opts: any) => {
    if (!hasAllPermissions(opts.ctx.user, permissions)) {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: `Permission denied: requires all of ${permissions.join(", ")}`,
      });
    }
    return opts.next(opts);
  };
}

/**
 * ロール別の procedure 生成関数
 */
export function createRoleProcedure(role: UserRole) {
  return (opts: any) => {
    if (opts.ctx.user?.role !== role) {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: `This action requires ${role} role`,
      });
    }
    return opts.next(opts);
  };
}
