import { int, mysqlEnum, mysqlTable, text, timestamp, varchar, json, boolean } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = mysqlTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: int("id").autoincrement().primaryKey(),
  /** Manus OAuth identifier (openId) returned from the OAuth callback. Unique per user. */
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin", "analyst", "operator"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/** 脅威イベントテーブル - 検知された脅威の記録 */
export const threats = mysqlTable("threats", {
  id: int("id").autoincrement().primaryKey(),
  threatId: varchar("threatId", { length: 64 }).notNull().unique(),
  type: mysqlEnum("type", ["intrusion", "malware", "privilege_escalation", "data_exfiltration", "lateral_movement", "reconnaissance"]).notNull(),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).notNull(),
  status: mysqlEnum("status", ["detected", "blocked", "isolated", "deceived", "traced", "resolved"]).notNull(),
  sourceIp: varchar("sourceIp", { length: 45 }).notNull(),
  sourceLat: varchar("sourceLat", { length: 20 }),
  sourceLng: varchar("sourceLng", { length: 20 }),
  sourceCountry: varchar("sourceCountry", { length: 64 }),
  sourceCity: varchar("sourceCity", { length: 128 }),
  targetHost: varchar("targetHost", { length: 256 }),
  targetPort: int("targetPort"),
  command: text("command"),
  attackerId: int("attackerId"),
  vmId: int("vmId"),
  description: text("description"),
  detectedAt: timestamp("detectedAt").defaultNow().notNull(),
  resolvedAt: timestamp("resolvedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Threat = typeof threats.$inferSelect;

/** 攻撃者プロファイルテーブル */
export const attackers = mysqlTable("attackers", {
  id: int("id").autoincrement().primaryKey(),
  attackerId: varchar("attackerId", { length: 64 }).notNull().unique(),
  ip: varchar("ip", { length: 45 }).notNull(),
  os: varchar("os", { length: 128 }),
  browser: varchar("browser", { length: 128 }),
  country: varchar("country", { length: 64 }),
  city: varchar("city", { length: 128 }),
  lat: varchar("lat", { length: 20 }),
  lng: varchar("lng", { length: 20 }),
  isp: varchar("isp", { length: 256 }),
  threatLevel: mysqlEnum("threatLevel", ["critical", "high", "medium", "low"]).notNull(),
  commandHistory: json("commandHistory"),
  firstSeen: timestamp("firstSeen").defaultNow().notNull(),
  lastSeen: timestamp("lastSeen").defaultNow().notNull(),
  isActive: boolean("isActive").default(true).notNull(),
  profileData: json("profileData"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Attacker = typeof attackers.$inferSelect;

/** セキュリティイベントログ */
export const events = mysqlTable("events", {
  id: int("id").autoincrement().primaryKey(),
  eventId: varchar("eventId", { length: 64 }).notNull().unique(),
  type: mysqlEnum("type", ["ebpf_hook", "vm_transfer", "decoy_access", "block", "alert", "system", "trace"]).notNull(),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low", "info"]).notNull(),
  source: varchar("source", { length: 128 }).notNull(),
  message: text("message").notNull(),
  details: json("details"),
  threatId: varchar("threatId", { length: 64 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Event = typeof events.$inferSelect;

/** 隔離VM (The Void) テーブル */
export const vms = mysqlTable("vms", {
  id: int("id").autoincrement().primaryKey(),
  vmId: varchar("vmId", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 128 }).notNull(),
  status: mysqlEnum("status", ["running", "stopped", "spawning", "destroying", "error"]).notNull(),
  cpuUsage: int("cpuUsage").default(0),
  memoryUsage: int("memoryUsage").default(0),
  diskUsage: int("diskUsage").default(0),
  networkIn: int("networkIn").default(0),
  networkOut: int("networkOut").default(0),
  assignedThreatId: varchar("assignedThreatId", { length: 64 }),
  attackerIp: varchar("attackerIp", { length: 45 }),
  uptime: int("uptime").default(0),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Vm = typeof vms.$inferSelect;

/** デコイ (NullHorizon) テーブル */
export const decoys = mysqlTable("decoys", {
  id: int("id").autoincrement().primaryKey(),
  decoyId: varchar("decoyId", { length: 64 }).notNull().unique(),
  type: mysqlEnum("type", ["password_file", "database", "ssh_key", "config_file", "api_key", "certificate"]).notNull(),
  name: varchar("name", { length: 256 }).notNull(),
  status: mysqlEnum("status", ["active", "inactive", "triggered", "expired"]).notNull(),
  content: text("content"),
  accessCount: int("accessCount").default(0),
  lastAccessedBy: varchar("lastAccessedBy", { length: 45 }),
  lastAccessedAt: timestamp("lastAccessedAt"),
  vmId: varchar("vmId", { length: 64 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Decoy = typeof decoys.$inferSelect;

/** 通知テーブル */
export const notifications = mysqlTable("notifications", {
  id: int("id").autoincrement().primaryKey(),
  notificationId: varchar("notificationId", { length: 64 }).notNull().unique(),
  userId: int("userId").notNull(),
  type: mysqlEnum("type", ["email", "in_app", "webhook"]).notNull(),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low"]).notNull(),
  title: varchar("title", { length: 256 }).notNull(),
  message: text("message").notNull(),
  threatId: varchar("threatId", { length: 64 }),
  isRead: boolean("isRead").default(false).notNull(),
  sentAt: timestamp("sentAt").defaultNow().notNull(),
  readAt: timestamp("readAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Notification = typeof notifications.$inferSelect;
/** 監査ログテーブル - admin操作の記録 */
export const auditLogs = mysqlTable("auditLogs", {
  id: int("id").autoincrement().primaryKey(),
  logId: varchar("logId", { length: 64 }).notNull().unique(),
  userId: int("userId").notNull(),
  userName: varchar("userName", { length: 256 }),
  action: mysqlEnum("action", [
    "user_promote",
    "user_demote",
    "vm_start",
    "vm_stop",
    "vm_reboot",
    "decoy_create",
    "decoy_delete",
    "decoy_activate",
    "decoy_deactivate",
    "process_isolate",
    "network_block",
    "tracing_enable",
    "tracing_disable",
    "process_whitelist",
    "threat_resolve",
    "threat_block",
    "settings_change",
    "permission_request_create",
    "permission_request_approve",
    "permission_request_reject",
    "other",
  ]).notNull(),
  resourceType: varchar("resourceType", { length: 64 }),
  resourceId: varchar("resourceId", { length: 64 }),
  resourceName: varchar("resourceName", { length: 256 }),
  details: json("details"),
  status: mysqlEnum("status", ["success", "failure"]).default("success").notNull(),
  errorMessage: text("errorMessage"),
  ipAddress: varchar("ipAddress", { length: 45 }),
  userAgent: text("userAgent"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type AuditLog = typeof auditLogs.$inferSelect;
export type InsertAuditLog = typeof auditLogs.$inferInsert;

/** アラート設定テーブル - 監査ログアラートの設定 */
export const alertSettings = mysqlTable("alertSettings", {
  id: int("id").autoincrement().primaryKey(),
  alertId: varchar("alertId", { length: 64 }).notNull().unique(),
  userId: int("userId").notNull(),
  actionType: mysqlEnum("actionType", [
    "user_promote",
    "user_demote",
    "vm_start",
    "vm_stop",
    "vm_reboot",
    "decoy_create",
    "decoy_delete",
    "decoy_activate",
    "decoy_deactivate",
    "process_isolate",
    "network_block",
    "tracing_enable",
    "tracing_disable",
    "threat_resolve",
    "threat_block",
    "settings_change",
    "all",
  ]).notNull(),
  notificationMethod: mysqlEnum("notificationMethod", ["email", "in-app", "webhook"]).default("in-app").notNull(),
  webhookUrl: text("webhookUrl"),
  isActive: boolean("isActive").default(true).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type AlertSetting = typeof alertSettings.$inferSelect;
export type InsertAlertSetting = typeof alertSettings.$inferInsert;

/** 権限リクエストテーブル - ユーザーの権限昇格リクエストを管理 */
export const permissionRequests = mysqlTable("permissionRequests", {
  id: int("id").autoincrement().primaryKey(),
  requestId: varchar("requestId", { length: 64 }).notNull().unique(),
  userId: int("userId").notNull(),
  requestedRole: mysqlEnum("requestedRole", ["admin", "analyst", "operator"]).notNull(),
  reason: text("reason"),
  status: mysqlEnum("status", ["pending", "approved", "rejected"]).default("pending").notNull(),
  reviewedBy: int("reviewedBy"),
  reviewedAt: timestamp("reviewedAt"),
  rejectionReason: text("rejectionReason"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type PermissionRequest = typeof permissionRequests.$inferSelect;
export type InsertPermissionRequest = typeof permissionRequests.$inferInsert;

/** リアルタイム脅威フィードテーブル - Phase 24 で受信したリアルタイムイベント */
export const threatFeeds = mysqlTable("threatFeeds", {
  id: int("id").autoincrement().primaryKey(),
  feedId: varchar("feedId", { length: 64 }).notNull().unique(),
  type: mysqlEnum("type", ["intrusion", "malware", "privilege_escalation", "data_exfiltration", "lateral_movement", "reconnaissance", "network_anomaly", "process_anomaly"]).notNull(),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low", "info"]).notNull(),
  title: varchar("title", { length: 256 }).notNull(),
  description: text("description").notNull(),
  sourceIp: varchar("sourceIp", { length: 45 }).notNull(),
  sourceCountry: varchar("sourceCountry", { length: 64 }),
  targetHost: varchar("targetHost", { length: 256 }),
  targetPort: int("targetPort"),
  command: text("command"),
  status: mysqlEnum("status", ["detected", "acknowledged", "investigating", "resolved", "false_positive"]).default("detected").notNull(),
  metadata: json("metadata"),
  detectedAt: timestamp("detectedAt").defaultNow().notNull(),
  acknowledgedAt: timestamp("acknowledgedAt"),
  resolvedAt: timestamp("resolvedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ThreatFeed = typeof threatFeeds.$inferSelect;
export type InsertThreatFeed = typeof threatFeeds.$inferInsert;

/** 脅威分析テーブル - 統計情報と傾向分析用 */
export const threatAnalytics = mysqlTable("threatAnalytics", {
  id: int("id").autoincrement().primaryKey(),
  analyticsId: varchar("analyticsId", { length: 64 }).notNull().unique(),
  period: mysqlEnum("period", ["hourly", "daily", "weekly", "monthly"]).notNull(),
  timestamp: timestamp("timestamp").notNull(),
  totalThreats: int("totalThreats").default(0).notNull(),
  criticalCount: int("criticalCount").default(0).notNull(),
  highCount: int("highCount").default(0).notNull(),
  mediumCount: int("mediumCount").default(0).notNull(),
  lowCount: int("lowCount").default(0).notNull(),
  infoCount: int("infoCount").default(0).notNull(),
  blockedCount: int("blockedCount").default(0).notNull(),
  resolvedCount: int("resolvedCount").default(0).notNull(),
  uniqueAttackers: int("uniqueAttackers").default(0).notNull(),
  topAttackType: varchar("topAttackType", { length: 64 }),
  topSourceCountry: varchar("topSourceCountry", { length: 64 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type ThreatAnalytic = typeof threatAnalytics.$inferSelect;
export type InsertThreatAnalytic = typeof threatAnalytics.$inferInsert;
