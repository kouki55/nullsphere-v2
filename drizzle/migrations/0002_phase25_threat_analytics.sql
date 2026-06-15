-- Phase 25: 脅威データの永続化と分析機能用テーブル

-- リアルタイム脅威フィードテーブル
CREATE TABLE IF NOT EXISTS `threatFeeds` (
  `id` int AUTO_INCREMENT PRIMARY KEY,
  `feedId` varchar(64) NOT NULL UNIQUE,
  `type` enum('intrusion', 'malware', 'privilege_escalation', 'data_exfiltration', 'lateral_movement', 'reconnaissance', 'network_anomaly', 'process_anomaly') NOT NULL,
  `severity` enum('critical', 'high', 'medium', 'low', 'info') NOT NULL,
  `title` varchar(256) NOT NULL,
  `description` text NOT NULL,
  `sourceIp` varchar(45) NOT NULL,
  `sourceCountry` varchar(64),
  `targetHost` varchar(256),
  `targetPort` int,
  `command` text,
  `status` enum('detected', 'acknowledged', 'investigating', 'resolved', 'false_positive') NOT NULL DEFAULT 'detected',
  `metadata` json,
  `detectedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `acknowledgedAt` timestamp,
  `resolvedAt` timestamp,
  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_severity` (`severity`),
  INDEX `idx_sourceIp` (`sourceIp`),
  INDEX `idx_detectedAt` (`detectedAt`),
  INDEX `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 脅威分析テーブル（統計情報用）
CREATE TABLE IF NOT EXISTS `threatAnalytics` (
  `id` int AUTO_INCREMENT PRIMARY KEY,
  `analyticsId` varchar(64) NOT NULL UNIQUE,
  `period` enum('hourly', 'daily', 'weekly', 'monthly') NOT NULL,
  `timestamp` timestamp NOT NULL,
  `totalThreats` int NOT NULL DEFAULT 0,
  `criticalCount` int NOT NULL DEFAULT 0,
  `highCount` int NOT NULL DEFAULT 0,
  `mediumCount` int NOT NULL DEFAULT 0,
  `lowCount` int NOT NULL DEFAULT 0,
  `infoCount` int NOT NULL DEFAULT 0,
  `blockedCount` int NOT NULL DEFAULT 0,
  `resolvedCount` int NOT NULL DEFAULT 0,
  `uniqueAttackers` int NOT NULL DEFAULT 0,
  `topAttackType` varchar(64),
  `topSourceCountry` varchar(64),
  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updatedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `idx_period_timestamp` (`period`, `timestamp`),
  INDEX `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- threatFeeds テーブルのインデックス追加（クエリ最適化用）
CREATE INDEX IF NOT EXISTS `idx_type_severity` ON `threatFeeds` (`type`, `severity`);
CREATE INDEX IF NOT EXISTS `idx_sourceCountry` ON `threatFeeds` (`sourceCountry`);
