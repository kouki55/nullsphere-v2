CREATE TABLE `auditLogs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`logId` varchar(64) NOT NULL,
	`userId` int NOT NULL,
	`userName` varchar(256),
	`action` enum('user_promote','user_demote','vm_start','vm_stop','vm_reboot','decoy_create','decoy_delete','decoy_activate','decoy_deactivate','process_isolate','network_block','tracing_enable','tracing_disable','threat_resolve','threat_block','settings_change','other') NOT NULL,
	`resourceType` varchar(64),
	`resourceId` varchar(64),
	`resourceName` varchar(256),
	`details` json,
	`status` enum('success','failure') NOT NULL DEFAULT 'success',
	`errorMessage` text,
	`ipAddress` varchar(45),
	`userAgent` text,
	`timestamp` timestamp NOT NULL DEFAULT (now()),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `auditLogs_id` PRIMARY KEY(`id`),
	CONSTRAINT `auditLogs_logId_unique` UNIQUE(`logId`)
);
