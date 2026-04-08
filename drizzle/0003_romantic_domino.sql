CREATE TABLE `alertSettings` (
	`id` int AUTO_INCREMENT NOT NULL,
	`alertId` varchar(64) NOT NULL,
	`userId` int NOT NULL,
	`actionType` enum('user_promote','user_demote','vm_start','vm_stop','vm_reboot','decoy_create','decoy_delete','decoy_activate','decoy_deactivate','process_isolate','network_block','tracing_enable','tracing_disable','threat_resolve','threat_block','settings_change','all') NOT NULL,
	`notificationMethod` enum('email','in-app','webhook') NOT NULL DEFAULT 'in-app',
	`webhookUrl` text,
	`isActive` boolean NOT NULL DEFAULT true,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `alertSettings_id` PRIMARY KEY(`id`),
	CONSTRAINT `alertSettings_alertId_unique` UNIQUE(`alertId`)
);
