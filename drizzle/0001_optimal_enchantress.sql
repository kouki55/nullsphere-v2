CREATE TABLE `attackers` (
	`id` int AUTO_INCREMENT NOT NULL,
	`attackerId` varchar(64) NOT NULL,
	`ip` varchar(45) NOT NULL,
	`os` varchar(128),
	`browser` varchar(128),
	`country` varchar(64),
	`city` varchar(128),
	`lat` varchar(20),
	`lng` varchar(20),
	`isp` varchar(256),
	`threatLevel` enum('critical','high','medium','low') NOT NULL,
	`commandHistory` json,
	`firstSeen` timestamp NOT NULL DEFAULT (now()),
	`lastSeen` timestamp NOT NULL DEFAULT (now()),
	`isActive` boolean NOT NULL DEFAULT true,
	`profileData` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `attackers_id` PRIMARY KEY(`id`),
	CONSTRAINT `attackers_attackerId_unique` UNIQUE(`attackerId`)
);
--> statement-breakpoint
CREATE TABLE `decoys` (
	`id` int AUTO_INCREMENT NOT NULL,
	`decoyId` varchar(64) NOT NULL,
	`type` enum('password_file','database','ssh_key','config_file','api_key','certificate') NOT NULL,
	`name` varchar(256) NOT NULL,
	`status` enum('active','inactive','triggered','expired') NOT NULL,
	`content` text,
	`accessCount` int DEFAULT 0,
	`lastAccessedBy` varchar(45),
	`lastAccessedAt` timestamp,
	`vmId` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `decoys_id` PRIMARY KEY(`id`),
	CONSTRAINT `decoys_decoyId_unique` UNIQUE(`decoyId`)
);
--> statement-breakpoint
CREATE TABLE `events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`eventId` varchar(64) NOT NULL,
	`type` enum('ebpf_hook','vm_transfer','decoy_access','block','alert','system','trace') NOT NULL,
	`severity` enum('critical','high','medium','low','info') NOT NULL,
	`source` varchar(128) NOT NULL,
	`message` text NOT NULL,
	`details` json,
	`threatId` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `events_id` PRIMARY KEY(`id`),
	CONSTRAINT `events_eventId_unique` UNIQUE(`eventId`)
);
--> statement-breakpoint
CREATE TABLE `notifications` (
	`id` int AUTO_INCREMENT NOT NULL,
	`notificationId` varchar(64) NOT NULL,
	`type` enum('email','in_app','webhook') NOT NULL,
	`severity` enum('critical','high','medium','low') NOT NULL,
	`title` varchar(256) NOT NULL,
	`message` text NOT NULL,
	`threatId` varchar(64),
	`isRead` boolean NOT NULL DEFAULT false,
	`sentAt` timestamp NOT NULL DEFAULT (now()),
	`readAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `notifications_id` PRIMARY KEY(`id`),
	CONSTRAINT `notifications_notificationId_unique` UNIQUE(`notificationId`)
);
--> statement-breakpoint
CREATE TABLE `threats` (
	`id` int AUTO_INCREMENT NOT NULL,
	`threatId` varchar(64) NOT NULL,
	`type` enum('intrusion','malware','privilege_escalation','data_exfiltration','lateral_movement','reconnaissance') NOT NULL,
	`severity` enum('critical','high','medium','low') NOT NULL,
	`status` enum('detected','blocked','isolated','deceived','traced','resolved') NOT NULL,
	`sourceIp` varchar(45) NOT NULL,
	`sourceLat` varchar(20),
	`sourceLng` varchar(20),
	`sourceCountry` varchar(64),
	`sourceCity` varchar(128),
	`targetHost` varchar(256),
	`targetPort` int,
	`command` text,
	`attackerId` int,
	`vmId` int,
	`description` text,
	`detectedAt` timestamp NOT NULL DEFAULT (now()),
	`resolvedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `threats_id` PRIMARY KEY(`id`),
	CONSTRAINT `threats_threatId_unique` UNIQUE(`threatId`)
);
--> statement-breakpoint
CREATE TABLE `vms` (
	`id` int AUTO_INCREMENT NOT NULL,
	`vmId` varchar(64) NOT NULL,
	`name` varchar(128) NOT NULL,
	`status` enum('running','stopped','spawning','destroying','error') NOT NULL,
	`cpuUsage` int DEFAULT 0,
	`memoryUsage` int DEFAULT 0,
	`diskUsage` int DEFAULT 0,
	`networkIn` int DEFAULT 0,
	`networkOut` int DEFAULT 0,
	`assignedThreatId` varchar(64),
	`attackerIp` varchar(45),
	`uptime` int DEFAULT 0,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `vms_id` PRIMARY KEY(`id`),
	CONSTRAINT `vms_vmId_unique` UNIQUE(`vmId`)
);
