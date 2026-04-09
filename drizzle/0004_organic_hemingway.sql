CREATE TABLE `permissionRequests` (
	`id` int AUTO_INCREMENT NOT NULL,
	`requestId` varchar(64) NOT NULL,
	`userId` int NOT NULL,
	`requestedRole` enum('admin','analyst','operator') NOT NULL,
	`reason` text,
	`status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
	`reviewedBy` int,
	`reviewedAt` timestamp,
	`rejectionReason` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `permissionRequests_id` PRIMARY KEY(`id`),
	CONSTRAINT `permissionRequests_requestId_unique` UNIQUE(`requestId`)
);
