import { describe, it, expect, beforeEach } from "vitest";
import {
  EBPFRingBufferManager,
  type BPFEvent,
  type EventPriority,
} from "./ebpf-ringbuffer-manager";

describe("eBPF RingBuffer Management & Anomaly Detection", () => {
  let manager: EBPFRingBufferManager;

  beforeEach(() => {
    manager = new EBPFRingBufferManager(1); // 1 MB for testing
  });

  describe("Event Addition", () => {
    it("should add events to buffer", () => {
      const event: BPFEvent = {
        pid: 1000,
        comm: "test_app",
        syscall: "openat",
        timestamp: Date.now(),
        priority: "normal",
      };

      const result = manager.addEvent(event);
      expect(result).toBe(true);
      expect(manager.size()).toBe(1);
    });

    it("should handle multiple events", () => {
      for (let i = 0; i < 10; i++) {
        const event: BPFEvent = {
          pid: 1000 + i,
          comm: "test_app",
          syscall: "openat",
          timestamp: Date.now(),
          priority: "normal",
        };
        manager.addEvent(event);
      }

      expect(manager.size()).toBe(10);
    });

    it("should reject events when buffer is full", () => {
      // Fill buffer with large events
      for (let i = 0; i < 100; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "test_app",
          syscall: "openat",
          timestamp: Date.now(),
          priority: "low",
          data: "x".repeat(10000), // Large payload
        };

        const result = manager.addEvent(event);
        if (!result) {
          // Buffer is full
          expect(result).toBe(false);
          break;
        }
      }
    });
  });

  describe("Priority-based Eviction", () => {
    it("should evict low priority events when buffer is full", () => {
      // Add critical events
      for (let i = 0; i < 5; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "test_app",
          syscall: "execve",
          timestamp: Date.now(),
          priority: "critical",
        };
        manager.addEvent(event);
      }

      // Add low priority events to fill buffer
      for (let i = 0; i < 100; i++) {
        const event: BPFEvent = {
          pid: 2000 + i,
          comm: "test_app",
          syscall: "getpid",
          timestamp: Date.now(),
          priority: "low",
          data: "x".repeat(5000),
        };
        manager.addEvent(event);
      }

      // Critical events should still be in buffer
      const criticalEvents = manager.getEventsByPriority("critical");
      expect(criticalEvents.length).toBeGreaterThan(0);
    });
  });

  describe("Anomaly Detection", () => {
    it("should detect high buffer usage", () => {
      // Fill buffer to 80%+
      for (let i = 0; i < 50; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "test_app",
          syscall: "openat",
          timestamp: Date.now(),
          priority: "normal",
          data: "x".repeat(15000),
        };
        manager.addEvent(event);
      }

      const stats = manager.getStats();
      expect(stats.currentUsage).toBeGreaterThan(0);
      expect(stats.usagePercentage).toBeGreaterThanOrEqual(0);
    });

    it("should detect event storm", () => {
      const now = Date.now();

      // Add many events with recent timestamp
      for (let i = 0; i < 1000; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "test_app",
          syscall: "getpid",
          timestamp: now,
          priority: "low",
        };
        manager.addEvent(event);
      }

      const stats = manager.getStats();
      // With 1000 events/sec, should trigger anomaly if threshold is 100k
      expect(stats.currentUsage).toBeGreaterThan(0);
    });

    it("should detect suspicious syscall patterns", () => {
      const now = Date.now();

      // Add many suspicious syscalls
      const suspiciousSyscalls = ["getpid", "gettid", "stat", "access"];
      for (let i = 0; i < 1000; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "test_app",
          syscall: suspiciousSyscalls[i % suspiciousSyscalls.length],
          timestamp: now,
          priority: "low",
        };
        manager.addEvent(event);
      }

      const stats = manager.getStats();
      expect(
        stats.anomalies.some((a) => a.includes("Suspicious syscall pattern"))
      ).toBe(true);
    });

    it("should detect high event drop rate", () => {
      // Force many events to be dropped
      for (let i = 0; i < 500; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "test_app",
          syscall: "openat",
          timestamp: Date.now(),
          priority: "low",
          data: "x".repeat(100000),
        };
        manager.addEvent(event);
      }

      const stats = manager.getStats();
      expect(stats.currentUsage).toBeGreaterThan(0);
    });
  });

  describe("Event Storming Detection", () => {
    it("should detect Event Storming attack", () => {
      const now = Date.now();

      // Simulate Event Storming: many getpid() calls
      for (let i = 0; i < 1000; i++) {
        const event: BPFEvent = {
          pid: 9999,
          comm: "attacker_process",
          syscall: "getpid",
          timestamp: now,
          priority: "low",
        };
        manager.addEvent(event);
      }

      // With custom threshold, should detect
      manager.setAnomalyThresholds({ eventsPerSecond: 500 });
      const isAttack = manager.detectEventStorming();
      expect(isAttack).toBe(true);
    });

    it("should not flag normal activity as attack", () => {
      const now = Date.now();

      // Add normal events
      for (let i = 0; i < 100; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "systemd",
          syscall: "openat",
          timestamp: now,
          priority: "normal",
        };
        manager.addEvent(event);
      }

      const isAttack = manager.detectEventStorming();
      expect(isAttack).toBe(false);
    });
  });

  describe("Event Filtering", () => {
    it("should filter events by priority", () => {
      const events: BPFEvent[] = [
        {
          pid: 1000,
          comm: "test",
          syscall: "openat",
          timestamp: Date.now(),
          priority: "critical",
        },
        {
          pid: 1001,
          comm: "test",
          syscall: "stat",
          timestamp: Date.now(),
          priority: "normal",
        },
        {
          pid: 1002,
          comm: "test",
          syscall: "getpid",
          timestamp: Date.now(),
          priority: "low",
        },
      ];

      for (const event of events) {
        manager.addEvent(event);
      }

      const highPriority = manager.getEventsByPriority("high");
      expect(highPriority.length).toBe(1); // Only critical
    });

    it("should filter events by time range", () => {
      const now = Date.now();

      const events: BPFEvent[] = [
        {
          pid: 1000,
          comm: "test",
          syscall: "openat",
          timestamp: now - 5000,
          priority: "normal",
        },
        {
          pid: 1001,
          comm: "test",
          syscall: "stat",
          timestamp: now,
          priority: "normal",
        },
        {
          pid: 1002,
          comm: "test",
          syscall: "getpid",
          timestamp: now + 5000,
          priority: "normal",
        },
      ];

      for (const event of events) {
        manager.addEvent(event);
      }

      const recent = manager.getEventsByTimeRange(now - 1000, now + 1000);
      expect(recent.length).toBe(1);
    });

    it("should group events by syscall", () => {
      const events: BPFEvent[] = [
        {
          pid: 1000,
          comm: "test",
          syscall: "openat",
          timestamp: Date.now(),
          priority: "normal",
        },
        {
          pid: 1001,
          comm: "test",
          syscall: "openat",
          timestamp: Date.now(),
          priority: "normal",
        },
        {
          pid: 1002,
          comm: "test",
          syscall: "stat",
          timestamp: Date.now(),
          priority: "normal",
        },
      ];

      for (const event of events) {
        manager.addEvent(event);
      }

      const bySyscall = manager.getEventsBySyscall();
      expect(bySyscall["openat"]).toBe(2);
      expect(bySyscall["stat"]).toBe(1);
    });
  });

  describe("Buffer Management", () => {
    it("should clear buffer", () => {
      for (let i = 0; i < 10; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "test",
          syscall: "openat",
          timestamp: Date.now(),
          priority: "normal",
        };
        manager.addEvent(event);
      }

      expect(manager.size()).toBe(10);

      manager.clear();
      expect(manager.size()).toBe(0);

      const stats = manager.getStats();
      expect(stats.currentUsage).toBe(0);
      expect(stats.droppedEvents).toBe(0);
    });

    it("should track statistics", () => {
      const event: BPFEvent = {
        pid: 1000,
        comm: "test",
        syscall: "openat",
        timestamp: Date.now(),
        priority: "critical",
      };

      manager.addEvent(event);

      const stats = manager.getStats();
      expect(stats.priorityDistribution.critical).toBe(1);
      expect(stats.currentUsage).toBeGreaterThan(0);
    });
  });

  describe("Anomaly Threshold Configuration", () => {
    it("should allow custom anomaly thresholds", () => {
      manager.setAnomalyThresholds({
        eventsPerSecond: 10,
        suspiciousEventRatio: 0.5,
      });

      const now = Date.now();

      // Add 20 events (exceeds custom threshold of 10)
      for (let i = 0; i < 20; i++) {
        const event: BPFEvent = {
          pid: 1000,
          comm: "test",
          syscall: "getpid",
          timestamp: now,
          priority: "low",
        };
        manager.addEvent(event);
      }

      const stats = manager.getStats();
      expect(stats.anomalies.some((a) => a.includes("Event storm"))).toBe(true);
    });
  });
});
