import { describe, it, expect, beforeEach } from "vitest";
import { IoUringMonitor, type IoUringOperation } from "./iouring-monitor";

describe("io_uring Monitoring & Blocking", () => {
  let monitor: IoUringMonitor;

  beforeEach(() => {
    monitor = new IoUringMonitor();
  });

  describe("Setup Validation", () => {
    it("should allow setup from whitelisted process", () => {
      const operation: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 0,
      };

      const result = monitor.validateSetup(operation);
      expect(result.allowed).toBe(true);
    });

    it("should reject setup from non-whitelisted process", () => {
      const operation: IoUringOperation = {
        pid: 2000,
        comm: "malicious_app",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 0,
      };

      const result = monitor.validateSetup(operation);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("not in whitelist");
    });

    it("should reject setup with too many entries", () => {
      const operation: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 100000, // Way too many
        flags: 0,
      };

      const result = monitor.validateSetup(operation);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Too many entries");
    });

    it("should reject setup with IOPOLL flag", () => {
      const operation: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 1 << 0, // IORING_SETUP_IOPOLL
      };

      const result = monitor.validateSetup(operation);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("IOPOLL");
    });

    it("should reject setup with SQPOLL flag", () => {
      const operation: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 1 << 1, // IORING_SETUP_SQPOLL
      };

      const result = monitor.validateSetup(operation);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("SQPOLL");
    });

    it("should allow normal flags", () => {
      const operation: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 1 << 3, // IORING_SETUP_CQSIZE (normal)
      };

      const result = monitor.validateSetup(operation);
      expect(result.allowed).toBe(true);
    });
  });

  describe("Enter Validation", () => {
    it("should allow enter from whitelisted process", () => {
      const operation: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_enter",
        timestamp: Date.now(),
        minComplete: 1,
        minWait: 0,
      };

      const result = monitor.validateEnter(operation);
      expect(result.allowed).toBe(true);
    });

    it("should reject enter from blocked PID", () => {
      monitor.blockPid(2000, "Suspicious activity");

      const operation: IoUringOperation = {
        pid: 2000,
        comm: "malicious_app",
        syscall: "io_uring_enter",
        timestamp: Date.now(),
      };

      const result = monitor.validateEnter(operation);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("blocked");
    });

    it("should enforce rate limiting", () => {
      const monitor = new IoUringMonitor({ maxOperationsPerSecond: 5 });

      const operation: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_enter",
        timestamp: Date.now(),
      };

      // Allow first 5 operations
      for (let i = 0; i < 5; i++) {
        const result = monitor.validateEnter(operation);
        expect(result.allowed).toBe(true);
      }

      // 6th operation should be rejected
      const result = monitor.validateEnter(operation);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Rate limit exceeded");
    });
  });

  describe("PID Blocking", () => {
    it("should block a PID", () => {
      monitor.blockPid(5000, "Suspicious io_uring usage");

      const blocked = monitor.getBlockedPids();
      expect(blocked).toContain(5000);
    });

    it("should unblock a PID", () => {
      monitor.blockPid(5000, "Test");
      monitor.unblockPid(5000);

      const blocked = monitor.getBlockedPids();
      expect(blocked).not.toContain(5000);
    });

    it("should prevent operations from blocked PIDs", () => {
      monitor.blockPid(5000, "Test");

      const operation: IoUringOperation = {
        pid: 5000,
        comm: "test_app",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 0,
      };

      const result = monitor.validateSetup(operation);
      expect(result.allowed).toBe(false);
    });
  });

  describe("Statistics", () => {
    it("should track statistics", () => {
      const op1: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_enter",
        timestamp: Date.now(),
      };

      const op2: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_enter",
        timestamp: Date.now(),
      };

      monitor.validateEnter(op1);
      monitor.validateEnter(op2);

      const stats = monitor.getStats();
      expect(stats.totalOperations).toBe(2);
      expect(stats.monitoredPids).toBe(1);
      expect(stats.blockedPids).toBe(0);
    });

    it("should update stats when blocking PIDs", () => {
      monitor.blockPid(1000, "Test");
      monitor.blockPid(2000, "Test");

      const stats = monitor.getStats();
      expect(stats.blockedPids).toBe(2);
    });
  });

  describe("Event Storming Attack Simulation", () => {
    it("should detect and block Event Storming attack", () => {
      // Attacker tries to setup io_uring with massive entries
      const attackOperation: IoUringOperation = {
        pid: 9999,
        comm: "attacker_process",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 1000000, // Massive number of entries
        flags: 1 << 0, // IOPOLL flag (high CPU)
      };

      const result = monitor.validateSetup(attackOperation);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("not in whitelist");
    });

    it("should detect io_uring abuse for file access bypass", () => {
      // Attacker tries to use io_uring to bypass openat monitoring
      const attackOperation: IoUringOperation = {
        pid: 9999,
        comm: "attacker_process",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 1 << 5, // IORING_SETUP_ATTACH_WQ (workqueue attachment)
      };

      const result = monitor.validateSetup(attackOperation);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("not in whitelist");
    });

    it("should block rapid io_uring operations (DoS)", () => {
      const monitor = new IoUringMonitor({ maxOperationsPerSecond: 100 });

      // Simulate 150 operations in 1 second
      for (let i = 0; i < 150; i++) {
        const operation: IoUringOperation = {
          pid: 9999,
          comm: "attacker_process",
          syscall: "io_uring_enter",
          timestamp: Date.now(),
        };

        const result = monitor.validateEnter(operation);

        if (i < 100) {
          expect(result.allowed).toBe(true);
        } else {
          expect(result.allowed).toBe(false);
          expect(result.reason).toContain("Rate limit exceeded");
        }
      }
    });
  });

  describe("Whitelist Management", () => {
    it("should allow custom whitelist", () => {
      const customMonitor = new IoUringMonitor({
        allowedComms: ["custom_app", "another_app"],
      });

      const operation: IoUringOperation = {
        pid: 1000,
        comm: "custom_app",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 0,
      };

      const result = customMonitor.validateSetup(operation);
      expect(result.allowed).toBe(true);
    });

    it("should reject non-whitelisted process with custom whitelist", () => {
      const customMonitor = new IoUringMonitor({
        allowedComms: ["custom_app"],
      });

      const operation: IoUringOperation = {
        pid: 1000,
        comm: "systemd",
        syscall: "io_uring_setup",
        timestamp: Date.now(),
        entries: 256,
        flags: 0,
      };

      const result = customMonitor.validateSetup(operation);
      expect(result.allowed).toBe(false);
    });
  });
});
