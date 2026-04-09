import { describe, it, expect, beforeEach } from "vitest";
import { PtraceMemoryMonitor } from "./ptrace-memory-monitor";

describe("ptrace & Memory Access Monitoring", () => {
  let monitor: PtraceMemoryMonitor;

  beforeEach(() => {
    monitor = new PtraceMemoryMonitor();
  });

  describe("ptrace Access Validation", () => {
    it("should allow ptrace for same user", () => {
      const result = monitor.validatePtraceAccess(1000, 2000, 1000, "ptrace");
      expect(result).toBe(true);
    });

    it("should allow ptrace for root user", () => {
      const result = monitor.validatePtraceAccess(0, 2000, 1000, "ptrace");
      expect(result).toBe(true);
    });

    it("should block ptrace for different user", () => {
      const result = monitor.validatePtraceAccess(1000, 2000, 2000, "ptrace");
      expect(result).toBe(false);
    });

    it("should block memory read for non-root", () => {
      const result = monitor.validatePtraceAccess(
        1000,
        2000,
        1000,
        "mem_read"
      );
      expect(result).toBe(false);
    });

    it("should block memory write for non-root", () => {
      const result = monitor.validatePtraceAccess(
        1000,
        2000,
        1000,
        "mem_write"
      );
      expect(result).toBe(false);
    });

    it("should block process_vm_read for non-root", () => {
      const result = monitor.validatePtraceAccess(
        1000,
        2000,
        1000,
        "process_vm_read"
      );
      expect(result).toBe(false);
    });

    it("should allow process_vm_read for root", () => {
      const result = monitor.validatePtraceAccess(0, 2000, 1000, "process_vm_read");
      expect(result).toBe(true);
    });

    it("should block access to root process memory", () => {
      const result = monitor.validatePtraceAccess(0, 100, 0, "mem_read");
      expect(result).toBe(false);
    });

    it("should block access to system process memory", () => {
      const result = monitor.validatePtraceAccess(0, 500, 0, "mem_read");
      expect(result).toBe(false);
    });
  });

  describe("/proc/[pid]/mem Access Validation", () => {
    it("should block non-root access to /proc/[pid]/mem", () => {
      const result = monitor.validateMemFileAccess(1000, 2000, 1000);
      expect(result).toBe(false);
    });

    it("should allow root access to /proc/[pid]/mem", () => {
      const result = monitor.validateMemFileAccess(0, 2000, 1000);
      expect(result).toBe(true);
    });

    it("should block root access to system process memory", () => {
      const result = monitor.validateMemFileAccess(0, 500, 0);
      expect(result).toBe(false);
    });
  });

  describe("Memory Hijacking Attack Detection", () => {
    it("should detect multiple memory access attempts", () => {
      for (let i = 0; i < 15; i++) {
        monitor.validatePtraceAccess(1000, 2000 + i, 1000, "mem_read");
      }

      const isAttack = monitor.detectMemoryHijackingAttack();
      expect(isAttack).toBe(true);
    });

    it("should detect /proc/[pid]/mem access attempts", () => {
      for (let i = 0; i < 10; i++) {
        monitor.validateMemFileAccess(1000, 2000 + i, 1000);
      }

      const isAttack = monitor.detectMemoryHijackingAttack();
      expect(isAttack).toBe(true);
    });

    it("should detect root process access attempts", () => {
      for (let i = 0; i < 5; i++) {
        monitor.validatePtraceAccess(1000, 100 + i, 0, "mem_read");
      }

      const isAttack = monitor.detectMemoryHijackingAttack();
      expect(isAttack).toBe(true);
    });

    it("should not flag normal activity as attack", () => {
      monitor.validatePtraceAccess(1000, 2000, 1000, "ptrace");
      monitor.validatePtraceAccess(1000, 2001, 1000, "ptrace");

      const isAttack = monitor.detectMemoryHijackingAttack();
      expect(isAttack).toBe(false);
    });
  });

  describe("Statistics Tracking", () => {
    it("should track total attempts", () => {
      monitor.validatePtraceAccess(1000, 2000, 1000, "ptrace");
      monitor.validatePtraceAccess(1000, 2001, 2000, "ptrace");

      const stats = monitor.getStats();
      expect(stats.totalAttempts).toBe(2);
    });

    it("should track allowed and blocked attempts", () => {
      monitor.validatePtraceAccess(1000, 2000, 1000, "ptrace"); // allowed
      monitor.validatePtraceAccess(1000, 2001, 2000, "ptrace"); // blocked

      const stats = monitor.getStats();
      expect(stats.allowedAttempts).toBe(1);
      expect(stats.blockedAttempts).toBe(1);
    });

    it("should detect suspicious patterns", () => {
      for (let i = 0; i < 10; i++) {
        monitor.validatePtraceAccess(1000, 2000 + i, 2000 + i, "ptrace");
      }

      const stats = monitor.getStats();
      expect(stats.suspiciousPatterns.length).toBeGreaterThan(0);
    });
  });

  describe("Whitelist Management", () => {
    it("should add process to whitelist", () => {
      monitor.addWhitelistedProcess("custom_debugger");
      const stats = monitor.getStats();
      expect(stats.whitelistedProcesses.has("custom_debugger")).toBe(true);
    });

    it("should remove process from whitelist", () => {
      monitor.addWhitelistedProcess("custom_debugger");
      monitor.removeWhitelistedProcess("custom_debugger");
      const stats = monitor.getStats();
      expect(stats.whitelistedProcesses.has("custom_debugger")).toBe(false);
    });

    it("should clear and reset whitelist", () => {
      monitor.addWhitelistedProcess("custom_debugger");
      monitor.clearWhitelist();
      const stats = monitor.getStats();
      expect(stats.whitelistedProcesses.has("custom_debugger")).toBe(false);
      expect(stats.whitelistedProcesses.has("gdb")).toBe(true); // Default
    });
  });

  describe("Attempt Retrieval", () => {
    it("should retrieve recent attempts", () => {
      for (let i = 0; i < 10; i++) {
        monitor.validatePtraceAccess(1000, 2000 + i, 1000, "ptrace");
      }

      const recent = monitor.getRecentAttempts(5);
      expect(recent.length).toBe(5);
    });

    it("should retrieve blocked attempts", () => {
      monitor.validatePtraceAccess(1000, 2000, 1000, "ptrace"); // allowed
      monitor.validatePtraceAccess(1000, 2001, 2000, "ptrace"); // blocked
      monitor.validatePtraceAccess(1000, 2002, 2000, "ptrace"); // blocked

      const blocked = monitor.getBlockedAttempts();
      expect(blocked.length).toBe(2);
    });
  });

  describe("Statistics Reset", () => {
    it("should reset all statistics", () => {
      monitor.validatePtraceAccess(1000, 2000, 1000, "ptrace");
      monitor.validatePtraceAccess(1000, 2001, 2000, "ptrace");

      monitor.resetStats();

      const stats = monitor.getStats();
      expect(stats.totalAttempts).toBe(0);
      expect(stats.allowedAttempts).toBe(0);
      expect(stats.blockedAttempts).toBe(0);
    });
  });
});
