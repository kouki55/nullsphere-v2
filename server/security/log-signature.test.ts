import { describe, it, expect, beforeEach } from "vitest";
import {
  signLog,
  verifyLogSignature,
  generateAuthToken,
  verifyAuthToken,
  detectLogAnomaly,
  validateLog,
  type LogEntry,
} from "./log-signature";

describe("Log Signature & Authentication Security", () => {
  describe("Log Signing", () => {
    it("should sign a log entry", () => {
      const log: LogEntry = {
        type: "info",
        comm: "nullsphere",
        pid: 1234,
        message: "Normal system event",
      };

      const signed = signLog(log);

      expect(signed.signature).toBeDefined();
      expect(signed.nonce).toBeDefined();
      expect(signed.timestamp).toBeDefined();
      expect(signed.message).toBe(log.message);
    });

    it("should generate different signatures for different logs", () => {
      const log1: LogEntry = {
        type: "info",
        comm: "process1",
        message: "Event 1",
      };

      const log2: LogEntry = {
        type: "info",
        comm: "process2",
        message: "Event 2",
      };

      const signed1 = signLog(log1);
      const signed2 = signLog(log2);

      expect(signed1.signature).not.toBe(signed2.signature);
    });

    it("should generate different signatures for same log (different nonce)", () => {
      const log: LogEntry = {
        type: "info",
        comm: "process",
        message: "Same event",
      };

      const signed1 = signLog(log);
      const signed2 = signLog(log);

      expect(signed1.signature).not.toBe(signed2.signature);
      expect(signed1.nonce).not.toBe(signed2.nonce);
    });
  });

  describe("Log Signature Verification", () => {
    it("should verify a valid signed log", () => {
      const log: LogEntry = {
        type: "info",
        comm: "nullsphere",
        message: "Valid log",
      };

      const signed = signLog(log);
      const valid = verifyLogSignature(signed);

      expect(valid).toBe(true);
    });

    it("should reject a tampered log", () => {
      const log: LogEntry = {
        type: "info",
        comm: "nullsphere",
        message: "Original message",
      };

      const signed = signLog(log);

      // Tamper with the message
      signed.message = "Tampered message";

      const valid = verifyLogSignature(signed);
      expect(valid).toBe(false);
    });

    it("should reject a log with invalid signature", () => {
      const log: LogEntry = {
        type: "info",
        comm: "nullsphere",
        message: "Test log",
      };

      const signed = signLog(log);
      signed.signature = "invalid_signature_0000000000000000";

      const valid = verifyLogSignature(signed);
      expect(valid).toBe(false);
    });

    it("should reject a log without nonce", () => {
      const log: LogEntry = {
        type: "info",
        comm: "nullsphere",
        message: "Test log",
      };

      const signed = signLog(log);
      delete (signed as any).nonce;

      const valid = verifyLogSignature(signed);
      expect(valid).toBe(false);
    });

    it("should reject a log with timestamp too old", () => {
      const log: LogEntry = {
        type: "info",
        comm: "nullsphere",
        message: "Old log",
        timestamp: Date.now() - 10 * 60 * 1000, // 10 minutes ago
      };

      const signed = signLog(log);

      const valid = verifyLogSignature(signed);
      expect(valid).toBe(false);
    });
  });

  describe("Authentication Token", () => {
    it("should generate a valid auth token", () => {
      const token = generateAuthToken("client-123");

      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
    });

    it("should verify a valid auth token", () => {
      const token = generateAuthToken("client-456");
      const result = verifyAuthToken(token);

      expect(result.valid).toBe(true);
      expect(result.clientId).toBe("client-456");
    });

    it("should reject an invalid token", () => {
      const result = verifyAuthToken("invalid-token-xyz");

      expect(result.valid).toBe(false);
      expect(result.clientId).toBeUndefined();
    });

    it("should reject a tampered token", () => {
      const token = generateAuthToken("client-789");
      const tampered = token.slice(0, -10) + "0000000000";

      const result = verifyAuthToken(tampered);
      expect(result.valid).toBe(false);
    });

    it("should reject an expired token", () => {
      // Create a token that's already expired
      const payload = {
        clientId: "client-expired",
        issuedAt: Date.now() - 48 * 60 * 60 * 1000,
        expiresAt: Date.now() - 24 * 60 * 60 * 1000, // Expired 24 hours ago
      };

      const payloadStr = JSON.stringify(payload);
      const crypto = require("crypto");
      const signature = crypto
        .createHmac("sha256", process.env.AUTH_TOKEN_SECRET || "default-dev-token-change-in-production")
        .update(payloadStr)
        .digest("hex");

      const token = Buffer.from(`${payloadStr}.${signature}`).toString("base64");
      const result = verifyAuthToken(token);

      expect(result.valid).toBe(false);
    });
  });

  describe("Log Anomaly Detection", () => {
    it("should detect suspicious command names", () => {
      const log: LogEntry = {
        type: "info",
        comm: "systemd",
        message: "盗んだデータ",
      };

      const anomaly = detectLogAnomaly(log);
      expect(anomaly).toBe("suspicious_command_name");
    });

    it("should detect oversized messages", () => {
      const log: LogEntry = {
        type: "info",
        comm: "process",
        message: "x".repeat(11000),
      };

      const anomaly = detectLogAnomaly(log);
      expect(anomaly).toBe("oversized_message");
    });

    it("should detect binary data", () => {
      const log: LogEntry = {
        type: "info",
        comm: "process",
        message: "Normal text \x00\x01\x02 binary",
      };

      const anomaly = detectLogAnomaly(log);
      expect(anomaly).toBe("binary_data_detected");
    });

    it("should detect injection patterns", () => {
      const log: LogEntry = {
        type: "info",
        comm: "process",
        message: "SELECT * FROM users WHERE id='1' OR '1'='1'",
      };

      const anomaly = detectLogAnomaly(log);
      expect(anomaly).toBe("injection_pattern_detected");
    });

    it("should allow normal logs", () => {
      const log: LogEntry = {
        type: "info",
        comm: "kernel",
        message: "Normal kernel event",
      };

      const anomaly = detectLogAnomaly(log);
      expect(anomaly).toBeNull();
    });
  });

  describe("Complete Log Validation Pipeline", () => {
    it("should validate a legitimate log", () => {
      const log: LogEntry = {
        type: "info",
        comm: "nullsphere",
        message: "Legitimate event",
      };

      const signed = signLog(log);
      const result = validateLog(signed);

      expect(result.valid).toBe(true);
    });

    it("should reject a log with invalid signature", () => {
      const log: LogEntry = {
        type: "info",
        comm: "nullsphere",
        message: "Test event",
      };

      const signed = signLog(log);
      signed.signature = "invalid";

      const result = validateLog(signed);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("invalid_signature");
    });

    it("should reject a log with anomalies", () => {
      const log: LogEntry = {
        type: "info",
        comm: "systemd",
        message: "盗んだデータ",
      };

      const signed = signLog(log);
      const result = validateLog(signed);

      expect(result.valid).toBe(false);
      expect(result.reason).toContain("anomaly_detected");
    });
  });

  describe("Event Storming Attack Simulation", () => {
    it("should reject a fake log impersonating systemd", () => {
      const fakeLog: LogEntry = {
        type: "info",
        comm: "systemd",
        message: '{"type": "info", "comm": "systemd", "message": "盗んだデータ"}',
      };

      const signed = signLog(fakeLog);

      // Attacker tries to send unsigned log
      const unsigned: any = {
        type: "info",
        comm: "systemd",
        message: "盗んだデータ",
      };

      const result = validateLog(unsigned);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("invalid_signature");
    });

    it("should detect log injection via message field", () => {
      const log: LogEntry = {
        type: "info",
        comm: "process",
        message: '{"type": "critical", "comm": "kernel", "message": "SYSTEM COMPROMISED"}',
      };

      const signed = signLog(log);
      const result = validateLog(signed);

      // Should still be valid (message is just data)
      expect(result.valid).toBe(true);
    });
  });
});
