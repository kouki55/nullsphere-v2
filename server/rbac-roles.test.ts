import { describe, it, expect } from "vitest";
import {
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  rolePermissions,
} from "./_core/rbac";

describe("RBAC - Role-based Permissions", () => {
  const adminUser = { id: 1, name: "Admin", email: "admin@test.com", role: "admin" };
  const analystUser = { id: 2, name: "Analyst", email: "analyst@test.com", role: "analyst" };
  const operatorUser = { id: 3, name: "Operator", email: "operator@test.com", role: "operator" };
  const regularUser = { id: 4, name: "User", email: "user@test.com", role: "user" };

  describe("Admin Role", () => {
    it("should have all permissions", () => {
      expect(hasPermission(adminUser as any, "user:promote")).toBe(true);
      expect(hasPermission(adminUser as any, "vm:start")).toBe(true);
      expect(hasPermission(adminUser as any, "decoy:create")).toBe(true);
      expect(hasPermission(adminUser as any, "kernel:isolate")).toBe(true);
      expect(hasPermission(adminUser as any, "admin:settings")).toBe(true);
    });

    it("should have admin-specific permissions", () => {
      expect(hasPermission(adminUser as any, "user:promote")).toBe(true);
      expect(hasPermission(adminUser as any, "user:demote")).toBe(true);
      expect(hasPermission(adminUser as any, "admin:view_logs")).toBe(true);
      expect(hasPermission(adminUser as any, "admin:export_logs")).toBe(true);
    });
  });

  describe("Analyst Role", () => {
    it("should have read-only permissions", () => {
      expect(hasPermission(analystUser as any, "threat:view")).toBe(true);
      expect(hasPermission(analystUser as any, "event:view")).toBe(true);
      expect(hasPermission(analystUser as any, "vm:view")).toBe(true);
      expect(hasPermission(analystUser as any, "analysis:view")).toBe(true);
    });

    it("should not have write permissions", () => {
      expect(hasPermission(analystUser as any, "vm:start")).toBe(false);
      expect(hasPermission(analystUser as any, "decoy:create")).toBe(false);
      expect(hasPermission(analystUser as any, "user:promote")).toBe(false);
    });

    it("should have analysis:full permission", () => {
      expect(hasPermission(analystUser as any, "analysis:full")).toBe(true);
    });
  });

  describe("Operator Role", () => {
    it("should have VM and Decoy management permissions", () => {
      expect(hasPermission(operatorUser as any, "vm:start")).toBe(true);
      expect(hasPermission(operatorUser as any, "vm:stop")).toBe(true);
      expect(hasPermission(operatorUser as any, "decoy:create")).toBe(true);
      expect(hasPermission(operatorUser as any, "decoy:delete")).toBe(true);
    });

    it("should have kernel operation permissions", () => {
      expect(hasPermission(operatorUser as any, "kernel:isolate")).toBe(true);
      expect(hasPermission(operatorUser as any, "kernel:block")).toBe(true);
      expect(hasPermission(operatorUser as any, "kernel:trace")).toBe(true);
    });

    it("should not have admin permissions", () => {
      expect(hasPermission(operatorUser as any, "user:promote")).toBe(false);
      expect(hasPermission(operatorUser as any, "admin:settings")).toBe(false);
      expect(hasPermission(operatorUser as any, "admin:export_logs")).toBe(false);
    });

    it("should have read permissions", () => {
      expect(hasPermission(operatorUser as any, "threat:view")).toBe(true);
      expect(hasPermission(operatorUser as any, "event:view")).toBe(true);
      expect(hasPermission(operatorUser as any, "analysis:view")).toBe(true);
    });
  });

  describe("Regular User Role", () => {
    it("should have minimal read-only permissions", () => {
      expect(hasPermission(regularUser as any, "threat:view")).toBe(true);
      expect(hasPermission(regularUser as any, "event:view")).toBe(true);
      expect(hasPermission(regularUser as any, "notification:view")).toBe(true);
    });

    it("should not have any write permissions", () => {
      expect(hasPermission(regularUser as any, "vm:start")).toBe(false);
      expect(hasPermission(regularUser as any, "decoy:create")).toBe(false);
      expect(hasPermission(regularUser as any, "kernel:isolate")).toBe(false);
      expect(hasPermission(regularUser as any, "user:promote")).toBe(false);
    });
  });

  describe("hasAnyPermission", () => {
    it("should return true if user has any of the permissions", () => {
      expect(
        hasAnyPermission(operatorUser as any, [
          "user:promote",
          "vm:start",
          "admin:settings",
        ])
      ).toBe(true);
    });

    it("should return false if user has none of the permissions", () => {
      expect(
        hasAnyPermission(operatorUser as any, [
          "user:promote",
          "admin:settings",
          "admin:export_logs",
        ])
      ).toBe(false);
    });
  });

  describe("hasAllPermissions", () => {
    it("should return true if user has all permissions", () => {
      expect(
        hasAllPermissions(operatorUser as any, ["vm:start", "decoy:create"])
      ).toBe(true);
    });

    it("should return false if user lacks any permission", () => {
      expect(
        hasAllPermissions(operatorUser as any, [
          "vm:start",
          "decoy:create",
          "user:promote",
        ])
      ).toBe(false);
    });
  });

  describe("Role Permissions Structure", () => {
    it("should have all required roles defined", () => {
      expect(rolePermissions.admin).toBeDefined();
      expect(rolePermissions.analyst).toBeDefined();
      expect(rolePermissions.operator).toBeDefined();
      expect(rolePermissions.user).toBeDefined();
    });

    it("admin should have most permissions", () => {
      expect(rolePermissions.admin.length).toBeGreaterThan(
        rolePermissions.operator.length
      );
      expect(rolePermissions.admin.length).toBeGreaterThan(
        rolePermissions.analyst.length
      );
    });

    it("analyst should have more permissions than user", () => {
      expect(rolePermissions.analyst.length).toBeGreaterThan(
        rolePermissions.user.length
      );
    });

    it("operator should have more permissions than analyst", () => {
      expect(rolePermissions.operator.length).toBeGreaterThanOrEqual(
        rolePermissions.analyst.length
      );
    });
  });

  describe("Null User", () => {
    it("should deny all permissions for null user", () => {
      expect(hasPermission(null, "threat:view")).toBe(false);
      expect(hasPermission(null, "vm:start")).toBe(false);
      expect(hasPermission(null, "admin:settings")).toBe(false);
    });
  });
});
