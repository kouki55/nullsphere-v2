import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, protectedProcedure, router } from "./_core/trpc";
import { dashboardRouter, threatRouter, attackerRouter, eventRouter, vmRouter, decoyRouter, notificationRouter, analysisRouter } from "./nullsphere";
import { kernelControlRouter } from "./kernel-control";
import { adminRouter } from "./admin";
import { auditRouter } from "./audit-router";
import { alertRouter } from "./alert-router";
import { permissionRequestRouter } from "./permission-request-router";
import { exportRouter } from "./export-router";
import { threatAnalyticsRouter } from "./routers/threat-analytics";

export const appRouter = router({
  // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: protectedProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),

  dashboard: dashboardRouter,
  threats: threatRouter,
  attackers: attackerRouter,
  events: eventRouter,
  vms: vmRouter,
  decoys: decoyRouter,
  notifications: notificationRouter,
  analysis: analysisRouter,
  kernel: kernelControlRouter,
  admin: adminRouter,
  audit: auditRouter,
  alert: alertRouter,
  permissionRequest: permissionRequestRouter,
  export: exportRouter,
  threatAnalytics: threatAnalyticsRouter,
});

export type AppRouter = typeof appRouter;
