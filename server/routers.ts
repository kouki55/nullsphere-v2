import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router } from "./_core/trpc";
import { dashboardRouter, threatRouter, attackerRouter, eventRouter, vmRouter, decoyRouter, notificationRouter, analysisRouter } from "./nullsphere";
import { kernelControlRouter } from "./kernel-control";

export const appRouter = router({
    // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
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
});

export type AppRouter = typeof appRouter;
