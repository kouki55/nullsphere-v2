import { NOT_ADMIN_ERR_MSG, UNAUTHED_ERR_MSG } from '@shared/const';
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { TrpcContext } from "./context";
import { globalRateLimiter, getClientIp, throwRateLimitError } from './jwt-middleware';

const t = initTRPC.context<TrpcContext>().create({
  transformer: superjson,
});

export const router = t.router;

// レート制限ミドルウェア
const rateLimit = t.middleware(async opts => {
  const { ctx, next } = opts;
  const clientId = getClientIp(ctx);

  if (!globalRateLimiter.checkLimit(clientId)) {
    throwRateLimitError();
  }

  return next();
});

export const publicProcedure = t.procedure.use(rateLimit);

const requireUser = t.middleware(async opts => {
  const { ctx, next } = opts;

  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }

  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
    },
  });
});

export const protectedProcedure = t.procedure.use(requireUser).use(rateLimit);

export const adminProcedure = t.procedure
  .use(
    t.middleware(async opts => {
      const { ctx, next } = opts;

      if (!ctx.user || ctx.user.role !== 'admin') {
        throw new TRPCError({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
      }

      return next({
        ctx: {
          ...ctx,
          user: ctx.user,
        },
      });
    }),
  )
  .use(rateLimit);

// レート制限インスタンスをエクスポート
export { globalRateLimiter };
