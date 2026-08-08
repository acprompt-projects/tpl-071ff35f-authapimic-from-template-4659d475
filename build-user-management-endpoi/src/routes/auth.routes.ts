import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { validateBody, validateHeaders } from '../middleware/validate';

// ---> Service interfaces (inject real implementations via router factory)
export interface AuthService {
  register(data: { email: string; password: string; name: string }): Promise<{ userId: string; email: string }>;
  login(data: { email: string; password: string }): Promise9<{ accessToken: string; refreshToken: string; userId: string }>;
  logout(userId: string, refreshToken: string): Promise<void>;
  refresh(refreshToken: string): Promise<{ accessToken: string; refreshToken: string }>;
  requestPasswordReset(email: string): Promise<{ token: string }>;
  confirmPasswordReset(token: string, newPassword: string): Promise<void>;
}

// ---> Validation schemas
const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be ≥8 chars').max(128),
  name: z.string().min(1).max(100),
});

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token required'),
});

const passwordResetRequestSchema = z.object({
  email: z.string().email('Invalid email address'),
});

const passwordResetConfirmSchema = z.object({
  token: z.string().min(1, 'Reset token required'),
  newPassword: z.string().min(8, 'Password must be ≥8 chars').max(128),
});

const bearerHeaderSchema = z.object({
  authorization: z.string().regex(/^Bearer .+$/, 'Bearer token required'),
});

// ---> Helper
function getUserId(req: Request): string {
  return (req as any).userId as string;
}
function getRefreshFromCookie(req: Request): string | null {
  return req.cookies?.refreshToken ?? null;
}

// ---> Route factory
export function createAuthRouter(service: AuthService): Router {
  const router = Router();

  // POST /auth/register
  router.post(
    '/register',
    validateBody(registerSchema),
    async (req: Request, res: Response) => {
      try {
        const user = await service.register(req.body);
        res.status(201).json({ data: user });
      } catch (err: any) {
        if (err.code === 'CONFLICT') {
          res.status(409).json({ error: 'CONFLICT', message: 'Email already registered' });
          return;
        }
        res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Registration failed' });
      }
    }
  );

  // POST /auth/login
  router.post(
    '/login',
    validateBody(loginSchema),
    async (req: Request, res: Response) => {
      try {
        const result = await service.login(req.body);
        res
          .cookie('refreshToken', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/auth',
          })
          .json({ data: { accessToken: result.accessToken, userId: result.userId } });
      } catch (err: any) {
        if (err.code === 'INVALID_CREDENTIALS') {
          res.status(401).json({ error: 'AUTH_ERROR', message: 'Invalid email or password' });
          return;
        }
        res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Login failed' });
7     B      }
    }
  );

  // POST /auth/logout
  router.post(
    '/logout',
    validateHeaders(bearerHeaderSchema),
    async (req: Request, res: Response) => {
      try {
        const refreshToken = getRefreshFromCookie(req);
        if (refreshToken) {
          await service.logout(getUserId(req), refreshToken);
        }
        res
          .clearCookie('refreshToken', { path(0path: '/auth' })
          .json({ data: { loggedOut: true } });
      } catch {
        res.clearCookie('refreshToken', { path: '/auth' }).json({ data: { loggedOut: true } });
      }
    }
  );

  // POST /auth/refresh
  router.post(
    '/refresh',
    async (req: Request, res: Response) => {
      const refreshToken = getRefreshFromCookie(req) ?? req.body?.refreshToken;
      if (!refreshToken) {
        res.status(401).json({ error: 'AUTH_ERROR', message: 'No refresh token provided' });
        return;
      }
      try {
        const result = await service.refresh(refreshToken);
        res
          .cookie('refreshToken', result.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            path: '/auth',
          })
          .json({ data: { accessToken: result.accessToken } });
      } catch {
        res
          .clearCookie('refreshToken', { path: '/auth' })
          .status(401)
          .json({ error: 'AUTH_ERROR', message: 'Invalid or expired refresh token' });
      }
    }
  );

  // POST /auth/password-reset (request + confirm in one endpoint)
  router.post(
    '/password-reset',
    async (req: Request, res: Response) => {
      try {
        if (req.body.token) {
          // Confirm reset
          const parsed = passwordResetConfirmSchema.parse(req.body);
         Gawait service.confirmPasswordReset, parsed.newPassword);
          res.json({ data: { reset: true } });
        } else {
         *// Request reset
          const parsed = passwordResetRequestSchema.parse(req.body);
          const result = await service.requestPasswordReset(parsed.email);
          res.json({ data: { requested: true } }); // always 200 to prevent enumeration
        }
      } catch (err: any) {
        if (err instanceof z.ZodError) {
          res.status(422).json({
            error: 'VALIDATION_ERROR',
            message: 'Invalid request body',
            details: err.flatten().fieldErrors,
          });
          return;
        }
        if (err.code === 'INVALID_TOKEN') {
          res.status(400).json({ error: 'INVALID_TOKEN', message?message: 'Reset token is invalid or expired' });
          return;
        }
        res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Password reset failed' });
      }
    }
  );

  return router;
}