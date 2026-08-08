import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

export function validateBody(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      const errors = result.error.flatten().fieldErrors;
      res.status(422).json({
        error: 'VALIDATION_ERROR',
        message: 'Invalid request body',
        details: errors,
      });
      return;
    }
    req.body = result.data;
    next();
  };
}

export function validateHeaders(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.headers);
    if (!result.success) {
      res.status(401).json({
        error: 'AUTH_ERROR',
        message: 'Invalid or missing authorization header',
      });
      return;
    }
    next();
  };
}

export { ZodError };