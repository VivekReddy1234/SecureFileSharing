import { Request, Response, NextFunction } from 'express';
import { AnyZodObject, ZodError } from 'zod';
import { ValidationError } from '../types/errors';

export const validateBody = (schema: AnyZodObject) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        next(new ValidationError(error.errors.map(e => e.message).join(', ')));
      } else {
        next(error);
      }
    }
  };
};

export const validateQuery = (schema: AnyZodObject) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.query = schema.parse(req.query);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        next(new ValidationError(error.errors.map(e => e.message).join(', ')));
      } else {
        next(error);
      }
    }
  };
};

export const validateParams = (schema: AnyZodObject) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.params = schema.parse(req.params);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        next(new ValidationError(error.errors.map(e => e.message).join(', ')));
      } else {
        next(error);
      }
    }
  };
};
