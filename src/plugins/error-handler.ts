import { FastifyInstance, FastifyError, FastifyRequest, FastifyReply } from 'fastify';
import { AppError } from '../lib/errors.js';

export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((error: FastifyError | AppError | Error, request: FastifyRequest, reply: FastifyReply) => {
    // If it's one of our domain AppErrors
    if (error instanceof AppError) {
      return reply.status(error.statusCode).send(error.toJSON());
    }

    const fastifyError = error as FastifyError;

    // Fastify rate-limit error
    if (fastifyError.statusCode === 429) {
      return reply.status(429).send({
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests, please try again later',
        },
      });
    }

    // Fastify schema validation error
    if (fastifyError.validation) {
      return reply.status(400).send({
        error: {
          code: 'VALIDATION_ERROR',
          message: fastifyError.message.replace(/"/g, "'"),
        },
      });
    }

    // Request entity too large (bodyLimit exceeded)
    if (fastifyError.statusCode === 413) {
      return reply.status(413).send({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'Request payload exceeds 16KB limit',
        },
      });
    }

    // JSON syntax / malformed body
    if (fastifyError.statusCode === 400) {
      return reply.status(400).send({
        error: {
          code: 'BAD_REQUEST',
          message: 'Malformed request payload',
        },
      });
    }

    // Unexpected internal error
    const statusCode = typeof fastifyError.statusCode === 'number' && fastifyError.statusCode >= 400 && fastifyError.statusCode < 600
      ? fastifyError.statusCode
      : 500;

    request.log.error({ err: error }, 'Unhandled server error');

    return reply.status(statusCode).send({
      error: {
        code: statusCode === 500 ? 'INTERNAL_SERVER_ERROR' : 'ERROR',
        message: statusCode === 500 ? 'An unexpected internal error occurred' : (error.message || 'Error occurred'),
      },
    });
  });

  app.setNotFoundHandler((_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(404).send({
      error: {
        code: 'NOT_FOUND',
        message: 'Route not found',
      },
    });
  });
}
