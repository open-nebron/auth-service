export interface ErrorResponse {
  error: {
    code: string;
    message: string;
  };
}

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON(): ErrorResponse {
    return {
      error: {
        code: this.code,
        message: this.message,
      },
    };
  }
}

export class ValidationError extends AppError {
  constructor(message: string = 'Validation failed') {
    super(400, 'VALIDATION_ERROR', message);
  }
}

export class InvalidCredentialsError extends AppError {
  constructor(message: string = 'Invalid credentials') {
    super(401, 'INVALID_CREDENTIALS', message);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message: string = 'Unauthorized') {
    super(401, 'UNAUTHORIZED', message);
  }
}

export class MissingRefreshTokenError extends AppError {
  constructor(message: string = 'Refresh token is required') {
    super(401, 'missing_refresh_token', message);
  }
}

export class TokenExpiredError extends AppError {
  constructor(message: string = 'Token has expired') {
    super(401, 'TOKEN_EXPIRED', message);
  }
}

export class TokenRevokedError extends AppError {
  constructor(message: string = 'Refresh token has been revoked') {
    super(401, 'TOKEN_REVOKED', message);
  }
}

export class InvalidTokenError extends AppError {
  constructor(message: string = 'Invalid token') {
    super(401, 'INVALID_TOKEN', message);
  }
}

export class EmailConflictError extends AppError {
  constructor(message: string = 'Email is already registered') {
    super(409, 'EMAIL_ALREADY_EXISTS', message);
  }
}

export class RateLimitError extends AppError {
  constructor(message: string = 'Too many requests, please try again later') {
    super(429, 'RATE_LIMIT_EXCEEDED', message);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string = 'Resource not found') {
    super(404, 'NOT_FOUND', message);
  }
}

export class InternalServerError extends AppError {
  constructor(message: string = 'An unexpected internal error occurred') {
    super(500, 'INTERNAL_SERVER_ERROR', message);
  }
}
