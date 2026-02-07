class ApiError extends Error {
  constructor(statusCode, message, options = {}, stack = '') {
    super(message);
    this.statusCode = statusCode;
    let resolvedOptions = {};

    if (typeof options === 'boolean') {
      resolvedOptions = { isOperational: options, stack };
    } else {
      resolvedOptions = options || {};
    }

    const { isOperational = true, reason, stack: optionsStack } = resolvedOptions;

    this.isOperational = isOperational;
    if (reason) {
      this.reason = reason;
    }

    const finalStack = typeof options === 'boolean' ? stack : optionsStack;

    if (finalStack) {
      this.stack = finalStack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

module.exports = ApiError;
