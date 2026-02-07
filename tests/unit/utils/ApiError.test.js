const ApiError = require('../../../src/utils/ApiError');

describe('ApiError', () => {
  test('should create ApiError with statusCode and message', () => {
    const statusCode = 400;
    const message = 'Bad Request';
    const error = new ApiError(statusCode, message);

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.statusCode).toBe(statusCode);
    expect(error.message).toBe(message);
    expect(error.isOperational).toBe(true);
    expect(error.stack).toBeDefined();
  });

  test('should create ApiError with custom isOperational flag', () => {
    const statusCode = 500;
    const message = 'Internal Server Error';
    const isOperational = false;
    const error = new ApiError(statusCode, message, isOperational);

    expect(error.statusCode).toBe(statusCode);
    expect(error.message).toBe(message);
    expect(error.isOperational).toBe(isOperational);
  });

  test('should create ApiError with custom stack trace', () => {
    const statusCode = 404;
    const message = 'Not Found';
    const customStack = 'Custom stack trace';
    const error = new ApiError(statusCode, message, true, customStack);

    expect(error.statusCode).toBe(statusCode);
    expect(error.message).toBe(message);
    expect(error.stack).toBe(customStack);
  });

  test('should inherit from Error', () => {
    const error = new ApiError(400, 'Test Error');

    expect(error instanceof Error).toBe(true);
    expect(error.name).toBe('Error');
  });

  test('should have correct default values', () => {
    const error = new ApiError(400, 'Test Error');

    expect(error.isOperational).toBe(true);
    expect(error.stack).toBeDefined();
    expect(typeof error.stack).toBe('string');
  });
});
