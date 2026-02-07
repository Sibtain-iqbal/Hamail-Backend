const catchAsync = require('../../../src/utils/catchAsync');

describe('catchAsync', () => {
  test('should return a function that handles async errors', () => {
    const asyncFn = catchAsync(async () => {
      throw new Error('Test error');
    });

    expect(typeof asyncFn).toBe('function');
  });

  test('should call next with error when async function throws', async () => {
    const error = new Error('Test error');
    const asyncFn = catchAsync(async () => {
      throw error;
    });

    const req = {};
    const res = {};
    const next = jest.fn();

    await asyncFn(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
  });

  test('should call next with error when async function rejects', async () => {
    const error = new Error('Test rejection');
    const asyncFn = catchAsync(async () => {
      throw error;
    });

    const req = {};
    const res = {};
    const next = jest.fn();

    await asyncFn(req, res, next);

    expect(next).toHaveBeenCalledWith(error);
  });

  test('should not call next when async function succeeds', async () => {
    const asyncFn = catchAsync(async () => {
      return 'success';
    });

    const req = {};
    const res = {};
    const next = jest.fn();

    await asyncFn(req, res, next);

    expect(next).not.toHaveBeenCalled();
  });

  test('should pass through req, res, next to wrapped function', async () => {
    const mockFn = jest.fn().mockResolvedValue('success');
    const asyncFn = catchAsync(mockFn);

    const req = { body: { test: 'data' } };
    const res = { status: jest.fn() };
    const next = jest.fn();

    await asyncFn(req, res, next);

    expect(mockFn).toHaveBeenCalledWith(req, res, next);
  });

  test('should handle synchronous functions that return successfully', async () => {
    const syncFn = catchAsync(() => {
      return 'sync success';
    });

    const req = {};
    const res = {};
    const next = jest.fn();

    await syncFn(req, res, next);

    expect(next).not.toHaveBeenCalled();
  });
});
