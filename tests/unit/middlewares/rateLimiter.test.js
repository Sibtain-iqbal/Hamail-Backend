const rateLimit = require('express-rate-limit');
const { authLimiter } = require('../../../src/middlewares/rateLimiter');

// Mock express-rate-limit
jest.mock('express-rate-limit');

describe('Rate limiter middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('authLimiter', () => {
    test('should create rate limiter with correct configuration', () => {
      // The authLimiter is already created when the module is imported
      // We need to verify that rateLimit was called with the correct options
      expect(rateLimit).toHaveBeenCalledWith({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 20, // 20 requests per window
        skipSuccessfulRequests: true,
      });
    });

    test('should export authLimiter', () => {
      expect(authLimiter).toBeDefined();
      expect(typeof authLimiter).toBe('function');
    });

    test('should have correct window duration', () => {
      const expectedWindowMs = 15 * 60 * 1000; // 15 minutes in milliseconds
      const callArgs = rateLimit.mock.calls[0][0];
      expect(callArgs.windowMs).toBe(expectedWindowMs);
    });

    test('should have correct max requests limit', () => {
      const expectedMax = 20;
      const callArgs = rateLimit.mock.calls[0][0];
      expect(callArgs.max).toBe(expectedMax);
    });

    test('should skip successful requests', () => {
      const callArgs = rateLimit.mock.calls[0][0];
      expect(callArgs.skipSuccessfulRequests).toBe(true);
    });

    test('should not have custom message handler', () => {
      const callArgs = rateLimit.mock.calls[0][0];
      expect(callArgs.message).toBeUndefined();
    });

    test('should not have custom key generator', () => {
      const callArgs = rateLimit.mock.calls[0][0];
      expect(callArgs.keyGenerator).toBeUndefined();
    });

    test('should not have custom skip function', () => {
      const callArgs = rateLimit.mock.calls[0][0];
      expect(callArgs.skip).toBeUndefined();
    });
  });

  describe('rate limiter behavior', () => {
    test('should be configured for authentication endpoints', () => {
      // This test verifies that the rate limiter is configured appropriately
      // for authentication endpoints with reasonable limits
      const callArgs = rateLimit.mock.calls[0][0];

      // 20 requests per 15 minutes is reasonable for auth endpoints
      expect(callArgs.max).toBeLessThanOrEqual(20);
      expect(callArgs.windowMs).toBeGreaterThanOrEqual(15 * 60 * 1000);
    });

    test('should skip successful requests to avoid penalizing valid users', () => {
      const callArgs = rateLimit.mock.calls[0][0];
      expect(callArgs.skipSuccessfulRequests).toBe(true);
    });
  });
});
