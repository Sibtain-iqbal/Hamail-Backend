const request = require('supertest');
const httpStatus = require('http-status');
const app = require('../../src/app');
const setupTestDB = require('../utils/setupTestDB');

setupTestDB();

describe('Health routes', () => {
  describe('GET /v1/health', () => {
    test('should return 200 and health status when system is healthy', async () => {
      const res = await request(app).get('/v1/health').expect(httpStatus.OK);

      expect(res.body).toHaveProperty('status');
      expect(res.body).toHaveProperty('timestamp');
      expect(res.body).toHaveProperty('uptime');
      expect(res.body).toHaveProperty('version');
      expect(res.body).toHaveProperty('environment');
      expect(res.body).toHaveProperty('services');

      // Check services structure
      expect(res.body.services).toHaveProperty('database');
      expect(res.body.services).toHaveProperty('memory');

      // Check database service
      expect(res.body.services.database).toHaveProperty('status');
      expect(res.body.services.database).toHaveProperty('responseTime');
      expect(['connected', 'disconnected', 'error']).toContain(res.body.services.database.status);

      // Check memory service
      expect(res.body.services.memory).toHaveProperty('used');
      expect(res.body.services.memory).toHaveProperty('total');
      expect(res.body.services.memory).toHaveProperty('percentage');

      // Validate data types
      expect(typeof res.body.status).toBe('string');
      expect(typeof res.body.timestamp).toBe('string');
      expect(typeof res.body.uptime).toBe('number');
      expect(typeof res.body.version).toBe('string');
      expect(typeof res.body.environment).toBe('string');
      expect(typeof res.body.services.database.responseTime).toBe('number');
      expect(typeof res.body.services.memory.used).toBe('number');
      expect(typeof res.body.services.memory.total).toBe('number');
      expect(typeof res.body.services.memory.percentage).toBe('number');
    });

    test('should return healthy status when database is connected', async () => {
      const res = await request(app).get('/v1/health').expect(httpStatus.OK);

      expect(res.body.status).toBe('healthy');
      expect(res.body.services.database.status).toBe('connected');
      expect(res.body.services.database.responseTime).toBeGreaterThan(0);
    });

    test('should include valid timestamp', async () => {
      const res = await request(app).get('/v1/health').expect(httpStatus.OK);

      const timestamp = new Date(res.body.timestamp);
      expect(timestamp).toBeInstanceOf(Date);
      expect(timestamp.getTime()).not.toBeNaN();

      // Check if timestamp is recent (within last minute)
      const now = new Date();
      const timeDiff = Math.abs(now.getTime() - timestamp.getTime());
      expect(timeDiff).toBeLessThan(60000); // 1 minute
    });

    test('should include valid uptime', async () => {
      const res = await request(app).get('/v1/health').expect(httpStatus.OK);

      expect(res.body.uptime).toBeGreaterThan(0);
      expect(typeof res.body.uptime).toBe('number');
    });

    test('should include version information', async () => {
      const res = await request(app).get('/v1/health').expect(httpStatus.OK);

      expect(res.body.version).toBeDefined();
      expect(typeof res.body.version).toBe('string');
      expect(res.body.version.length).toBeGreaterThan(0);
    });

    test('should include environment information', async () => {
      const res = await request(app).get('/v1/health').expect(httpStatus.OK);

      expect(res.body.environment).toBeDefined();
      expect(typeof res.body.environment).toBe('string');
      expect(['development', 'production', 'test']).toContain(res.body.environment);
    });

    test('should include memory usage information', async () => {
      const res = await request(app).get('/v1/health').expect(httpStatus.OK);

      const { memory } = res.body.services;
      expect(memory.used).toBeGreaterThan(0);
      expect(memory.total).toBeGreaterThan(0);
      expect(memory.percentage).toBeGreaterThan(0);
      expect(memory.percentage).toBeLessThanOrEqual(100);
      expect(memory.used).toBeLessThanOrEqual(memory.total);
    });

    test('should not require authentication', async () => {
      // This test ensures the health endpoint is publicly accessible
      const res = await request(app).get('/v1/health').expect(httpStatus.OK);

      expect(res.body).toHaveProperty('status');
    });

    test('should return consistent response structure', async () => {
      const res1 = await request(app).get('/v1/health').expect(httpStatus.OK);

      const res2 = await request(app).get('/v1/health').expect(httpStatus.OK);

      // Both responses should have the same structure
      expect(Object.keys(res1.body)).toEqual(Object.keys(res2.body));
      expect(Object.keys(res1.body.services)).toEqual(Object.keys(res2.body.services));
      expect(Object.keys(res1.body.services.database)).toEqual(Object.keys(res2.body.services.database));
      expect(Object.keys(res1.body.services.memory)).toEqual(Object.keys(res2.body.services.memory));
    });

    test('should handle multiple concurrent requests', async () => {
      const requests = Array.from({ length: 5 }, () => request(app).get('/v1/health').expect(httpStatus.OK));

      const responses = await Promise.all(requests);

      responses.forEach((res) => {
        expect(res.body).toHaveProperty('status');
        expect(res.body).toHaveProperty('services');
        expect(res.body.services).toHaveProperty('database');
        expect(res.body.services).toHaveProperty('memory');
      });
    });
  });
});
