const httpMocks = require('node-mocks-http');
const Joi = require('joi');
const httpStatus = require('http-status');
const validate = require('../../../src/middlewares/validate');
const ApiError = require('../../../src/utils/ApiError');

describe('Validate middleware', () => {
  let req;
  let res;
  let next;

  beforeEach(() => {
    req = httpMocks.createRequest();
    res = httpMocks.createResponse();
    next = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('body validation', () => {
    test('should call next when body is valid', () => {
      const schema = {
        body: Joi.object({
          name: Joi.string().required(),
          email: Joi.string().email().required(),
        }),
      };

      req.body = {
        name: 'John Doe',
        email: 'john@example.com',
      };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.body).toEqual({
        name: 'John Doe',
        email: 'john@example.com',
      });
    });

    test('should call next with error when body is invalid', () => {
      const schema = {
        body: Joi.object({
          name: Joi.string().required(),
          email: Joi.string().email().required(),
        }),
      };

      req.body = {
        name: 'John Doe',
        email: 'invalid-email',
      };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: httpStatus.BAD_REQUEST,
          message: expect.stringContaining('email'),
        })
      );
    });

    test('should call next with error when required field is missing', () => {
      const schema = {
        body: Joi.object({
          name: Joi.string().required(),
          email: Joi.string().email().required(),
        }),
      };

      req.body = {
        name: 'John Doe',
      };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: httpStatus.BAD_REQUEST,
          message: expect.stringContaining('email'),
        })
      );
    });
  });

  describe('params validation', () => {
    test('should call next when params are valid', () => {
      const schema = {
        params: Joi.object({
          userId: Joi.string().required(),
        }),
      };

      req.params = {
        userId: '123456789',
      };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.params).toEqual({
        userId: '123456789',
      });
    });

    test('should call next with error when params are invalid', () => {
      const schema = {
        params: Joi.object({
          userId: Joi.string().required(),
        }),
      };

      req.params = {};

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: httpStatus.BAD_REQUEST,
          message: expect.stringContaining('userId'),
        })
      );
    });
  });

  describe('query validation', () => {
    test('should call next when query is valid', () => {
      const schema = {
        query: Joi.object({
          page: Joi.number().integer().min(1).default(1),
          limit: Joi.number().integer().min(1).max(100).default(10),
        }),
      };

      req.query = {
        page: '2',
        limit: '20',
      };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.query).toEqual({
        page: 2,
        limit: 20,
      });
    });

    test('should call next with error when query is invalid', () => {
      const schema = {
        query: Joi.object({
          page: Joi.number().integer().min(1).default(1),
          limit: Joi.number().integer().min(1).max(100).default(10),
        }),
      };

      req.query = {
        page: '0',
        limit: '200',
      };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: httpStatus.BAD_REQUEST,
          message: expect.stringContaining('page'),
        })
      );
    });
  });

  describe('multiple validation', () => {
    test('should validate body, params, and query together', () => {
      const schema = {
        body: Joi.object({
          name: Joi.string().required(),
        }),
        params: Joi.object({
          userId: Joi.string().required(),
        }),
        query: Joi.object({
          page: Joi.number().integer().min(1).default(1),
        }),
      };

      req.body = { name: 'John Doe' };
      req.params = { userId: '123456789' };
      req.query = { page: '2' };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.body).toEqual({ name: 'John Doe' });
      expect(req.params).toEqual({ userId: '123456789' });
      expect(req.query).toEqual({ page: 2 });
    });

    test('should call next with error when any validation fails', () => {
      const schema = {
        body: Joi.object({
          name: Joi.string().required(),
        }),
        params: Joi.object({
          userId: Joi.string().required(),
        }),
        query: Joi.object({
          page: Joi.number().integer().min(1).default(1),
        }),
      };

      req.body = { name: 'John Doe' };
      req.params = {}; // Missing userId
      req.query = { page: '2' };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: httpStatus.BAD_REQUEST,
          message: expect.stringContaining('userId'),
        })
      );
    });
  });

  describe('error handling', () => {
    test('should handle multiple validation errors', () => {
      const schema = {
        body: Joi.object({
          name: Joi.string().required(),
          email: Joi.string().email().required(),
        }),
      };

      req.body = {
        name: '',
        email: 'invalid-email',
      };

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: httpStatus.BAD_REQUEST,
          message: expect.stringMatching(/name.*email|email.*name/),
        })
      );
    });

    test('should not modify original request when validation fails', () => {
      const schema = {
        body: Joi.object({
          name: Joi.string().required(),
        }),
      };

      const originalBody = { name: '' };
      req.body = originalBody;

      const validateMiddleware = validate(schema);
      validateMiddleware(req, res, next);

      expect(req.body).toBe(originalBody);
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
    });
  });
});
