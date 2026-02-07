const httpStatus = require('http-status');
const mongoose = require('mongoose');
const { version } = require('../../package.json');
const config = require('../config/config');
const logger = require('../config/logger');

/**
 * Check database connection health
 * @returns {Promise<Object>}
 */
const checkDatabase = async () => {
  const startTime = Date.now();
  try {
    // Check if mongoose is connected
    if (mongoose.connection.readyState === 1) {
      // Ping the database to check response time
      await mongoose.connection.db.admin().ping();
      const responseTime = Date.now() - startTime;

      return {
        status: 'connected',
        responseTime,
      };
    }

    return {
      status: 'disconnected',
      responseTime: null,
    };
  } catch (error) {
    logger.error('Database health check failed: %s', error.message);
    return {
      status: 'error',
      responseTime: null,
    };
  }
};

/**
 * Check memory usage
 * @returns {Object}
 */
const checkMemory = () => {
  const memUsage = process.memoryUsage();
  const used = Math.round((memUsage.heapUsed / 1024 / 1024) * 100) / 100;
  const total = Math.round((memUsage.heapTotal / 1024 / 1024) * 100) / 100;
  const percentage = Math.round((used / total) * 100 * 100) / 100;

  return {
    used,
    total,
    percentage,
  };
};

/**
 * Get health status
 * @param {Object} req
 * @param {Object} res
 */
const getHealth = async (req, res) => {
  logger.info('Health check requested');

  const timestamp = new Date().toISOString();
  const uptime = Math.floor(process.uptime());

  try {
    // Check database health
    const database = await checkDatabase();

    // Check memory usage
    const memory = checkMemory();

    // Determine overall health status
    const errors = [];
    let overallStatus = 'healthy';

    if (database.status !== 'connected') {
      errors.push('Database connection failed');
      overallStatus = 'unhealthy';
    }

    if (memory.percentage > 90) {
      errors.push('High memory usage detected');
      overallStatus = 'unhealthy';
    }

    const healthData = {
      status: overallStatus,
      timestamp,
      uptime,
      version,
      environment: config.env,
      services: {
        database,
        memory,
      },
    };

    // Add errors if any
    if (errors.length > 0) {
      healthData.errors = errors;
    }

    const statusCode = overallStatus === 'healthy' ? httpStatus.OK : httpStatus.SERVICE_UNAVAILABLE;

    logger.info('Health check completed: %s', overallStatus);
    res.status(statusCode).send(healthData);
  } catch (error) {
    logger.error('Health check failed: %s', error.message);

    const errorResponse = {
      status: 'unhealthy',
      timestamp,
      uptime: Math.floor(process.uptime()),
      version,
      environment: config.env,
      services: {
        database: { status: 'error', responseTime: null },
        memory: checkMemory(),
      },
      errors: ['Health check failed'],
    };

    res.status(httpStatus.SERVICE_UNAVAILABLE).send(errorResponse);
  }
};

module.exports = {
  getHealth,
};
