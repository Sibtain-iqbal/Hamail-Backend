const express = require('express');
const healthController = require('../../controllers/health.controller');

const router = express.Router();

router.route('/').get(healthController.getHealth);

module.exports = router;

/**
 * @swagger
 * tags:
 *   name: Health
 *   description: System health check
 */

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check
 *     description: Check the health status of the API and its dependencies.
 *     tags: [Health]
 *     responses:
 *       "200":
 *         description: System is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, unhealthy]
 *                   description: Overall system health status
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                   description: Health check timestamp
 *                 uptime:
 *                   type: number
 *                   description: System uptime in seconds
 *                 version:
 *                   type: string
 *                   description: API version
 *                 environment:
 *                   type: string
 *                   description: Current environment
 *                 services:
 *                   type: object
 *                   properties:
 *                     database:
 *                       type: object
 *                       properties:
 *                         status:
 *                           type: string
 *                           enum: [connected, disconnected, error]
 *                         responseTime:
 *                           type: number
 *                           description: Database response time in milliseconds
 *                     memory:
 *                       type: object
 *                       properties:
 *                         used:
 *                           type: number
 *                           description: Memory usage in MB
 *                         total:
 *                           type: number
 *                           description: Total memory in MB
 *                         percentage:
 *                           type: number
 *                           description: Memory usage percentage
 *             example:
 *               status: "healthy"
 *               timestamp: "2023-01-01T12:00:00.000Z"
 *               uptime: 3600
 *               version: "1.0.0"
 *               environment: "development"
 *               services:
 *                 database:
 *                   status: "connected"
 *                   responseTime: 15
 *                 memory:
 *                   used: 45.2
 *                   total: 512
 *                   percentage: 8.8
 *       "503":
 *         description: System is unhealthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, unhealthy]
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                 uptime:
 *                   type: number
 *                 version:
 *                   type: string
 *                 environment:
 *                   type: string
 *                 services:
 *                   type: object
 *                 errors:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: List of health check errors
 *             example:
 *               status: "unhealthy"
 *               timestamp: "2023-01-01T12:00:00.000Z"
 *               uptime: 3600
 *               version: "1.0.0"
 *               environment: "development"
 *               services:
 *                 database:
 *                   status: "disconnected"
 *                   responseTime: null
 *                 memory:
 *                   used: 45.2
 *                   total: 512
 *                   percentage: 8.8
 *               errors:
 *                 - "Database connection failed"
 */
