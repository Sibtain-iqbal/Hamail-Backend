const express = require('express');
const auth = require('../../middlewares/auth');
const validate = require('../../middlewares/validate');
const requireTradingPlan = require('../../middlewares/requireTradingPlan');
const { mt5Validation } = require('../../validations');
const { mt5Controller } = require('../../controllers');

const router = express.Router();

router.post('/connect', auth(), validate(mt5Validation.connectMT5), mt5Controller.connectMT5);
router.post('/sync', auth(), requireTradingPlan, validate(mt5Validation.syncTrades), mt5Controller.syncTrades);
router.get('/status', auth(), mt5Controller.getConnectionStatus);
router.delete('/disconnect', auth(), mt5Controller.disconnectMT5);

module.exports = router;

/**
 * @swagger
 * tags:
 *   name: MT5
 *   description: MetaTrader 5 account integration and trade synchronization
 */

/**
 * @swagger
 * /mt5/connect:
 *   post:
 *     summary: Connect MT5 account
 *     description: Connect user's MetaTrader 5 account and store credentials for future use.
 *     tags: [MT5]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - accountId
 *               - server
 *               - password
 *             properties:
 *               accountId:
 *                 type: string
 *                 description: MT5 account ID
 *                 example: "12345678"
 *               server:
 *                 type: string
 *                 description: MT5 broker server name
 *                 example: "Broker-Demo"
 *               password:
 *                 type: string
 *                 format: password
 *                 description: MT5 account password
 *                 example: "password123"
 *     responses:
 *       "200":
 *         description: Successfully connected to MT5 account
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 accountId:
 *                   type: integer
 *                   example: 12345678
 *                 server:
 *                   type: string
 *                   example: "Broker-Demo"
 *                 balance:
 *                   type: number
 *                   example: 10000.0
 *                 equity:
 *                   type: number
 *                   example: 10000.0
 *                 margin:
 *                   type: number
 *                   example: 0.0
 *                 currency:
 *                   type: string
 *                   example: "USD"
 *       "400":
 *         $ref: '#/components/responses/BadRequest'
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "409":
 *         description: MT5 account already connected (different account)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *             example:
 *               code: 409
 *               message: "MT5 account already connected. Disconnect current account before connecting a new one."
 *       "500":
 *         description: MT5 service error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *             example:
 *               code: 500
 *               message: "Failed to connect to MT5 account"
 */

/**
 * @swagger
 * /mt5/sync:
 *   post:
 *     summary: Sync trades from MT5
 *     description: Fetch trades from connected MT5 account and import them into the system. If fromDate is not provided, defaults to last sync time or 30 days ago. toDate is automatically set to current time.
 *     tags: [MT5]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               fromDate:
 *                 type: string
 *                 format: date-time
 *                 description: Start date for trade sync (ISO 8601 format). If not provided, defaults to last sync time or 30 days ago. toDate is automatically set to current time.
 *                 example: "2024-01-01T00:00:00Z"
 *     responses:
 *       "200":
 *         description: Successfully synced trades
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 trades:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Trade'
 *                 count:
 *                   type: integer
 *                   description: Number of trades imported
 *                   example: 10
 *                 syncedAt:
 *                   type: string
 *                   format: date-time
 *                   description: Timestamp of sync operation
 *                   example: "2024-01-15T10:30:00Z"
 *       "400":
 *         description: Bad request (e.g., MT5 account not connected)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *             example:
 *               code: 400
 *               message: "MT5 account not connected"
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "403":
 *         $ref: '#/components/responses/TradingPlanRequired'
 *       "500":
 *         description: MT5 service error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */

/**
 * @swagger
 * /mt5/status:
 *   get:
 *     summary: Get MT5 connection status
 *     description: Get the current MT5 account connection status for the authenticated user.
 *     tags: [MT5]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: Connection status retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 connected:
 *                   type: boolean
 *                   description: Whether MT5 account is connected
 *                   example: true
 *                 accountId:
 *                   type: string
 *                   description: MT5 account ID (only if connected)
 *                   example: "12345678"
 *                 server:
 *                   type: string
 *                   description: MT5 server name (only if connected)
 *                   example: "Broker-Demo"
 *                 lastSyncAt:
 *                   type: string
 *                   format: date-time
 *                   description: Last successful sync timestamp (only if connected)
 *                   example: "2024-01-15T10:30:00Z"
 *                 message:
 *                   type: string
 *                   description: Status message (only if not connected)
 *                   example: "MT5 account not connected"
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 */

/**
 * @swagger
 * /mt5/disconnect:
 *   delete:
 *     summary: Disconnect MT5 account
 *     description: Disconnect MT5 account and delete all related data (MT5 trades, heatmap history, stability history).
 *     tags: [MT5]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: Successfully disconnected MT5 account and cleaned up data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "MT5 account disconnected"
 *                 deletedTrades:
 *                   type: boolean
 *                   description: Whether MT5 trades were deleted
 *                   example: true
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 */
