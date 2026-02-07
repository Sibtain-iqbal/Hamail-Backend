const express = require('express');
const auth = require('../../middlewares/auth');
const validate = require('../../middlewares/validate');
const tradingPlanValidation = require('../../validations/tradingPlan.validation');
const tradingPlanController = require('../../controllers/tradingPlan.controller');

const router = express.Router();

router
  .route('/')
  .post(auth(), validate(tradingPlanValidation.createTradingPlan), tradingPlanController.createTradingPlan)
  .get(auth(), validate(tradingPlanValidation.getTradingPlan), tradingPlanController.getTradingPlan)
  .delete(auth(), validate(tradingPlanValidation.deleteTradingPlan), tradingPlanController.deleteTradingPlan);

router.route('/status').get(auth(), tradingPlanController.getTradingPlanStatus);

module.exports = router;

/**
 * @swagger
 * tags:
 *   name: Trading Plan
 *   description: Trading plan management
 */

/**
 * @swagger
 * /trading-plan:
 *   post:
 *     summary: Create or update trading plan
 *     description: Create a new trading plan or update existing one for the authenticated user.
 *     tags: [Trading Plan]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - maxTradesPerDay
 *               - riskPercentPerTrade
 *               - targetRiskRewardRatio
 *               - preferredSessions
 *               - stopLossDiscipline
 *             properties:
 *               maxTradesPerDay:
 *                 type: integer
 *                 minimum: 0
 *                 description: Maximum number of trades per day
 *               riskPercentPerTrade:
 *                 type: number
 *                 minimum: 0
 *                 maximum: 100
 *                 description: Risk percentage per trade
 *               targetRiskRewardRatio:
 *                 type: number
 *                 minimum: 0
 *                 description: Target risk-reward ratio
 *               preferredSessions:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [LONDON, NY, ASIA]
 *                 description: Preferred trading sessions
 *               stopLossDiscipline:
 *                 type: string
 *                 enum: [ALWAYS, FLEXIBLE]
 *                 description: Stop loss discipline approach
 *             example:
 *               maxTradesPerDay: 5
 *               riskPercentPerTrade: 2.0
 *               targetRiskRewardRatio: 1.5
 *               preferredSessions: [LONDON, NY]
 *               stopLossDiscipline: ALWAYS
 *     responses:
 *       "201":
 *         description: Created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TradingPlan'
 *       "400":
 *         $ref: '#/components/responses/BadRequest'
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *
 *   get:
 *     summary: Get current trading plan
 *     description: Get the current trading plan for the authenticated user.
 *     tags: [Trading Plan]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TradingPlan'
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "404":
 *         $ref: '#/components/responses/NotFound'
 *
 * /trading-plan/status:
 *   get:
 *     summary: Get trading plan status
 *     description: Returns whether the authenticated user has a trading plan.
 *     tags: [Trading Plan]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 hasTradingPlan:
 *                   type: boolean
 *                   example: true
 *                 lastUpdated:
 *                   type: string
 *                   format: date-time
 *                   nullable: true
 *                   example: "2025-01-10T12:00:00.000Z"
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *
 *   delete:
 *     summary: Reset trading plan
 *     description: Delete the current trading plan for the authenticated user.
 *     tags: [Trading Plan]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "204":
 *         description: No content
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "404":
 *         $ref: '#/components/responses/NotFound'
 */
