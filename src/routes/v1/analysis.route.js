const express = require('express');
const auth = require('../../middlewares/auth');
const validate = require('../../middlewares/validate');
const requireTradingPlan = require('../../middlewares/requireTradingPlan');
const analysisValidation = require('../../validations/analysis.validation');
const analysisController = require('../../controllers/analysis.controller');

const router = express.Router();

router.route('/state').get(auth(), requireTradingPlan, validate(analysisValidation.getState), analysisController.getState);

router
  .route('/forecast')
  .get(auth(), requireTradingPlan, validate(analysisValidation.getForecast), analysisController.getForecast);

router
  .route('/insights')
  .get(auth(), requireTradingPlan, validate(analysisValidation.getInsights), analysisController.getInsights);

router
  .route('/history')
  .get(auth(), requireTradingPlan, validate(analysisValidation.getHistory), analysisController.getHistory);

module.exports = router;

/**
 * @swagger
 * tags:
 *   name: Analysis
 *   description: Trading psychological analysis
 */

/**
 * @swagger
 * /analysis/state:
 *   get:
 *     summary: Get current psychological state
 *     description: Get the current psychological state analysis for the authenticated user.
 *     tags: [Analysis]
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
 *                 state:
 *                   type: string
 *                   enum: [STABLE, OVEREXTENDED, HESITANT, AGGRESSIVE]
 *                   description: Current psychological state
 *                 confidence:
 *                   type: number
 *                   minimum: 0
 *                   maximum: 100
 *                   description: Confidence level percentage
 *                 planAdherence:
 *                   type: number
 *                   minimum: 0
 *                   maximum: 100
 *                   description: Plan adherence score percentage
 *                 analyzedTradeCount:
 *                   type: integer
 *                   description: Number of trades analyzed (last 5–10)
 *                 indicators:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       category:
 *                         type: string
 *                       message:
 *                         type: string
 *                       severity:
 *                         type: string
 *                         enum: [positive, neutral, warning, critical]
 *                       value:
 *                         type: number
 *                     description: State indicators
 *                 lastUpdated:
 *                   type: string
 *                   format: date-time
 *                   description: Last state update timestamp
 *                 recommendations:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: Psychological recommendations
 *             example:
 *               state: "STABLE"
 *               confidence: 72
 *               planAdherence: 81
 *               analyzedTradeCount: 9
 *               indicators:
 *                 - category: "plan"
 *                   message: "Trading within plan parameters"
 *                   severity: "positive"
 *               lastUpdated: "2023-01-01T09:00:00Z"
 *               recommendations: ["Maintain discipline; continue tracking adherence"]
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "403":
 *         $ref: '#/components/responses/TradingPlanRequired'
 */

/**
 * @swagger
 * /analysis/forecast:
 *   get:
 *     summary: Get session forecast
 *     description: Get psychological forecast for the current trading session.
 *     tags: [Analysis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: session
 *         schema:
 *           type: string
 *           enum: [LONDON, NY, ASIA]
 *         description: Trading session to forecast
 *     responses:
 *       "200":
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 session:
 *                   type: string
 *                   enum: [LONDON, NY, ASIA]
 *                   description: Trading session
 *                 forecast:
 *                   type: string
 *                   enum: [POSITIVE, NEUTRAL, NEGATIVE]
 *                   description: Overall session forecast
 *                 predictedBias:
 *                   type: string
 *                   description: Predicted psychological bias risk
 *                 riskLevel:
 *                   type: string
 *                   enum: [LOW, MEDIUM, HIGH]
 *                   description: Risk level associated with predicted bias
 *                 basedOnState:
 *                   type: string
 *                   enum: [STABLE, OVEREXTENDED, HESITANT, AGGRESSIVE]
 *                   description: Current state used for the forecast
 *                 recommendations:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: Session recommendations
 *             example:
 *               session: "LONDON"
 *               forecast: "NEUTRAL"
 *               predictedBias: "Revenge trading risk"
 *               riskLevel: "HIGH"
 *               basedOnState: "AGGRESSIVE"
 *               recommendations: ["Consider pausing before new entries", "Reduce risk to plan level"]
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "403":
 *         $ref: '#/components/responses/TradingPlanRequired'
 */

/**
 * @swagger
 * /analysis/insights:
 *   get:
 *     summary: Get performance insights
 *     description: Get psychological insights based on trading performance.
 *     tags: [Analysis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [WEEK, MONTH, QUARTER, YEAR]
 *         default: MONTH
 *         description: Analysis period
 *     responses:
 *       "200":
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 period:
 *                   type: string
 *                   enum: [WEEK, MONTH, QUARTER, YEAR]
 *                   description: Analysis period
 *                 insights:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       type:
 *                         type: string
 *                         enum: [POSITIVE, CONSTRUCTIVE]
 *                         description: Insight type
 *                       title:
 *                         type: string
 *                         description: Insight title
 *                       description:
 *                         type: string
 *                         description: Insight description
 *                       metric:
 *                         type: object
 *                         properties:
 *                           label:
 *                             type: string
 *                           value:
 *                             type: string
 *                         description: Key metric for the insight
 *                   description: Performance insights (one positive + one constructive minimum)
 *                 stats:
 *                   type: object
 *                   properties:
 *                     winRate:
 *                       type: number
 *                       description: Win rate percentage
 *                     avgRiskReward:
 *                       type: number
 *                       description: Average R:R achieved
 *                     planAdherence:
 *                       type: number
 *                       minimum: 0
 *                       maximum: 100
 *                       description: Plan adherence score percentage
 *                     tradesThisWeek:
 *                       type: integer
 *                       description: Number of trades in the last 7 days
 *                 recommendations:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: Improvement recommendations
 *             example:
 *               period: "MONTH"
 *               insights:
 *                 - type: "POSITIVE"
 *                   title: "Strong plan adherence"
 *                   description: "You are trading within your rules. Keep it up."
 *                   metric:
 *                     label: "Plan adherence"
 *                     value: "81%"
 *                 - type: "CONSTRUCTIVE"
 *                   title: "Exiting too early"
 *                   description: "Consider scaling out or letting winners reach planned targets."
 *                   metric:
 *                     label: "Early exits"
 *                     value: "40%"
 *               stats:
 *                 winRate: 60
 *                 avgRiskReward: 1.6
 *                 planAdherence: 72
 *                 tradesThisWeek: 7
 *               recommendations: ["Stick to sessions and daily trade limits"]
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "403":
 *         $ref: '#/components/responses/TradingPlanRequired'
 */

/**
 * @swagger
 * /analysis/history:
 *   get:
 *     summary: Get historical state changes
 *     description: Get historical psychological state changes over time.
 *     tags: [Analysis]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: Start date for history
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: End date for history
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *         default: 50
 *         description: Maximum number of records
 *     responses:
 *       "200":
 *         description: OK
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 history:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       timestamp:
 *                         type: string
 *                         format: date-time
 *                         description: State change timestamp
 *                       state:
 *                         type: string
 *                         enum: [STABLE, OVEREXTENDED, HESITANT, AGGRESSIVE]
 *                         description: Psychological state
 *                       confidence:
 *                         type: number
 *                         minimum: 0
 *                         maximum: 100
 *                         description: Confidence level
 *                       trigger:
 *                         type: string
 *                         description: State change trigger
 *                       context:
 *                         type: object
 *                         description: Additional context
 *                   description: Historical state changes
 *                 summary:
 *                   type: object
 *                   properties:
 *                     totalChanges:
 *                       type: integer
 *                       description: Total number of state changes
 *                     mostCommonState:
 *                       type: string
 *                       description: Most common state
 *                     averageConfidence:
 *                       type: number
 *                       description: Average confidence level
 *                     volatility:
 *                       type: number
 *                       description: State volatility score
 *                   description: History summary
 *             example:
 *               history:
 *                 - timestamp: "2023-01-01T09:00:00Z"
 *                   state: "STABLE"
 *                   confidence: 75
 *                   trigger: "Successful trade"
 *                   context: {"tradeId": "123", "profit": 150}
 *                 - timestamp: "2023-01-01T10:30:00Z"
 *                   state: "HESITANT"
 *                   confidence: 45
 *                   trigger: "Stop loss hit"
 *                   context: {"tradeId": "124", "loss": -75}
 *               summary:
 *                 totalChanges: 25
 *                 mostCommonState: "STABLE"
 *                 averageConfidence: 68
 *                 volatility: 0.3
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "403":
 *         $ref: '#/components/responses/TradingPlanRequired'
 */
