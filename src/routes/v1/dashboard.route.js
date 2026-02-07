const express = require('express');
const auth = require('../../middlewares/auth');
const validate = require('../../middlewares/validate');
const requireTradingPlan = require('../../middlewares/requireTradingPlan');
const dashboardValidation = require('../../validations/dashboard.validation');
const dashboardController = require('../../controllers/dashboard.controller');

const router = express.Router();

router
  .route('/')
  .get(auth(), requireTradingPlan, validate(dashboardValidation.getDashboard), dashboardController.getDashboard);

router
  .route('/summary')
  .get(auth(), requireTradingPlan, validate(dashboardValidation.getSummary), dashboardController.getSummary);

module.exports = router;

/**
 * @swagger
 * tags:
 *   name: Dashboard
 *   description: Trading dashboard and analytics
 */

/**
 * @swagger
 * /dashboard:
 *   get:
 *     summary: Get complete dashboard data
 *     description: Get comprehensive dashboard data including trades, performance metrics, psychological state, and insights.
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [WEEK, MONTH, QUARTER, YEAR]
 *         default: MONTH
 *         description: Analysis period for dashboard data
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
 *                 summary:
 *                   type: object
 *                   properties:
 *                     totalTrades:
 *                       type: integer
 *                       description: Total number of trades
 *                     winningTrades:
 *                       type: integer
 *                       description: Number of winning trades
 *                     losingTrades:
 *                       type: integer
 *                       description: Number of losing trades
 *                     winRate:
 *                       type: number
 *                       description: Win rate percentage
 *                     totalProfitLoss:
 *                       type: number
 *                       description: Total profit/loss
 *                     averageRiskReward:
 *                       type: number
 *                       description: Average risk-reward ratio
 *                     bestTrade:
 *                       type: number
 *                       description: Best trade profit
 *                     worstTrade:
 *                       type: number
 *                       description: Worst trade loss
 *                 psychologicalState:
 *                   type: object
 *                   properties:
 *                     state:
 *                       type: string
 *                       enum: [STABLE, OVEREXTENDED, HESITANT, AGGRESSIVE]
 *                       description: Current psychological state
 *                     confidence:
 *                       type: number
 *                       minimum: 0
 *                       maximum: 100
 *                       description: Confidence level
 *                     planAdherence:
 *                       type: number
 *                       minimum: 0
 *                       maximum: 100
 *                       description: Plan adherence score percentage
 *                     analyzedTradeCount:
 *                       type: integer
 *                       description: Number of trades analyzed (last 5–10)
 *                     indicators:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           category:
 *                             type: string
 *                           message:
 *                             type: string
 *                           severity:
 *                             type: string
 *                             enum: [positive, neutral, warning, critical]
 *                           value:
 *                             type: number
 *                       description: State indicators
 *                 performance:
 *                   type: object
 *                   properties:
 *                     dailyPnL:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           date:
 *                             type: string
 *                             format: date
 *                           profitLoss:
 *                             type: number
 *                     sessionPerformance:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           session:
 *                             type: string
 *                             enum: [LONDON, NY, ASIA]
 *                           trades:
 *                             type: integer
 *                           profitLoss:
 *                             type: number
 *                           winRate:
 *                             type: number
 *                     riskMetrics:
 *                       type: object
 *                       properties:
 *                         averageRiskPerTrade:
 *                           type: number
 *                         maxDrawdown:
 *                           type: number
 *                         sharpeRatio:
 *                           type: number
 *                 insights:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       type:
 *                         type: string
 *                         enum: [POSITIVE, CONSTRUCTIVE]
 *                       title:
 *                         type: string
 *                       description:
 *                         type: string
 *                       metric:
 *                         type: object
 *                         properties:
 *                           label:
 *                             type: string
 *                           value:
 *                             type: string
 *                 recentTrades:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       entryTime:
 *                         type: string
 *                         format: date-time
 *                       exitTime:
 *                         type: string
 *                         format: date-time
 *                       profitLoss:
 *                         type: number
 *                       session:
 *                         type: string
 *                         enum: [LONDON, NY, ASIA]
 *                       riskPercentUsed:
 *                         type: number
 *                       riskRewardAchieved:
 *                         type: number
 *             example:
 *               period: "MONTH"
 *               summary:
 *                 totalTrades: 25
 *                 winningTrades: 15
 *                 losingTrades: 10
 *                 winRate: 60.0
 *                 totalProfitLoss: 1250.0
 *                 averageRiskReward: 1.8
 *                 bestTrade: 450.0
 *                 worstTrade: -180.0
 *               psychologicalState:
 *                 state: "STABLE"
 *                 confidence: 72
 *                 planAdherence: 81
 *                 analyzedTradeCount: 9
 *                 indicators:
 *                   - category: "plan"
 *                     message: "Trading within plan parameters"
 *                     severity: "positive"
 *               performance:
 *                 dailyPnL:
 *                   - date: "2023-01-01"
 *                     profitLoss: 150.0
 *                   - date: "2023-01-02"
 *                     profitLoss: -75.0
 *                 sessionPerformance:
 *                   - session: "LONDON"
 *                     trades: 12
 *                     profitLoss: 800.0
 *                     winRate: 66.7
 *                   - session: "NY"
 *                     trades: 8
 *                     profitLoss: 300.0
 *                     winRate: 62.5
 *                 riskMetrics:
 *                   averageRiskPerTrade: 2.1
 *                   maxDrawdown: 5.2
 *                   sharpeRatio: 1.4
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
 *               recentTrades:
 *                 - id: "trade123"
 *                   entryTime: "2023-01-01T09:00:00Z"
 *                   exitTime: "2023-01-01T10:30:00Z"
 *                   profitLoss: 150.0
 *                   session: "LONDON"
 *                   riskPercentUsed: 2.0
 *                   riskRewardAchieved: 1.5
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "403":
 *         $ref: '#/components/responses/TradingPlanRequired'
 */

/**
 * @swagger
 * /dashboard/summary:
 *   get:
 *     summary: Get summary stats
 *     description: Get quick summary statistics for the dashboard header or overview.
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: period
 *         schema:
 *           type: string
 *           enum: [WEEK, MONTH, QUARTER, YEAR]
 *         default: MONTH
 *         description: Analysis period for summary stats
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
 *                 quickStats:
 *                   type: object
 *                   properties:
 *                     totalTrades:
 *                       type: integer
 *                       description: Total number of trades
 *                     winRate:
 *                       type: number
 *                       description: Win rate percentage
 *                     totalPnL:
 *                       type: number
 *                       description: Total profit/loss
 *                     avgRiskReward:
 *                       type: number
 *                       description: Average risk-reward ratio
 *                     currentState:
 *                       type: string
 *                       enum: [STABLE, OVEREXTENDED, HESITANT, AGGRESSIVE]
 *                       description: Current psychological state
 *                     confidence:
 *                       type: number
 *                       minimum: 0
 *                       maximum: 100
 *                       description: Confidence level
 *                 trends:
 *                   type: object
 *                   properties:
 *                     pnlTrend:
 *                       type: string
 *                       enum: [UP, DOWN, STABLE]
 *                       description: P&L trend direction
 *                     winRateTrend:
 *                       type: string
 *                       enum: [UP, DOWN, STABLE]
 *                       description: Win rate trend direction
 *                     riskTrend:
 *                       type: string
 *                       enum: [UP, DOWN, STABLE]
 *                       description: Risk management trend
 *                 alerts:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       type:
 *                         type: string
 *                         enum: [WARNING, SUCCESS, INFO, ERROR]
 *                       message:
 *                         type: string
 *                       priority:
 *                         type: string
 *                         enum: [HIGH, MEDIUM, LOW]
 *             example:
 *               period: "MONTH"
 *               quickStats:
 *                 totalTrades: 25
 *                 winRate: 60.0
 *                 totalPnL: 1250.0
 *                 avgRiskReward: 1.8
 *                 currentState: "STABLE"
 *                 confidence: 75
 *               trends:
 *                 pnlTrend: "UP"
 *                 winRateTrend: "STABLE"
 *                 riskTrend: "DOWN"
 *               alerts:
 *                 - type: "SUCCESS"
 *                   message: "Win rate improved this week"
 *                   priority: "MEDIUM"
 *                 - type: "WARNING"
 *                   message: "Risk per trade above target"
 *                   priority: "HIGH"
 *       "401":
 *         $ref: '#/components/responses/Unauthorized'
 *       "403":
 *         $ref: '#/components/responses/TradingPlanRequired'
 */
