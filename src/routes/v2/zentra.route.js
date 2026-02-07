const express = require('express');
const auth = require('../../middlewares/auth');
const validate = require('../../middlewares/validate');
const requireTradingPlan = require('../../middlewares/requireTradingPlan');
const zentraValidation = require('../../validations/zentra.validation');
const zentraController = require('../../controllers/zentra.controller');

const router = express.Router();

// Feature 1: Mental Battery
router
  .route('/mental-battery')
  .get(auth(), requireTradingPlan, validate(zentraValidation.getMentalBattery), zentraController.getMentalBattery);

// Feature 2: Plan Control %
router
  .route('/plan-control')
  .get(auth(), requireTradingPlan, validate(zentraValidation.getPlanControl), zentraController.getPlanControl);

// Feature 3: Behavior Heatmap
router
  .route('/behavior-heatmap')
  .get(auth(), requireTradingPlan, validate(zentraValidation.getBehaviorHeatmap), zentraController.getBehaviorHeatmap);

// Behavior Heatmap History
router
  .route('/behavior-heatmap/history')
  .get(auth(), requireTradingPlan, validate(zentraValidation.getHeatmapHistory), zentraController.getBehaviorHeatmapHistory);

// Feature 4: Psychological Radar
router
  .route('/psychological-radar')
  .get(auth(), requireTradingPlan, validate(zentraValidation.getPsychologicalRadar), zentraController.getPsychologicalRadar);

// Feature 5: Breathwork Suggestion
router
  .route('/breathwork-suggestion')
  .get(
    auth(),
    requireTradingPlan,
    validate(zentraValidation.getBreathworkSuggestion),
    zentraController.getBreathworkSuggestion
  );

// Feature 6: Performance Window
router
  .route('/performance-window')
  .get(auth(), requireTradingPlan, validate(zentraValidation.getPerformanceWindow), zentraController.getPerformanceWindow);

// Feature 7: Consistency Trend
router
  .route('/consistency-trend')
  .get(auth(), requireTradingPlan, validate(zentraValidation.getConsistencyTrend), zentraController.getConsistencyTrend);

// Consistency/Stability Trend History
router
  .route('/consistency-trend/history')
  .get(auth(), requireTradingPlan, validate(zentraValidation.getStabilityHistory), zentraController.getStabilityHistory);

// Feature 8: Daily Quote
router.route('/daily-quote').get(auth(), validate(zentraValidation.getDailyQuote), zentraController.getDailyQuote);

module.exports = router;

/**
 * @swagger
 * tags:
 *   name: Zentra V2
 *   description: Zentra V2 psychological trading analysis
 */

/**
 * @swagger
 * /v2/zentra/mental-battery:
 *   get:
 *     summary: Get mental battery status
 *     description: Get current mental battery level based on today's trading behavior.
 *     tags: [Zentra V2]
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
 *                 battery:
 *                   type: number
 *                   minimum: 0
 *                   maximum: 100
 *                 status:
 *                   type: string
 *                   enum: [optimal, strained, high_risk]
 *                 message:
 *                   type: string
 *                 drainFactors:
 *                   type: array
 *                   items:
 *                     type: object
 *                 rechargeFactors:
 *                   type: array
 *                   items:
 *                     type: object
 */

/**
 * @swagger
 * /v2/zentra/plan-control:
 *   get:
 *     summary: Get plan control percentage
 *     description: Get plan compliance score based on last 5 trades.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: OK
 */

/**
 * @swagger
 * /v2/zentra/behavior-heatmap:
 *   get:
 *     summary: Get behavior heatmap
 *     description: Get behavior scores per time window (last 30 days). Historical data is auto-analyzed on import.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: OK
 */

/**
 * @swagger
 * /v2/zentra/behavior-heatmap/history:
 *   get:
 *     summary: Get behavior heatmap history
 *     description: Get stored behavior heatmap snapshots for a date range.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: Start date (default last 30 days)
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: End date (default today)
 *     responses:
 *       "200":
 *         description: OK
 */

/**
 * @swagger
 * /v2/zentra/psychological-radar:
 *   get:
 *     summary: Get psychological radar data
 *     description: Get 6-trait psychological distribution.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: OK
 */

/**
 * @swagger
 * /v2/zentra/breathwork-suggestion:
 *   get:
 *     summary: Get breathwork suggestion
 *     description: Check if breathwork should be suggested based on current state.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: OK
 */

/**
 * @swagger
 * /v2/zentra/performance-window:
 *   get:
 *     summary: Get performance window
 *     description: Get improvement message based on last 5 trades.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: OK
 */

/**
 * @swagger
 * /v2/zentra/consistency-trend:
 *   get:
 *     summary: Get consistency trend
 *     description: Get daily psychological scores over time. Historical data is auto-analyzed on import.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: days
 *         schema:
 *           type: string
 *           enum: ['7', '10', '20', 'all']
 *         default: '7'
 *     responses:
 *       "200":
 *         description: OK
 */

/**
 * @swagger
 * /v2/zentra/consistency-trend/history:
 *   get:
 *     summary: Get stability/consistency trend history
 *     description: Get stored daily stability scores for a date range.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: Start date (default last 30 days)
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: End date (default today)
 *     responses:
 *       "200":
 *         description: OK
 */

/**
 * @swagger
 * /v2/zentra/daily-quote:
 *   get:
 *     summary: Get daily quote
 *     description: Get deterministic daily motivational quote.
 *     tags: [Zentra V2]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       "200":
 *         description: OK
 */
