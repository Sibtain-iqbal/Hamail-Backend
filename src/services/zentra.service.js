const logger = require('../config/logger');
const { Trade, TradingPlan, BehaviorHeatmapHistory, StabilityTrendHistory } = require('../models');
const {
  mentalBattery,
  planControl,
  behaviorHeatmap,
  psychologicalRadar,
  breathwork,
  performanceWindow,
  consistencyTrend,
  quotes,
} = require('./zentra');

/**
 * Get start of today (midnight)
 */
const getStartOfToday = () => {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate());
};

/**
 * Get trades for today
 */
const getTodayTrades = async (userId) => {
  const startOfToday = getStartOfToday();
  return Trade.find({
    userId,
    entryTime: { $gte: startOfToday },
  })
    .sort({ entryTime: -1 })
    .lean();
};

/**
 * Get recent trades (last N)
 */
const getRecentTrades = async (userId, limit = 5) => {
  return Trade.find({ userId }).sort({ entryTime: -1 }).limit(limit).lean();
};

/**
 * Get trades within date range
 */
const getTradesInRange = async (userId, startDate, endDate = new Date()) => {
  return Trade.find({
    userId,
    entryTime: { $gte: startDate, $lte: endDate },
  })
    .sort({ entryTime: -1 })
    .lean();
};

/**
 * Feature 1: Get Mental Battery
 */
const getMentalBattery = async (userId) => {
  logger.info('[ZentraService] getMentalBattery for user: %s', userId);

  const [plan, todayTrades, recentTrades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    getTodayTrades(userId),
    getRecentTrades(userId, 5),
  ]);

  // Calculate plan control for recharge bonus calculation
  const planControlResult = planControl.calculatePlanControl(recentTrades, plan);

  const result = mentalBattery.calculateMentalBattery(todayTrades, plan, planControlResult.percentage);

  logger.info('[ZentraService] Mental battery result: %d%% status: %s', result.battery, result.status);
  return result;
};

/**
 * Feature 2: Get Plan Control % with deviation attribution
 */
const getPlanControl = async (userId) => {
  logger.info('[ZentraService] getPlanControl for user: %s', userId);

  const [plan, todayTrades, recentTrades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    getTodayTrades(userId),
    getRecentTrades(userId, 5),
  ]);

  // Get mental battery level for attribution analysis
  const planControlBasic = planControl.calculatePlanControl(recentTrades, plan);
  const batteryResult = mentalBattery.calculateMentalBattery(todayTrades, plan, planControlBasic.percentage);

  // Use enhanced function with attribution
  const result = planControl.calculatePlanControlWithAttribution(recentTrades, plan, batteryResult.battery);

  logger.info(
    '[ZentraService] Plan control result: %d%% attribution: %s',
    result.percentage,
    result.deviationAttribution?.primaryCause || 'none'
  );
  return result;
};

/**
 * Feature 3: Get Behavior Heatmap with insight
 * Returns current aggregated heatmap (last 30 days). Historical data is auto-analyzed on import.
 */
const getBehaviorHeatmap = async (userId) => {
  logger.info('[ZentraService] getBehaviorHeatmap for user: %s', userId);

  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const [plan, trades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    getTradesInRange(userId, thirtyDaysAgo),
  ]);

  const result = behaviorHeatmap.calculateBehaviorHeatmapWithInsight(trades, plan);

  logger.info(
    '[ZentraService] Behavior heatmap generated with %d trades, insight: %s',
    result.totalTrades,
    result.insight?.type || 'none'
  );

  // Persist today's snapshot
  const today = getStartOfToday();
  await BehaviorHeatmapHistory.updateOne(
    { userId, date: today },
    {
      userId,
      date: today,
      windows: result.windows,
      insight: result.insight,
      totalTrades: result.totalTrades,
    },
    { upsert: true }
  );

  return result;
};

/**
 * Feature 4: Get Psychological Radar
 */
const getPsychologicalRadar = async (userId) => {
  logger.info('[ZentraService] getPsychologicalRadar for user: %s', userId);

  const [plan, recentTrades] = await Promise.all([TradingPlan.findOne({ userId }).lean(), getRecentTrades(userId, 5)]);

  const result = psychologicalRadar.calculatePsychologicalRadar(recentTrades, plan);

  logger.info('[ZentraService] Psychological radar generated for %d trades', result.tradesAnalyzed);
  return result;
};

/**
 * Feature 5: Get Breathwork Suggestion
 */
const getBreathworkSuggestion = async (userId) => {
  logger.info('[ZentraService] getBreathworkSuggestion for user: %s', userId);

  const [plan, todayTrades, recentTrades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    getTodayTrades(userId),
    getRecentTrades(userId, 5),
  ]);

  // Get mental battery
  const planControlResult = planControl.calculatePlanControl(recentTrades, plan);
  const batteryResult = mentalBattery.calculateMentalBattery(todayTrades, plan, planControlResult.percentage);

  // Get radar for emotional volatility
  const radarResult = psychologicalRadar.calculatePsychologicalRadar(recentTrades, plan);

  const result = breathwork.shouldSuggestBreathwork({
    mentalBattery: batteryResult.battery,
    emotionalVolatility: radarResult.traits.emotionalVolatility,
    todayTrades,
    sessionStartBattery: 100, // Assuming session starts at 100
  });

  logger.info('[ZentraService] Breathwork suggestion: %s', result.shouldSuggest);
  return result;
};

/**
 * Feature 6: Get Performance Window
 */
const getPerformanceWindow = async (userId) => {
  logger.info('[ZentraService] getPerformanceWindow for user: %s', userId);

  const [plan, recentTrades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    getRecentTrades(userId, 10), // Get 10 to compare current 5 vs previous 5
  ]);

  const currentTrades = recentTrades.slice(0, 5);
  const previousTrades = recentTrades.slice(5, 10);

  // Calculate plan control for current and previous windows
  const currentPlanControl = planControl.calculatePlanControl(currentTrades, plan);
  const previousPlanControl = previousTrades.length > 0 ? planControl.calculatePlanControl(previousTrades, plan) : null;

  const result = performanceWindow.getPerformanceWindow(
    currentTrades,
    plan,
    currentPlanControl.percentage,
    previousPlanControl?.percentage
  );

  logger.info('[ZentraService] Performance window: %s improvements detected', result.hasImprovement);
  return result;
};

/**
 * Feature 7: Get Consistency Trend
 * Returns trend analysis. Historical data is auto-analyzed on import.
 */
const getConsistencyTrend = async (userId, daysOption = '7') => {
  logger.info('[ZentraService] getConsistencyTrend for user: %s days: %s', userId, daysOption);

  // Calculate date range based on option
  let startDate;
  if (daysOption === 'all') {
    startDate = new Date(0);
  } else {
    const days = parseInt(daysOption, 10);
    startDate = new Date();
    startDate.setDate(startDate.getDate() - days);
  }

  const [plan, trades, todayTrades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    getTradesInRange(userId, startDate),
    getTodayTrades(userId),
  ]);

  const result = consistencyTrend.calculateConsistencyTrend(trades, plan, daysOption);

  logger.info(
    '[ZentraService] Consistency trend: %d data points, direction: %s',
    result.trend.length,
    result.summary.trendDirection
  );

  // Persist today's stability score
  const today = getStartOfToday();
  const todayScore = consistencyTrend.calculateDailyScore(todayTrades, plan);
  if (todayScore) {
    await StabilityTrendHistory.updateOne(
      { userId, date: today },
      {
        userId,
        date: today,
        score: todayScore.score,
        metrics: todayScore.metrics,
        tradeCount: todayScore.tradeCount,
      },
      { upsert: true }
    );
  }

  return result;
};

/**
 * Get behavior heatmap history between dates (default last 30 days)
 * @param {ObjectId} userId
 * @param {Object} query
 * @returns {Promise<Object>}
 */
const getBehaviorHeatmapHistory = async (userId, query = {}) => {
  const { startDate, endDate } = query;
  const start = startDate !== undefined ? new Date(startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const end = endDate !== undefined ? new Date(endDate) : new Date();

  const history = await BehaviorHeatmapHistory.find({
    userId,
    date: { $gte: start, $lte: end },
  })
    .sort({ date: -1 })
    .lean();

  logger.info('[ZentraService] Heatmap history records: %d', history.length);
  return { history, count: history.length };
};

/**
 * Get stability (consistency) trend history between dates (default last 30 days)
 * @param {ObjectId} userId
 * @param {Object} query
 * @returns {Promise<Object>}
 */
const getStabilityHistory = async (userId, query = {}) => {
  const { startDate, endDate } = query;
  const start = startDate !== undefined ? new Date(startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const end = endDate !== undefined ? new Date(endDate) : new Date();

  const history = await StabilityTrendHistory.find({
    userId,
    date: { $gte: start, $lte: end },
  })
    .sort({ date: -1 })
    .lean();

  logger.info('[ZentraService] Stability history records: %d', history.length);
  return { history, count: history.length };
};

/**
 * Feature 8: Get Daily Quote
 */
const getDailyQuote = async (userId) => {
  logger.info('[ZentraService] getDailyQuote for user: %s', userId);

  const result = quotes.getDailyQuote(userId);

  logger.info('[ZentraService] Daily quote category: %s', result.category);
  return result;
};

module.exports = {
  getMentalBattery,
  getPlanControl,
  getBehaviorHeatmap,
  getPsychologicalRadar,
  getBreathworkSuggestion,
  getPerformanceWindow,
  getConsistencyTrend,
  getBehaviorHeatmapHistory,
  getStabilityHistory,
  getDailyQuote,
};
