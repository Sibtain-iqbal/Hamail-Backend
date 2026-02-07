const logger = require('../config/logger');
const getDateRange = require('../utils/dateRange');
const { Trade, TradingPlan } = require('../models');
const { TradingSessions } = require('../models/enums');
const {
  analyzePsychologicalState,
  analyzeSessionForecast,
  analyzePerformanceInsights,
  analyzeStateHistory,
} = require('./analysis');

/**
 * Get current psychological state
 * @param {ObjectId} userId
 * @returns {Promise<Object>}
 */
const getCurrentState = async (userId) => {
  logger.info('Service: Getting current psychological state for user: %s', userId);

  const [plan, recentTrades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    Trade.find({ userId }).sort({ entryTime: -1 }).limit(10).lean(),
  ]);

  logger.info('Service: Found plan: %s Recent trades: %d', !!plan, recentTrades.length);

  const state = analyzePsychologicalState(recentTrades, plan);

  logger.info('Service: Calculated psychological state: %s', state.state);
  return state;
};

/**
 * Get session forecast
 * @param {ObjectId} userId
 * @param {string} session
 * @returns {Promise<Object>}
 */
const getSessionForecast = async (userId, session = TradingSessions.LONDON) => {
  logger.info('Service: Getting session forecast for user: %s Session: %s', userId, session);

  const [plan, currentState] = await Promise.all([TradingPlan.findOne({ userId }).lean(), getCurrentState(userId)]);

  const sessionTrades = await Trade.find({
    userId,
    session: (session || TradingSessions.LONDON).toUpperCase(),
  })
    .sort({ entryTime: -1 })
    .limit(20)
    .lean();

  logger.info('Service: Found session trades for forecast: %d', sessionTrades.length);

  const forecast = analyzeSessionForecast(sessionTrades, session, plan, currentState);

  logger.info('Service: Calculated session forecast: %s', forecast.forecast);
  return forecast;
};

/**
 * Get performance insights
 * @param {ObjectId} userId
 * @param {string} period
 * @returns {Promise<Object>}
 */
const getPerformanceInsights = async (userId, period = 'MONTH') => {
  logger.info('Service: Getting performance insights for user: %s Period: %s', userId, period);

  const dateRange = getDateRange(period);

  const [plan, periodTrades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    Trade.find({
      userId,
      entryTime: { $gte: dateRange.start, $lte: dateRange.end },
    })
      .sort({ entryTime: -1 })
      .lean(),
  ]);

  logger.info('Service: Found period trades for insights: %d Plan exists: %s', periodTrades.length, !!plan);

  const insights = analyzePerformanceInsights(periodTrades, plan, period);

  logger.info('Service: Generated insights count: %d', insights.insights.length);
  return insights;
};

/**
 * Get state history
 * @param {ObjectId} userId
 * @param {Object} filter
 * @returns {Promise<Object>}
 */
const getStateHistory = async (userId, filter = {}) => {
  logger.info('Service: Getting state history for user: %s Filter: %j', userId, filter);

  const { startDate, endDate, limit = 50 } = filter;

  const dateFilter = {};
  if (startDate) dateFilter.$gte = new Date(startDate);
  if (endDate) dateFilter.$lte = new Date(endDate);

  const query = { userId };
  if (Object.keys(dateFilter).length > 0) {
    query.entryTime = dateFilter;
  }

  const [plan, trades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    Trade.find(query)
      .sort({ entryTime: -1 })
      .limit(limit * 2)
      .lean(),
  ]);

  logger.info('Service: Found trades for history analysis: %d Plan exists: %s', trades.length, !!plan);

  const history = analyzeStateHistory(trades, plan, limit);

  logger.info('Service: Generated history records: %d', history.history.length);
  return history;
};

module.exports = {
  getCurrentState,
  getSessionForecast,
  getPerformanceInsights,
  getStateHistory,
};
