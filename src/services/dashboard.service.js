const { Trade } = require('../models');
const { analysisService } = require('./index');
const logger = require('../config/logger');
const {
  calculateSummaryStats,
  calculateDailyPnL,
  calculateSessionPerformance,
  calculateRiskMetrics,
  calculateTrends,
  generateAlerts,
} = require('./dashboard');

/**
 * Get complete dashboard data
 * @param {ObjectId} userId
 * @param {string} period
 * @returns {Promise<Object>}
 */
const getCompleteDashboard = async (userId, period = 'MONTH') => {
  logger.info('Service: Getting complete dashboard for user: %s Period: %s', userId, period);

  // Get the last 10 trades (same as used in analysis) - no period filter for consistency
  const last10Trades = await Trade.find({ userId }).sort({ entryTime: -1 }).limit(10).lean();

  logger.info('Service: Found last 10 trades for dashboard state: %d', last10Trades.length);

  // Get psychological state (uses same 10 trades internally)
  const psychologicalState = await analysisService.getCurrentState(userId);

  // Get performance insights (uses period-based trades)
  const insights = await analysisService.getPerformanceInsights(userId, period);

  // Calculate metrics using the same 10 trades used for psychological state analysis
  const summary = calculateSummaryStats(last10Trades);
  const dailyPnL = calculateDailyPnL(last10Trades);
  const sessionPerformance = calculateSessionPerformance(last10Trades);
  const riskMetrics = calculateRiskMetrics(last10Trades);

  logger.info('Service: Calculated dashboard metrics using last 10 trades');

  // Get recent trades (last 10)
  const recentTrades = last10Trades.map((trade) => ({
    id: trade._id,
    entryTime: trade.entryTime,
    exitTime: trade.exitTime,
    profitLoss: trade.profitLoss,
    session: trade.session,
    riskPercentUsed: trade.riskPercentUsed,
    riskRewardAchieved: trade.riskRewardAchieved,
  }));

  const dashboard = {
    period,
    summary,
    psychologicalState,
    performance: {
      dailyPnL,
      sessionPerformance,
      riskMetrics,
    },
    insights: insights.insights,
    recentTrades,
  };

  logger.info('Service: Dashboard data compiled successfully');
  return dashboard;
};

/**
 * Get dashboard summary
 * @param {ObjectId} userId
 * @param {string} period
 * @returns {Promise<Object>}
 */
const getDashboardSummary = async (userId, period = 'MONTH') => {
  logger.info('Service: Getting dashboard summary for user: %s Period: %s', userId, period);

  // Get the last 10 trades (same as used in analysis) - no period filter for consistency
  const last10Trades = await Trade.find({ userId }).sort({ entryTime: -1 }).limit(10).lean();

  logger.info('Service: Found last 10 trades for summary: %d', last10Trades.length);

  // Get psychological state (uses same 10 trades internally)
  const psychologicalState = await analysisService.getCurrentState(userId);

  // Calculate quick stats using the same 10 trades used for psychological state analysis
  const summaryStats = calculateSummaryStats(last10Trades);
  logger.info('Service: Summary stats (using last 10 trades): %j', summaryStats);
  const quickStats = {
    totalTrades: summaryStats.totalTrades,
    winRate: summaryStats.winRate,
    totalPnL: summaryStats.totalProfitLoss,
    avgRiskReward: summaryStats.averageRiskReward,
    currentState: psychologicalState.state,
    confidence: psychologicalState.confidence,
  };

  // Calculate trends using the same 10 trades
  const trends = calculateTrends(last10Trades);

  // Generate alerts using the same 10 trades
  const alerts = generateAlerts(last10Trades, psychologicalState);

  const summary = {
    period,
    quickStats,
    trends,
    alerts,
  };

  logger.info('Service: Dashboard summary compiled successfully');
  return summary;
};

module.exports = {
  getCompleteDashboard,
  getDashboardSummary,
};
