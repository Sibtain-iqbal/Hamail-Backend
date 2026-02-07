const httpStatus = require('http-status');

const ApiError = require('../utils/ApiError');
const logger = require('../config/logger');
const { Trade, TradingPlan, BehaviorHeatmapHistory, StabilityTrendHistory } = require('../models');
const { behaviorHeatmap, consistencyTrend } = require('./zentra');

/**
 * Create a trade
 * @param {ObjectId} userId
 * @param {Object} tradeBody
 * @returns {Promise<Trade>}
 */
const createTrade = async (userId, tradeBody) => {
  logger.info('Service: Creating trade for user: %s', userId);
  logger.info('Service: Trade data: %j', tradeBody);

  const trade = new Trade({
    userId,
    ...tradeBody,
    // Default to manual source if not specified
    source: tradeBody.source || { type: 'manual' },
  });
  await trade.save();

  // Recalculate history for the trade's date
  await recalculateHistoryForDate(userId, trade.entryTime);

  return trade;
};

/**
 * Get start of a specific date (midnight)
 */
const getStartOfDate = (dateInput) => {
  const date = new Date(dateInput);
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
};

/**
 * Get end of a specific date (23:59:59.999)
 */
const getEndOfDate = (dateInput) => {
  const date = new Date(dateInput);
  return new Date(date.getFullYear(), date.getMonth(), date.getDate(), 23, 59, 59, 999);
};

/**
 * Get trades for a specific date
 */
const getTradesForDate = async (userId, targetDate) => {
  const startOfDay = getStartOfDate(targetDate);
  const endOfDay = getEndOfDate(targetDate);
  return Trade.find({
    userId,
    entryTime: { $gte: startOfDay, $lte: endOfDay },
  })
    .sort({ entryTime: -1 })
    .lean();
};

/**
 * Recalculate and store heatmap + stability history for a specific date
 * @param {ObjectId} userId
 * @param {Date|string} targetDate - The date to recalculate
 */
const recalculateHistoryForDate = async (userId, targetDate) => {
  logger.info('[TradeService] Recalculating history for user: %s date: %s', userId, targetDate);

  const [plan, dayTrades] = await Promise.all([
    TradingPlan.findOne({ userId }).lean(),
    getTradesForDate(userId, targetDate),
  ]);

  if (dayTrades.length === 0) {
    // No trades for this day - remove history records if they exist
    const dayDate = getStartOfDate(targetDate);
    await Promise.all([
      BehaviorHeatmapHistory.deleteMany({ userId, date: dayDate }),
      StabilityTrendHistory.deleteMany({ userId, date: dayDate }),
    ]);
    logger.info('[TradeService] No trades for date, removed history records');
    return;
  }

  const dayDate = getStartOfDate(targetDate);

  // Calculate heatmap
  const heatmapResult = behaviorHeatmap.calculateBehaviorHeatmapWithInsight(dayTrades, plan);
  await BehaviorHeatmapHistory.updateOne(
    { userId, date: dayDate },
    {
      userId,
      date: dayDate,
      windows: heatmapResult.windows,
      insight: heatmapResult.insight,
      totalTrades: heatmapResult.totalTrades,
    },
    { upsert: true }
  );

  // Calculate stability
  const stabilityScore = consistencyTrend.calculateDailyScore(dayTrades, plan);
  if (stabilityScore) {
    await StabilityTrendHistory.updateOne(
      { userId, date: dayDate },
      {
        userId,
        date: dayDate,
        score: stabilityScore.score,
        metrics: stabilityScore.metrics,
        tradeCount: stabilityScore.tradeCount,
      },
      { upsert: true }
    );
  } else {
    // No valid stability score - remove if exists
    await StabilityTrendHistory.deleteMany({ userId, date: dayDate });
  }

  logger.info('[TradeService] Recalculated history for date: %s trades: %d', targetDate, dayTrades.length);
};

/**
 * Analyze imported trades and store heatmap + stability history for each day
 * @param {ObjectId} userId
 * @param {Array} trades - The imported trades
 */
const analyzeImportedTrades = async (userId, trades) => {
  if (!trades || trades.length === 0) return;

  logger.info('[TradeService] Analyzing %d imported trades for user: %s', trades.length, userId);

  // Get trading plan
  const plan = await TradingPlan.findOne({ userId }).lean();

  // Group trades by day
  const tradesByDay = {};
  trades.forEach((trade) => {
    const entryTime = trade.entryTime || trade.entryTime;
    const dayKey = new Date(entryTime).toISOString().split('T')[0];
    if (!tradesByDay[dayKey]) {
      tradesByDay[dayKey] = [];
    }
    tradesByDay[dayKey].push(trade);
  });

  const days = Object.keys(tradesByDay).sort();
  logger.info('[TradeService] Processing %d days with trades', days.length);

  // Prepare bulk operations
  const heatmapOps = [];
  const stabilityOps = [];

  days.forEach((dayKey) => {
    const dayTrades = tradesByDay[dayKey];
    const dayDate = new Date(dayKey);

    // Calculate heatmap
    const heatmapResult = behaviorHeatmap.calculateBehaviorHeatmapWithInsight(dayTrades, plan);
    heatmapOps.push({
      updateOne: {
        filter: { userId, date: dayDate },
        update: {
          userId,
          date: dayDate,
          windows: heatmapResult.windows,
          insight: heatmapResult.insight,
          totalTrades: heatmapResult.totalTrades,
        },
        upsert: true,
      },
    });

    // Calculate stability
    const stabilityScore = consistencyTrend.calculateDailyScore(dayTrades, plan);
    if (stabilityScore) {
      stabilityOps.push({
        updateOne: {
          filter: { userId, date: dayDate },
          update: {
            userId,
            date: dayDate,
            score: stabilityScore.score,
            metrics: stabilityScore.metrics,
            tradeCount: stabilityScore.tradeCount,
          },
          upsert: true,
        },
      });
    }
  });

  // Execute bulk writes
  if (heatmapOps.length > 0) {
    await BehaviorHeatmapHistory.bulkWrite(heatmapOps);
    logger.info('[TradeService] Stored %d heatmap records', heatmapOps.length);
  }
  if (stabilityOps.length > 0) {
    await StabilityTrendHistory.bulkWrite(stabilityOps);
    logger.info('[TradeService] Stored %d stability records', stabilityOps.length);
  }
};

/**
 * Create multiple trades
 * @param {ObjectId} userId
 * @param {Array} tradesData
 * @returns {Promise<Array<Trade>>}
 */
const createBulkTrades = async (userId, tradesData) => {
  logger.info('Service: Creating bulk trades for user: %s', userId);
  logger.info('Service: Number of trades: %d', tradesData.length);

  const trades = tradesData.map((tradeData) => ({
    userId,
    ...tradeData,
    // Default to manual source if not specified (MT5 sync passes source explicitly)
    source: tradeData.source || { type: 'manual' },
  }));

  const result = await Trade.insertMany(trades);
  logger.info('Service: Bulk trades created successfully: %d', result.length);

  // Analyze imported trades and store heatmap + stability history
  await analyzeImportedTrades(userId, result);

  return result;
};

/**
 * Query for trades
 * @param {Object} filter - Mongo filter
 * @param {Object} options - Query options
 * @param {string} [options.sortBy] - Sort option in the format: sortField:(desc|asc)
 * @param {number} [options.limit] - Maximum number of results per page (default = 10)
 * @param {number} [options.page] - Current page (default = 1)
 * @returns {Promise<QueryResult>}
 */
const queryTrades = async (filter, options) => {
  logger.info('Service: Querying trades with filter: %j', filter);
  logger.info('Service: Query options: %j', options);

  const trades = await Trade.paginate(filter, options);
  logger.info('Service: Trades found: %d', trades.results.length);
  return trades;
};

/**
 * Get trade by id
 * @param {ObjectId} tradeId
 * @param {ObjectId} userId
 * @returns {Promise<Trade>}
 */
const getTradeById = async (tradeId, userId) => {
  logger.info('Service: Getting trade by id: %s for user: %s', tradeId, userId);
  const trade = await Trade.findOne({ _id: tradeId, userId });
  logger.info('Service: Trade found: %s', !!trade);
  return trade;
};

/**
 * Update trade by id
 * @param {ObjectId} tradeId
 * @param {ObjectId} userId
 * @param {Object} updateBody
 * @returns {Promise<Trade>}
 */
const updateTradeById = async (tradeId, userId, updateBody) => {
  logger.info('Service: Updating trade: %s for user: %s', tradeId, userId);
  logger.info('Service: Update data: %j', updateBody);

  const trade = await getTradeById(tradeId, userId);
  if (!trade) {
    logger.info('Service: Trade not found for update: %s', tradeId);
    throw new ApiError(httpStatus.NOT_FOUND, 'Trade not found');
  }

  // Store old entryTime to check if date changed
  const oldEntryTime = trade.entryTime;

  Object.assign(trade, updateBody);
  await trade.save();

  // Recalculate history for affected dates
  const newEntryTime = trade.entryTime;
  const datesToRecalculate = new Set();

  // Always recalculate the new date
  datesToRecalculate.add(newEntryTime);

  // If entryTime changed, also recalculate the old date
  if (oldEntryTime && oldEntryTime.getTime() !== newEntryTime.getTime()) {
    datesToRecalculate.add(oldEntryTime);
    logger.info('Service: Entry time changed, recalculating both old and new dates');
  }

  // Recalculate history for all affected dates
  await Promise.all(Array.from(datesToRecalculate).map((date) => recalculateHistoryForDate(userId, date)));

  logger.info('Service: Trade updated successfully: %s', trade.id);
  return trade;
};

/**
 * Delete trade by id
 * @param {ObjectId} tradeId
 * @param {ObjectId} userId
 * @returns {Promise<void>}
 */
const deleteTradeById = async (tradeId, userId) => {
  logger.info('Service: Deleting trade: %s for user: %s', tradeId, userId);

  const trade = await getTradeById(tradeId, userId);
  if (!trade) {
    logger.info('Service: Trade not found for deletion: %s', tradeId);
    throw new ApiError(httpStatus.NOT_FOUND, 'Trade not found');
  }

  // Store entryTime before deletion
  const { entryTime } = trade;

  logger.info('Service: Deleting trade: %s', trade.id);
  await trade.remove();

  // Recalculate history for the deleted trade's date
  await recalculateHistoryForDate(userId, entryTime);
};

/**
 * Delete multiple trades
 * @param {ObjectId} userId
 * @param {Array<ObjectId>} tradeIds
 * @returns {Promise<void>}
 */
const deleteBulkTrades = async (userId, tradeIds) => {
  logger.info('Service: Deleting %d trades for user: %s', tradeIds.length, userId);
  const result = await Trade.deleteMany({ _id: { $in: tradeIds }, userId });
  logger.info('Service: Deleted %d trades', result.deletedCount);
};

module.exports = {
  createTrade,
  createBulkTrades,
  queryTrades,
  getTradeById,
  updateTradeById,
  deleteTradeById,
  deleteBulkTrades,
};
