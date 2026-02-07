const httpStatus = require('http-status');

const ApiError = require('../utils/ApiError');
const logger = require('../config/logger');
const { TradingPlan } = require('../models');

/**
 * Create or update trading plan for user
 * @param {ObjectId} userId
 * @param {Object} tradingPlanBody
 * @returns {Promise<TradingPlan>}
 */
const createOrUpdateTradingPlan = async (userId, tradingPlanBody) => {
  logger.info('Service: Creating/updating trading plan for user: %s', userId);
  logger.info('Service: Trading plan data: %j', tradingPlanBody);

  // Check if trading plan already exists for this user
  const tradingPlan = await TradingPlan.findOne({ userId });

  if (tradingPlan) {
    logger.info('Service: Updating existing trading plan: %s', tradingPlan.id);
    Object.assign(tradingPlan, tradingPlanBody);
    await tradingPlan.save();
    return tradingPlan;
  }
  logger.info('Service: Creating new trading plan');
  const newTradingPlan = new TradingPlan({
    userId,
    ...tradingPlanBody,
  });
  await newTradingPlan.save();
  return newTradingPlan;
};

/**
 * Get trading plan by user id
 * @param {ObjectId} userId
 * @returns {Promise<TradingPlan>}
 */
const getTradingPlanByUserId = async (userId) => {
  logger.info('Service: Getting trading plan for user: %s', userId);
  const tradingPlan = await TradingPlan.findOne({ userId });
  logger.info('Service: Trading plan found: %s', !!tradingPlan);
  return tradingPlan;
};

/**
 * Delete trading plan by user id
 * @param {ObjectId} userId
 * @returns {Promise<void>}
 */
const deleteTradingPlanByUserId = async (userId) => {
  logger.info('Service: Deleting trading plan for user: %s', userId);
  const tradingPlan = await TradingPlan.findOne({ userId });
  if (!tradingPlan) {
    logger.info('Service: No trading plan found to delete for user: %s', userId);
    throw new ApiError(httpStatus.NOT_FOUND, 'Trading plan not found');
  }
  logger.info('Service: Deleting trading plan: %s', tradingPlan.id);
  await tradingPlan.remove();
};

module.exports = {
  createOrUpdateTradingPlan,
  getTradingPlanByUserId,
  deleteTradingPlanByUserId,
};
