const httpStatus = require('http-status');
const ApiError = require('../utils/ApiError');
const { tradingPlanService } = require('../services');
const logger = require('../config/logger');

/**
 * Middleware to require user to have a trading plan
 * Should be used after auth() middleware
 */
const requireTradingPlan = async (req, res, next) => {
  try {
    if (!req.user || !req.user.id) {
      logger.warn('requireTradingPlan: No user found in request');
      return next(new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate'));
    }

    logger.info('Checking trading plan for user: %s', req.user.id);
    const tradingPlan = await tradingPlanService.getTradingPlanByUserId(req.user.id);

    if (!tradingPlan) {
      logger.warn('User %s attempted to access protected route without trading plan', req.user.id);
      return next(
        new ApiError(
          httpStatus.FORBIDDEN,
          'Trading plan required. Please create a trading plan before accessing this resource.',
          { reason: 'TRADING_PLAN_REQUIRED' }
        )
      );
    }

    logger.info('Trading plan found for user: %s', req.user.id);
    req.tradingPlan = tradingPlan;
    return next();
  } catch (error) {
    logger.error('Error checking trading plan: %s', error.message);
    return next(error);
  }
};

module.exports = requireTradingPlan;
