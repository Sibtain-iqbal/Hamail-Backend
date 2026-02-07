const Joi = require('joi');

const createTradingPlan = {
  body: Joi.object().keys({
    maxTradesPerDay: Joi.number().integer().min(0).required(),
    riskPercentPerTrade: Joi.number().min(0).max(100).required(),
    targetRiskRewardRatio: Joi.number().min(0).required(),
    preferredSessions: Joi.array().items(Joi.string().valid('LONDON', 'NY', 'ASIA')).required(),
    stopLossDiscipline: Joi.string().valid('ALWAYS', 'FLEXIBLE').required(),
  }),
};

const getTradingPlan = {};

const deleteTradingPlan = {};

const getTradingPlanStatus = {};

module.exports = {
  createTradingPlan,
  getTradingPlan,
  deleteTradingPlan,
  getTradingPlanStatus,
};
