const Joi = require('joi');

const createTrade = {
  body: Joi.object().keys({
    entryTime: Joi.date().required(),
    exitTime: Joi.date().required(),
    riskPercentUsed: Joi.number().min(0).allow(null).optional(),
    profitLoss: Joi.number().required(),
    riskRewardAchieved: Joi.number().allow(null).optional(),
    session: Joi.string().valid('LONDON', 'NY', 'ASIA').required(),
    stopLossHit: Joi.boolean().required(),
    exitedEarly: Joi.boolean().required(),
    targetPercentAchieved: Joi.number().allow(null).optional(),
    notes: Joi.string().allow('').optional(),
    mt5DealId: Joi.number().allow(null).optional(),
    mt5Symbol: Joi.string().allow('').allow(null).optional(),
  }),
};

const createBulkTrades = {
  body: Joi.object().keys({
    trades: Joi.array()
      .items(
        Joi.object().keys({
          entryTime: Joi.date().required(),
          exitTime: Joi.date().required(),
          riskPercentUsed: Joi.number().min(0).allow(null).optional(),
          profitLoss: Joi.number().required(),
          riskRewardAchieved: Joi.number().allow(null).optional(),
          session: Joi.string().valid('LONDON', 'NY', 'ASIA').required(),
          stopLossHit: Joi.boolean().required(),
          exitedEarly: Joi.boolean().required(),
          targetPercentAchieved: Joi.number().allow(null).optional(),
          notes: Joi.string().allow('').optional(),
          mt5DealId: Joi.number().allow(null).optional(),
          mt5Symbol: Joi.string().allow('').allow(null).optional(),
        })
      )
      .min(1)
      .required(),
  }),
};

const getTrades = {
  query: Joi.object().keys({
    session: Joi.string().valid('LONDON', 'NY', 'ASIA'),
    entryTime: Joi.date(),
    exitTime: Joi.date(),
    stopLossHit: Joi.boolean(),
    exitedEarly: Joi.boolean(),
    sortBy: Joi.string(),
    limit: Joi.number().integer(),
    page: Joi.number().integer(),
  }),
};

const getTrade = {
  params: Joi.object().keys({
    tradeId: Joi.string().required(),
  }),
};

const updateTrade = {
  params: Joi.object().keys({
    tradeId: Joi.string().required(),
  }),
  body: Joi.object()
    .keys({
      entryTime: Joi.date(),
      exitTime: Joi.date(),
      riskPercentUsed: Joi.number().min(0).allow(null),
      profitLoss: Joi.number(),
      riskRewardAchieved: Joi.number().allow(null),
      session: Joi.string().valid('LONDON', 'NY', 'ASIA'),
      stopLossHit: Joi.boolean(),
      exitedEarly: Joi.boolean(),
      targetPercentAchieved: Joi.number().allow(null),
      notes: Joi.string().allow(''),
      mt5DealId: Joi.number().allow(null),
      mt5Symbol: Joi.string().allow('').allow(null),
    })
    .min(1),
};

const deleteTrade = {
  params: Joi.object().keys({
    tradeId: Joi.string().required(),
  }),
};

const deleteBulkTrades = {
  body: Joi.object().keys({
    tradeIds: Joi.array().items(Joi.string().required()).min(1).required(),
  }),
};

module.exports = {
  createTrade,
  createBulkTrades,
  getTrades,
  getTrade,
  updateTrade,
  deleteTrade,
  deleteBulkTrades,
};
