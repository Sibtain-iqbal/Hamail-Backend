const Joi = require('joi');

const getState = {
  // No query parameters needed for getting current state
};

const getForecast = {
  query: Joi.object().keys({
    session: Joi.string().valid('LONDON', 'NY', 'ASIA').optional(),
  }),
};

const getInsights = {
  query: Joi.object().keys({
    period: Joi.string().valid('WEEK', 'MONTH', 'QUARTER', 'YEAR').default('MONTH'),
  }),
};

const getHistory = {
  query: Joi.object().keys({
    startDate: Joi.date().iso().optional(),
    endDate: Joi.date().iso().optional(),
    limit: Joi.number().integer().min(1).max(100).default(50),
  }),
};

module.exports = {
  getState,
  getForecast,
  getInsights,
  getHistory,
};
