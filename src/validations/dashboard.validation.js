const Joi = require('joi');

const getDashboard = {
  query: Joi.object().keys({
    period: Joi.string().valid('WEEK', 'MONTH', 'QUARTER', 'YEAR').default('MONTH'),
  }),
};

const getSummary = {
  query: Joi.object().keys({
    period: Joi.string().valid('WEEK', 'MONTH', 'QUARTER', 'YEAR').default('MONTH'),
  }),
};

module.exports = {
  getDashboard,
  getSummary,
};
