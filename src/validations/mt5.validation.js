const Joi = require('joi');

const connectMT5 = {
  body: Joi.object().keys({
    accountId: Joi.string().required(),
    server: Joi.string().required(),
    password: Joi.string().required(),
  }),
};

const syncTrades = {
  body: Joi.object().keys({
    fromDate: Joi.date().optional(),
  }),
};

module.exports = {
  connectMT5,
  syncTrades,
};
