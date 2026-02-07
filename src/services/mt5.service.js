const axios = require('axios');
const httpStatus = require('http-status');
const ApiError = require('../utils/ApiError');
const logger = require('../config/logger');
const config = require('../config/config');

/**
 * Connect to MT5 account via Python service
 * @param {string} accountId
 * @param {string} server
 * @param {string} password
 * @param {boolean} manualLogin - If true, sends manualLogin: true (required for first-time connections)
 * @returns {Promise<Object>}
 */
const connectMT5Account = async (accountId, server, password, manualLogin = false) => {
  logger.info(
    'Connecting to MT5 account via Python service: %s on server: %s, manualLogin: %s',
    accountId,
    server,
    manualLogin
  );

  try {
    const requestBody = {
      accountId: parseInt(accountId, 10),
      server,
      password,
    };

    // Include manualLogin: true only for first-time connections
    if (manualLogin) {
      requestBody.manualLogin = true;
      logger.info('Including manualLogin: true for first-time MT5 connection');
    }

    const response = await axios.post(`${config.mt5.apiUrl}/connect`, requestBody, {
      headers: {
        'X-API-Key': config.mt5.apiKey,
        'Content-Type': 'application/json',
      },
      timeout: 30000, // 30 seconds timeout
    });

    if (!response.data.success) {
      logger.error('MT5 connection failed: %s', response.data.error);
      throw new ApiError(httpStatus.BAD_REQUEST, response.data.error || 'Failed to connect to MT5 account');
    }

    logger.info('MT5 account connected successfully: %s', accountId);
    return response.data;
  } catch (error) {
    logger.error('MT5 connection error: %s', error.message);
    if (error.response) {
      throw new ApiError(
        error.response.status || httpStatus.INTERNAL_SERVER_ERROR,
        error.response.data.error || 'Failed to connect to MT5 account'
      );
    }
    throw new ApiError(httpStatus.INTERNAL_SERVER_ERROR, error.message);
  }
};

/**
 * Fetch trades from MT5 account via Python service
 * @param {string} accountId
 * @param {string} server
 * @param {string} password
 * @param {Date} fromDate
 * @param {Date} toDate
 * @returns {Promise<Array>}
 */
const fetchMT5Trades = async (accountId, server, password, fromDate, toDate) => {
  logger.info('Fetching MT5 trades via Python service: %s from %s to %s', accountId, fromDate, toDate);

  try {
    const response = await axios.post(
      `${config.mt5.apiUrl}/trades`,
      {
        accountId: parseInt(accountId, 10),
        server,
        password,
        fromDate: fromDate.toISOString(),
        toDate: toDate.toISOString(),
      },
      {
        headers: {
          'X-API-Key': config.mt5.apiKey,
          'Content-Type': 'application/json',
        },
        timeout: 60000, // 60 seconds timeout for trade fetching
      }
    );

    if (!response.data.success) {
      logger.error('MT5 fetch trades failed: %s', response.data.error);
      throw new ApiError(httpStatus.BAD_REQUEST, response.data.error || 'Failed to fetch trades from MT5');
    }

    logger.info('Fetched %d trades from MT5', response.data.count || 0);
    return response.data.trades || [];
  } catch (error) {
    logger.error('MT5 fetch trades error: %s', error.message);
    if (error.response) {
      throw new ApiError(
        error.response.status || httpStatus.INTERNAL_SERVER_ERROR,
        error.response.data.error || 'Failed to fetch trades from MT5'
      );
    }
    throw new ApiError(httpStatus.INTERNAL_SERVER_ERROR, error.message);
  }
};

module.exports = {
  connectMT5Account,
  fetchMT5Trades,
};
