const httpStatus = require('http-status');
const pick = require('../utils/pick');
const ApiError = require('../utils/ApiError');
const catchAsync = require('../utils/catchAsync');
const { tradeService } = require('../services');
const logger = require('../config/logger');

const createTrade = catchAsync(async (req, res) => {
  logger.info('Creating trade for user: %s', req.user.id);
  const trade = await tradeService.createTrade(req.user.id, req.body);
  logger.info('Trade created successfully: %s', trade.id);
  res.status(httpStatus.CREATED).send(trade);
});

const createBulkTrades = catchAsync(async (req, res) => {
  logger.info('Creating bulk trades for user: %s', req.user.id);
  const { trades } = req.body;
  const result = await tradeService.createBulkTrades(req.user.id, trades);
  logger.info('Bulk trades created successfully: %d', result.length);
  res.status(httpStatus.CREATED).send({ trades: result, count: result.length });
});

const getTrades = catchAsync(async (req, res) => {
  logger.info('Getting trades for user: %s', req.user.id);
  const filter = pick(req.query, ['session', 'entryTime', 'exitTime', 'stopLossHit', 'exitedEarly']);
  const options = pick(req.query, ['sortBy', 'limit', 'page']);

  // Add user filter to ensure users only see their own trades
  filter.userId = req.user.id;

  const result = await tradeService.queryTrades(filter, options);
  logger.info('Trades retrieved successfully: %d', result.results.length);
  res.send(result);
});

const getTrade = catchAsync(async (req, res) => {
  logger.info('Getting trade: %s for user: %s', req.params.tradeId, req.user.id);
  const trade = await tradeService.getTradeById(req.params.tradeId, req.user.id);
  if (!trade) {
    logger.info('Trade not found: %s', req.params.tradeId);
    throw new ApiError(httpStatus.NOT_FOUND, 'Trade not found');
  }
  logger.info('Trade retrieved successfully: %s', trade.id);
  res.send(trade);
});

const updateTrade = catchAsync(async (req, res) => {
  logger.info('Updating trade: %s for user: %s', req.params.tradeId, req.user.id);
  const trade = await tradeService.updateTradeById(req.params.tradeId, req.user.id, req.body);
  logger.info('Trade updated successfully: %s', trade.id);
  res.send(trade);
});

const deleteTrade = catchAsync(async (req, res) => {
  logger.info('Deleting trade: %s for user: %s', req.params.tradeId, req.user.id);
  await tradeService.deleteTradeById(req.params.tradeId, req.user.id);
  logger.info('Trade deleted successfully: %s', req.params.tradeId);
  res.status(httpStatus.NO_CONTENT).send();
});

const deleteBulkTrades = catchAsync(async (req, res) => {
  logger.info('Deleting bulk trades for user: %s', req.user.id);
  const { tradeIds } = req.body;
  await tradeService.deleteBulkTrades(req.user.id, tradeIds);
  logger.info('Bulk trades deleted successfully: %d', tradeIds.length);
  res.status(httpStatus.NO_CONTENT).send();
});

module.exports = {
  createTrade,
  createBulkTrades,
  getTrades,
  getTrade,
  updateTrade,
  deleteTrade,
  deleteBulkTrades,
};
