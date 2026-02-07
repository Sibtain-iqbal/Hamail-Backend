const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const ApiError = require('../utils/ApiError');
const { mt5Service, userService, tradeService } = require('../services');
const { Trade, BehaviorHeatmapHistory, StabilityTrendHistory } = require('../models');
const logger = require('../config/logger');

/**
 * Connect user's MT5 account
 */
const connectMT5 = catchAsync(async (req, res) => {
  logger.info('Connecting MT5 account for user: %s', req.user.id);
  const { accountId, server, password } = req.body;

  const user = await userService.getUserById(req.user.id);

  // Block if already connected to a different account
  if (user.mt5Account && user.mt5Account.isConnected && user.mt5Account.accountId !== accountId) {
    logger.info(
      'User %s already has MT5 account %s connected, blocking new connection to %s',
      req.user.id,
      user.mt5Account.accountId,
      accountId
    );
    throw new ApiError(
      httpStatus.CONFLICT,
      'MT5 account already connected. Disconnect current account before connecting a new one.'
    );
  }

  // Check if this is first time connection (same account reconnect or new connection)
  const isFirstTime = !user.mt5Account || !user.mt5Account.isConnected || !user.mt5Account.accountId;

  logger.info('MT5 connection for user %s - isFirstTime: %s', req.user.id, isFirstTime);

  // Connect via Python service
  const connectionResult = await mt5Service.connectMT5Account(accountId, server, password, isFirstTime);

  // Update user with MT5 credentials
  await userService.updateUserById(req.user.id, {
    mt5Account: {
      accountId,
      server,
      password,
      isConnected: true,
    },
  });

  logger.info('MT5 account connected and saved for user: %s', req.user.id);
  res.status(httpStatus.OK).send({
    success: true,
    accountId: connectionResult.accountId,
    server: connectionResult.server,
    balance: connectionResult.balance,
    equity: connectionResult.equity,
    margin: connectionResult.margin,
    currency: connectionResult.currency,
  });
});

/**
 * Sync trades from MT5 account
 */
const syncTrades = catchAsync(async (req, res) => {
  logger.info('Syncing MT5 trades for user: %s', req.user.id);
  const user = await userService.getUserById(req.user.id);

  if (!user.mt5Account || !user.mt5Account.isConnected) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'MT5 account not connected');
  }

  const { fromDate } = req.body;
  const from = user.mt5Account.lastSyncAt
    ? new Date(user.mt5Account.lastSyncAt)
    : new Date(fromDate || Date.now() - 30 * 24 * 60 * 60 * 1000); // Default to 30 days ago
  const to = new Date(Date.now()); // Always use current time as toDate
  logger.info('Syncing trades from %s to %s (current time)', from.toISOString(), to.toISOString());

  // Get decrypted MT5 password
  const decryptedPassword = user.getMT5Password();
  if (!decryptedPassword) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'MT5 password not found');
  }

  // Fetch trades from Python service
  const mt5Trades = await mt5Service.fetchMT5Trades(
    user.mt5Account.accountId,
    user.mt5Account.server,
    decryptedPassword,
    from,
    to
  );

  logger.info('Fetched %d trades from MT5, importing to database', mt5Trades.length);

  // Transform and save trades with source tagging
  const transformedTrades = mt5Trades.map((trade) => ({
    entryTime: new Date(trade.entryTime),
    exitTime: new Date(trade.exitTime),
    riskPercentUsed: trade.riskPercentUsed,
    profitLoss: trade.profitLoss,
    riskRewardAchieved: trade.riskRewardAchieved,
    session: trade.session,
    stopLossHit: trade.stopLossHit,
    exitedEarly: trade.exitedEarly,
    targetPercentAchieved: trade.targetPercentAchieved,
    notes: trade.notes,
    mt5DealId: trade.mt5DealId,
    mt5Symbol: trade.mt5Symbol,
    source: {
      type: 'mt5',
      mt5AccountId: user.mt5Account.accountId,
    },
  }));

  // Use bulk create
  const savedTrades = await tradeService.createBulkTrades(req.user.id, transformedTrades);

  // Update last sync time
  await userService.updateUserById(req.user.id, {
    'mt5Account.lastSyncAt': new Date(),
  });

  logger.info('Successfully synced %d trades for user: %s', savedTrades.length, req.user.id);
  res.status(httpStatus.OK).send({
    success: true,
    trades: savedTrades,
    count: savedTrades.length,
    syncedAt: new Date(),
  });
});

/**
 * Get MT5 connection status
 */
const getConnectionStatus = catchAsync(async (req, res) => {
  logger.info('Getting MT5 connection status for user: %s', req.user.id);
  const user = await userService.getUserById(req.user.id);

  if (!user.mt5Account || !user.mt5Account.isConnected) {
    return res.status(httpStatus.OK).send({
      connected: false,
      message: 'MT5 account not connected',
    });
  }

  res.status(httpStatus.OK).send({
    connected: true,
    accountId: user.mt5Account.accountId,
    server: user.mt5Account.server,
    lastSyncAt: user.mt5Account.lastSyncAt,
  });
});

/**
 * Disconnect MT5 account
 */
const disconnectMT5 = catchAsync(async (req, res) => {
  logger.info('Disconnecting MT5 account for user: %s', req.user.id);

  const user = await userService.getUserById(req.user.id);
  const mt5AccountId = user.mt5Account?.accountId;

  if (mt5AccountId) {
    // Delete all trades associated with this MT5 account
    const deleteTradesResult = await Trade.deleteMany({
      userId: req.user.id,
      'source.mt5AccountId': mt5AccountId,
    });
    logger.info(
      'Deleted %d MT5 trades for user: %s account: %s',
      deleteTradesResult.deletedCount,
      req.user.id,
      mt5AccountId
    );

    // Delete all heatmap history for this user
    const deleteHeatmapResult = await BehaviorHeatmapHistory.deleteMany({ userId: req.user.id });
    logger.info('Deleted %d heatmap history records for user: %s', deleteHeatmapResult.deletedCount, req.user.id);

    // Delete all stability history for this user
    const deleteStabilityResult = await StabilityTrendHistory.deleteMany({ userId: req.user.id });
    logger.info('Deleted %d stability history records for user: %s', deleteStabilityResult.deletedCount, req.user.id);
  }

  // Clear MT5 account info
  await userService.updateUserById(req.user.id, {
    mt5Account: {
      accountId: null,
      server: null,
      password: null,
      isConnected: false,
      lastSyncAt: null,
    },
  });

  logger.info('MT5 account disconnected for user: %s', req.user.id);
  res.status(httpStatus.OK).send({
    success: true,
    message: 'MT5 account disconnected',
    deletedTrades: !!mt5AccountId,
  });
});

module.exports = {
  connectMT5,
  syncTrades,
  getConnectionStatus,
  disconnectMT5,
};
