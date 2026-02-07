const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const { dashboardService } = require('../services');
const logger = require('../config/logger');

const getDashboard = catchAsync(async (req, res) => {
  logger.info('Getting complete dashboard data for user: %s Period: %s', req.user.id, req.query.period);
  const dashboard = await dashboardService.getCompleteDashboard(req.user.id, req.query.period);
  logger.info('Dashboard data retrieved successfully for user: %s Trades: %d', req.user.id, dashboard.summary.totalTrades);
  res.status(httpStatus.OK).send(dashboard);
});

const getSummary = catchAsync(async (req, res) => {
  logger.info('Getting dashboard summary for user: %s Period: %s', req.user.id, req.query.period);
  const summary = await dashboardService.getDashboardSummary(req.user.id, req.query.period);
  logger.info(
    'Dashboard summary retrieved successfully for user: %s State: %s',
    req.user.id,
    summary.quickStats.currentState
  );
  res.status(httpStatus.OK).send(summary);
});

module.exports = {
  getDashboard,
  getSummary,
};
