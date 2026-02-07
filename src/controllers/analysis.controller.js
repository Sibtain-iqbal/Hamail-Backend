const httpStatus = require('http-status');
const pick = require('../utils/pick');
const catchAsync = require('../utils/catchAsync');
const { analysisService } = require('../services');
const logger = require('../config/logger');

const getState = catchAsync(async (req, res) => {
  logger.info('Getting psychological state for user: %s', req.user.id);
  const state = await analysisService.getCurrentState(req.user.id);
  logger.info('Psychological state retrieved successfully for user: %s State: %s', req.user.id, state.state);
  res.status(httpStatus.OK).send(state);
});

const getForecast = catchAsync(async (req, res) => {
  logger.info('Getting session forecast for user: %s Session: %s', req.user.id, req.query.session);
  const forecast = await analysisService.getSessionForecast(req.user.id, req.query.session);
  logger.info('Session forecast retrieved successfully for user: %s Forecast: %s', req.user.id, forecast.forecast);
  res.status(httpStatus.OK).send(forecast);
});

const getInsights = catchAsync(async (req, res) => {
  logger.info('Getting performance insights for user: %s Period: %s', req.user.id, req.query.period);
  const insights = await analysisService.getPerformanceInsights(req.user.id, req.query.period);
  logger.info(
    'Performance insights retrieved successfully for user: %s Insights count: %d',
    req.user.id,
    insights.insights.length
  );
  res.status(httpStatus.OK).send(insights);
});

const getHistory = catchAsync(async (req, res) => {
  logger.info('Getting psychological history for user: %s', req.user.id);
  const filter = pick(req.query, ['startDate', 'endDate', 'limit']);
  const history = await analysisService.getStateHistory(req.user.id, filter);
  logger.info('Psychological history retrieved successfully for user: %s Records: %d', req.user.id, history.history.length);
  res.status(httpStatus.OK).send(history);
});

module.exports = {
  getState,
  getForecast,
  getInsights,
  getHistory,
};
