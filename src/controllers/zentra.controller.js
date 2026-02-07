const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const { zentraService } = require('../services');
const logger = require('../config/logger');

const getMentalBattery = catchAsync(async (req, res) => {
  logger.info('[V2] Getting mental battery for user: %s', req.user.id);
  const result = await zentraService.getMentalBattery(req.user.id);
  logger.info('[V2] Mental battery retrieved: %d%% status: %s', result.battery, result.status);
  res.status(httpStatus.OK).send(result);
});

const getPlanControl = catchAsync(async (req, res) => {
  logger.info('[V2] Getting plan control for user: %s', req.user.id);
  const result = await zentraService.getPlanControl(req.user.id);
  logger.info('[V2] Plan control retrieved: %d%% trades analyzed: %d', result.percentage, result.tradesAnalyzed);
  res.status(httpStatus.OK).send(result);
});

const getBehaviorHeatmap = catchAsync(async (req, res) => {
  logger.info('[V2] Getting behavior heatmap for user: %s', req.user.id);
  const result = await zentraService.getBehaviorHeatmap(req.user.id);
  logger.info('[V2] Behavior heatmap retrieved: %d windows', result.windows.length);
  res.status(httpStatus.OK).send(result);
});

const getPsychologicalRadar = catchAsync(async (req, res) => {
  logger.info('[V2] Getting psychological radar for user: %s', req.user.id);
  const result = await zentraService.getPsychologicalRadar(req.user.id);
  logger.info('[V2] Psychological radar retrieved for user: %s', req.user.id);
  res.status(httpStatus.OK).send(result);
});

const getBreathworkSuggestion = catchAsync(async (req, res) => {
  logger.info('[V2] Getting breathwork suggestion for user: %s', req.user.id);
  const result = await zentraService.getBreathworkSuggestion(req.user.id);
  logger.info('[V2] Breathwork suggestion: %s triggers: %d', result.shouldSuggest, result.triggers.length);
  res.status(httpStatus.OK).send(result);
});

const getPerformanceWindow = catchAsync(async (req, res) => {
  logger.info('[V2] Getting performance window for user: %s', req.user.id);
  const result = await zentraService.getPerformanceWindow(req.user.id);
  logger.info('[V2] Performance window retrieved, message: %s', result.message || 'none');
  res.status(httpStatus.OK).send(result);
});

const getConsistencyTrend = catchAsync(async (req, res) => {
  const days = req.query.days || '7';
  logger.info('[V2] Getting consistency trend for user: %s days: %s', req.user.id, days);
  const result = await zentraService.getConsistencyTrend(req.user.id, days);
  logger.info('[V2] Consistency trend retrieved: %d data points', result.trend.length);
  res.status(httpStatus.OK).send(result);
});

const getDailyQuote = catchAsync(async (req, res) => {
  logger.info('[V2] Getting daily quote for user: %s', req.user.id);
  const result = await zentraService.getDailyQuote(req.user.id);
  logger.info('[V2] Daily quote retrieved, category: %s', result.category);
  res.status(httpStatus.OK).send(result);
});

const getBehaviorHeatmapHistory = catchAsync(async (req, res) => {
  logger.info('[V2] Getting behavior heatmap history for user: %s', req.user.id);
  const result = await zentraService.getBehaviorHeatmapHistory(req.user.id, req.query);
  logger.info('[V2] Behavior heatmap history retrieved: %d records', result.count);
  res.status(httpStatus.OK).send(result);
});

const getStabilityHistory = catchAsync(async (req, res) => {
  logger.info('[V2] Getting stability history for user: %s', req.user.id);
  const result = await zentraService.getStabilityHistory(req.user.id, req.query);
  logger.info('[V2] Stability history retrieved: %d records', result.count);
  res.status(httpStatus.OK).send(result);
});

module.exports = {
  getMentalBattery,
  getPlanControl,
  getBehaviorHeatmap,
  getPsychologicalRadar,
  getBreathworkSuggestion,
  getPerformanceWindow,
  getConsistencyTrend,
  getDailyQuote,
  getBehaviorHeatmapHistory,
  getStabilityHistory,
};
