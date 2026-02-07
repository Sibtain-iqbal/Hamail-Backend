const calculatePlanAdherence = require('./planAdherence');
const calculateConfidence = require('./confidence');
const determineState = require('./stateDetermination');
const logger = require('../../config/logger');

const { PsychologicalState } = require('../../models/enums');
const { calculateBasicMetrics, calculateDayMetrics, calculateRiskSpike, calculateRiskBreaches } = require('./metrics');

/**
 * Analyze psychological state from recent trades against the user's plan
 * @param {Array} trades
 * @param {Object} plan
 * @returns {Object}
 */
const analyzePsychologicalState = (trades, plan) => {
  logger.info('Analysis: Starting psychological state analysis');
  if (trades.length === 0 || !plan) {
    logger.info('Analysis: No trades or plan missing, returning default state');
    return {
      state: PsychologicalState.STABLE,
      confidence: 50,
      planAdherence: 50,
      analyzedTradeCount: 0,
      indicators: [{ category: 'data', message: 'Insufficient data to analyze state', severity: 'neutral' }],
      recommendations: ['Record trades and set a trading plan to enable analysis'],
      lastUpdated: new Date().toISOString(),
    };
  }

  // Analyze up to the last 10 trades (most recent first expected)
  const analyzedTrades = trades.slice(0, 10);
  const totalTrades = analyzedTrades.length;
  const planRisk = plan.riskPercentPerTrade || 0;

  // Calculate all metrics
  const basicMetrics = calculateBasicMetrics(analyzedTrades);
  const dayMetrics = calculateDayMetrics(analyzedTrades, plan);
  const riskSpikeData = calculateRiskSpike(analyzedTrades, planRisk);
  const riskBreaches = calculateRiskBreaches(analyzedTrades, planRisk);

  const riskMetrics = {
    ...riskSpikeData,
    riskBreaches,
    avgRiskUsed: basicMetrics.avgRiskUsed,
  };

  // Calculate plan adherence
  const planAdherence = calculatePlanAdherence({ ...basicMetrics, riskBreaches }, dayMetrics, totalTrades);

  // Determine state
  const { state, indicators, recommendations } = determineState(
    basicMetrics,
    dayMetrics,
    riskMetrics,
    planRisk,
    totalTrades
  );

  // Calculate confidence
  const confidence = calculateConfidence(basicMetrics, planAdherence, planRisk, totalTrades);

  const stateData = {
    state,
    planAdherence,
    winRate: Math.round(basicMetrics.winRate * 100),
    avgRiskUsed: basicMetrics.avgRiskUsed,
    avgRR: basicMetrics.avgRR,
    medianTargetPct: Math.round(basicMetrics.medianTargetPct || 0),
    earlyExits: basicMetrics.earlyExits,
    daysWithTrades: dayMetrics.daysWithTrades,
    exceededDays: dayMetrics.exceededDays,
    outsideSessionDays: dayMetrics.outsideSessionDays,
    riskBreaches,
    riskSpike: riskSpikeData.riskSpike,
    last3Breaches: riskSpikeData.last3Breaches,
    sampleFactor: Math.min(totalTrades, 10) / 10,
    confidence,
  };
  logger.info('Analysis: State computed (v1.1) %j', stateData);

  return {
    state,
    confidence,
    planAdherence,
    analyzedTradeCount: totalTrades,
    indicators,
    recommendations,
    lastUpdated: new Date().toISOString(),
  };
};

module.exports = analyzePsychologicalState;
