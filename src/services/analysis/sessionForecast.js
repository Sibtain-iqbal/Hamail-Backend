const logger = require('../../config/logger');

const { PsychologicalState, TradingSessions, RiskLevel } = require('../../models/enums');

/**
 * Analyze session forecast focusing on psychological bias risk
 * @param {Array} trades
 * @param {string} session
 * @param {Object} plan
 * @param {Object} currentState
 * @returns {Object}
 */
const analyzeSessionForecast = (trades, session, plan, currentState) => {
  logger.info('Analysis: Starting session forecast analysis');
  const upperSession = (session || TradingSessions.LONDON).toUpperCase();

  if (trades.length === 0 || !plan) {
    return {
      session: upperSession,
      predictedBias: 'NEUTRAL',
      riskLevel: RiskLevel.MEDIUM,
      forecast: 'NEUTRAL',
      recommendations: ['Log more trades in this session to improve forecast'],
      basedOnState: (currentState && currentState.state) || PsychologicalState.STABLE,
    };
  }

  const totalTrades = trades.length;

  // Calculate avgRisk only from trades with non-null riskPercentUsed
  const tradesWithRisk = trades.filter((t) => t.riskPercentUsed != null);
  const avgRisk =
    tradesWithRisk.length > 0
      ? tradesWithRisk.reduce((s, t) => s + t.riskPercentUsed, 0) / tradesWithRisk.length
      : plan.riskPercentPerTrade || 0;
  const outsideSessionTrades = trades.filter((t) => !(plan.preferredSessions || []).includes(t.session)).length;

  // Bias detection heuristics
  let predictedBias = 'NEUTRAL';
  let riskLevel = RiskLevel.MEDIUM;
  const recommendations = [];
  const recentLossStreak = trades.slice(0, 3).every((t) => t.profitLoss <= 0) && totalTrades >= 3;

  if (recentLossStreak) {
    predictedBias = 'Revenge trading risk';
    riskLevel = RiskLevel.HIGH;
    recommendations.push('Consider pausing before new entries; reset after losses');
  }

  if (avgRisk > (plan.riskPercentPerTrade || 0) * 1.25) {
    predictedBias = predictedBias === 'NEUTRAL' ? 'Risk escalation tendency' : predictedBias;
    riskLevel = RiskLevel.HIGH;
    recommendations.push('Reduce risk per trade to plan level');
  }

  if (outsideSessionTrades / totalTrades >= 0.2) {
    predictedBias = predictedBias === 'NEUTRAL' ? 'Session drift' : predictedBias;
    if (riskLevel !== RiskLevel.HIGH) riskLevel = RiskLevel.MEDIUM;
    recommendations.push('Trade only in preferred sessions for this period');
  }

  if (predictedBias === 'NEUTRAL') {
    recommendations.push('Proceed per plan; monitor emotions after first outcome');
  }

  let forecast = 'NEUTRAL';
  if (riskLevel === RiskLevel.HIGH) {
    forecast = 'NEGATIVE';
  } else if (riskLevel === RiskLevel.LOW) {
    forecast = 'POSITIVE';
  }

  return {
    session: upperSession,
    predictedBias,
    riskLevel,
    forecast,
    recommendations,
    basedOnState: (currentState && currentState.state) || PsychologicalState.STABLE,
  };
};

module.exports = analyzeSessionForecast;
