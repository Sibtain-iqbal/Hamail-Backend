const analyzePsychologicalState = require('./stateAnalysis');
const getStateTrigger = require('../../utils/stateTrigger');

const { PsychologicalState } = require('../../models/enums');

/**
 * Analyze state history
 * @param {Array} trades
 * @param {Object} plan
 * @param {number} limit
 * @returns {Object}
 */
const analyzeStateHistory = (trades, plan, limit) => {
  if (trades.length === 0 || !plan) {
    return {
      history: [],
      summary: {
        totalChanges: 0,
        mostCommonState: PsychologicalState.STABLE,
        averageConfidence: 50,
        volatility: 0,
      },
    };
  }

  const history = [];
  const states = [];
  const confidences = [];

  const sortedTrades = trades.sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));
  let lastState = null;
  let stateChangeCount = 0;

  for (let i = 0; i < sortedTrades.length && history.length < limit; i += 1) {
    const trade = sortedTrades[i];
    const recentTrades = sortedTrades.slice(Math.max(0, i - 4), i + 1);
    const state = analyzePsychologicalState(recentTrades, plan);

    if (!lastState || lastState.state !== state.state || Math.abs(lastState.confidence - state.confidence) > 15) {
      history.push({
        timestamp: trade.entryTime,
        state: state.state,
        confidence: state.confidence,
        trigger: getStateTrigger(trade),
        context: {
          tradeId: trade._id,
          profitLoss: trade.profitLoss,
          riskPercentUsed: trade.riskPercentUsed,
        },
      });

      states.push(state.state);
      confidences.push(state.confidence);
      stateChangeCount += 1;
      lastState = state;
    }
  }

  const stateCounts = {};
  states.forEach((st) => {
    stateCounts[st] = (stateCounts[st] || 0) + 1;
  });
  const mostCommonState = Object.keys(stateCounts).length
    ? Object.keys(stateCounts).reduce((a, b) => (stateCounts[a] > stateCounts[b] ? a : b))
    : PsychologicalState.STABLE;

  const averageConfidence =
    confidences.length > 0 ? Math.round(confidences.reduce((sum, conf) => sum + conf, 0) / confidences.length) : 50;

  const variance =
    confidences.length > 0
      ? confidences.reduce((sum, conf) => sum + (conf - averageConfidence) ** 2, 0) / confidences.length
      : 0;
  const volatility = Math.round((Math.sqrt(variance) / 100) * 100) / 100;

  return {
    history: history.slice(0, limit),
    summary: {
      totalChanges: stateChangeCount,
      mostCommonState,
      averageConfidence,
      volatility,
    },
  };
};

module.exports = analyzeStateHistory;
