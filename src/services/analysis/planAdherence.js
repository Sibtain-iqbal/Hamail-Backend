/**
 * Calculate plan adherence score (0-100)
 * @param {Object} metrics
 * @param {Object} dayMetrics
 * @param {number} totalTrades
 * @returns {number}
 */
const calculatePlanAdherence = (metrics, dayMetrics, totalTrades) => {
  const { riskBreaches, nearTargetHits } = metrics;
  const { daysWithTrades, exceededDays, outsideSessionDays } = dayMetrics;

  const riskDiscipline = 1 - riskBreaches / Math.max(1, totalTrades);
  const sessionAdherence = 1 - outsideSessionDays / Math.max(1, daysWithTrades);
  const tradeCountDiscipline = 1 - exceededDays / Math.max(1, daysWithTrades);
  const targetProgress = Math.min(1, nearTargetHits / Math.max(1, totalTrades));

  const WEIGHTS = { risk: 0.4, session: 0.25, tradeCount: 0.25, target: 0.1 };
  const components = [];
  const weights = [];

  if (!Number.isNaN(riskDiscipline)) {
    components.push(riskDiscipline);
    weights.push(WEIGHTS.risk);
  }
  if (!Number.isNaN(sessionAdherence)) {
    components.push(sessionAdherence);
    weights.push(WEIGHTS.session);
  }
  if (!Number.isNaN(tradeCountDiscipline)) {
    components.push(tradeCountDiscipline);
    weights.push(WEIGHTS.tradeCount);
  }
  if (!Number.isNaN(targetProgress)) {
    components.push(targetProgress);
    weights.push(WEIGHTS.target);
  }

  const weightSum = weights.reduce((s, w) => s + w, 0) || 1;
  const adherenceWeighted = components.reduce((s, v, i) => s + v * weights[i], 0) / weightSum;

  return Math.round(adherenceWeighted * 100);
};

module.exports = calculatePlanAdherence;
