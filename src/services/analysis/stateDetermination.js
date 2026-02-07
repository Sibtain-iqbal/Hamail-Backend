const { PsychologicalState } = require('../../models/enums');

/**
 * Determine psychological state based on metrics
 * @param {Object} metrics
 * @param {Object} dayMetrics
 * @param {Object} riskMetrics
 * @param {number} planRisk
 * @param {number} totalTrades
 * @returns {Object} { state, indicators, recommendations }
 */
const determineState = (metrics, dayMetrics, riskMetrics, planRisk, totalTrades) => {
  const { winRate, earlyExits, medianTargetPct, nearTargetHits } = metrics;
  const { daysWithTrades, exceededDays, outsideSessionDays } = dayMetrics;
  const { riskSpike, riskBreaches, avgRiskUsed } = riskMetrics;

  const indicators = [];
  const recommendations = [];
  let state = PsychologicalState.STABLE;

  // Priority: OVEREXTENDED > AGGRESSIVE > HESITANT > STABLE
  const overextended =
    daysWithTrades > 0 && (exceededDays / daysWithTrades >= 0.33 || outsideSessionDays / daysWithTrades >= 0.33);
  const aggressive = riskSpike || riskBreaches / Math.max(1, totalTrades) >= 0.25 || avgRiskUsed > planRisk * 1.25;
  const hesitant = earlyExits / Math.max(1, totalTrades) >= 0.4 || (medianTargetPct < 60 && winRate <= 0.6);

  if (overextended) {
    state = PsychologicalState.OVEREXTENDED;
    indicators.push({
      category: 'discipline',
      message: 'Trading beyond plan boundaries',
      severity: 'warning',
    });
    if (exceededDays > 0) {
      indicators.push({
        category: 'frequency',
        message: 'Exceeded max trades/day',
        severity: 'warning',
        value: exceededDays,
      });
    }
    if (outsideSessionDays > 0) {
      indicators.push({
        category: 'session',
        message: 'Outside preferred sessions (days)',
        severity: 'warning',
        value: outsideSessionDays,
      });
    }
    recommendations.push('Respect daily trade cap and stick to planned sessions');
  } else if (aggressive) {
    state = PsychologicalState.AGGRESSIVE;
    if (riskSpike) {
      indicators.push({
        category: 'risk',
        message: 'Sustained risk elevation (2 of last 3)',
        severity: 'critical',
        value: riskMetrics.last3Breaches,
      });
    }
    if (riskBreaches > 0) {
      indicators.push({
        category: 'risk',
        message: 'Risk > 1.5× plan detected',
        severity: 'critical',
        value: riskBreaches,
      });
    }
    if (avgRiskUsed > planRisk * 1.25) {
      indicators.push({
        category: 'risk',
        message: 'Average risk above plan by 25%+',
        severity: 'warning',
        value: Math.round(avgRiskUsed * 100) / 100,
      });
    }
    recommendations.push('Reduce position size to plan level and enforce stop discipline');
  } else if (hesitant) {
    state = PsychologicalState.HESITANT;
    if (earlyExits > 0) {
      indicators.push({
        category: 'execution',
        message: 'Frequent early exits',
        severity: 'warning',
        value: earlyExits,
      });
    }
    if (medianTargetPct < 60) {
      indicators.push({
        category: 'targets',
        message: 'Median target % below 60',
        severity: 'neutral',
        value: Math.round(medianTargetPct),
      });
    }
    recommendations.push('Define target rules; practice holding winners and scaling out');
  } else {
    state = PsychologicalState.STABLE;
    indicators.push({
      category: 'plan',
      message: 'Trading within plan parameters',
      severity: 'positive',
    });
    if (nearTargetHits / Math.max(1, totalTrades) >= 0.6) {
      indicators.push({
        category: 'targets',
        message: 'Exits near targets',
        severity: 'positive',
        value: nearTargetHits,
      });
    }
    recommendations.push('Maintain discipline; continue tracking adherence');
  }

  return { state, indicators, recommendations };
};

module.exports = determineState;
