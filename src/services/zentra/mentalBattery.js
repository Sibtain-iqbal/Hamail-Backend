const logger = require('../../config/logger');

/**
 * Check if trade is an impulsive re-entry (entry < 30 min from previous exit)
 */
const isImpulsiveReentry = (trade, previousTrade) => {
  if (!previousTrade) return false;
  const entryTime = new Date(trade.entryTime);
  const prevExitTime = new Date(previousTrade.exitTime);
  const diffMinutes = (entryTime - prevExitTime) / (1000 * 60);
  return diffMinutes < 30 && diffMinutes >= 0;
};

/**
 * Check if trade is oversized (riskUsed > planRisk * 1.3)
 */
const isOversizedTrade = (trade, planRisk) => {
  if (!trade.riskPercentUsed || !planRisk) return false;
  return trade.riskPercentUsed > planRisk * 1.3;
};

/**
 * Check if trade has large loss (profitLoss < -2 * planRisk)
 */
const isLargeLoss = (trade, planRisk) => {
  if (!planRisk) return false;
  return trade.profitLoss < -2 * planRisk;
};

/**
 * Detect clustered trades (3+ trades within 2 hours)
 * Returns number of clusters found (max 2)
 */
const detectClusters = (trades) => {
  if (trades.length < 3) return 0;

  let clusters = 0;
  const twoHoursMs = 2 * 60 * 60 * 1000;

  // Sort trades by entry time
  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  for (let i = 0; i < sortedTrades.length - 2; i++) {
    const windowStart = new Date(sortedTrades[i].entryTime);
    let tradesInWindow = 1;

    for (let j = i + 1; j < sortedTrades.length; j++) {
      const tradeTime = new Date(sortedTrades[j].entryTime);
      if (tradeTime - windowStart <= twoHoursMs) {
        tradesInWindow++;
      } else {
        break;
      }
    }

    if (tradesInWindow >= 3) {
      clusters++;
      if (clusters >= 2) break; // Max 2 clusters
    }
  }

  return clusters;
};

/**
 * Detect disciplined pauses (gap >= 2 hours between trades)
 * Returns count (max 3 for +15% total)
 */
const detectDisciplinedPauses = (trades) => {
  if (trades.length < 2) return 0;

  const twoHoursMs = 2 * 60 * 60 * 1000;
  let pauses = 0;

  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  for (let i = 1; i < sortedTrades.length; i++) {
    const prevExit = new Date(sortedTrades[i - 1].exitTime);
    const currEntry = new Date(sortedTrades[i].entryTime);
    if (currEntry - prevExit >= twoHoursMs) {
      pauses++;
      if (pauses >= 3) break; // Max +15%
    }
  }

  return pauses;
};

/**
 * Check if all trades have stable risk usage (within ±10% of planRisk)
 */
const hasStableRiskUsage = (trades, planRisk) => {
  if (!trades.length || !planRisk) return false;

  const minRisk = planRisk * 0.9;
  const maxRisk = planRisk * 1.1;

  return trades.every((trade) => {
    if (!trade.riskPercentUsed) return false;
    return trade.riskPercentUsed >= minRisk && trade.riskPercentUsed <= maxRisk;
  });
};

/**
 * Check for emotional volatility (both impulsive entries AND hesitation flags today)
 */
const hasEmotionalVolatility = (trades) => {
  if (trades.length < 2) return false;

  let hasImpulsive = false;
  let hasHesitation = false;

  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  for (let i = 0; i < sortedTrades.length; i++) {
    // Check hesitation (early exit or low target achievement)
    if (
      sortedTrades[i].exitedEarly ||
      (sortedTrades[i].targetPercentAchieved && sortedTrades[i].targetPercentAchieved < 60)
    ) {
      hasHesitation = true;
    }

    // Check impulsive re-entry
    if (i > 0 && isImpulsiveReentry(sortedTrades[i], sortedTrades[i - 1])) {
      hasImpulsive = true;
    }
  }

  return hasImpulsive && hasHesitation;
};

const getStatusMessage = (status) => {
  if (status === 'optimal') {
    return 'Mental state is optimal for trading';
  } else if (status === 'strained') {
    return 'Mental energy is strained - consider taking a break';
  } else {
    return 'High-risk emotional state - strongly recommend pausing trading';
  }
};

/**
 * Get behavioral interpretation based on battery level
 * Provides psychological context for what the battery level means
 */
const getBehavioralInterpretation = (battery, drainFactors) => {
  const interpretation = {
    riskLevel: 'low',
    patterns: [],
    recommendation: null,
  };

  // Determine risk level based on thresholds
  if (battery >= 80) {
    interpretation.riskLevel = 'low';
    interpretation.patterns.push('Decision quality is typically strong at this level');
    interpretation.patterns.push('Impulse control remains high');
    interpretation.recommendation = 'Good state for trading - maintain current discipline';
  } else if (battery >= 50) {
    interpretation.riskLevel = 'moderate';
    interpretation.patterns.push('Impulsive trades increase by ~40% in this range');
    interpretation.patterns.push('Plan adherence may start to slip');
    interpretation.recommendation = 'Consider reducing position sizes or trade frequency';
  } else if (battery >= 30) {
    interpretation.riskLevel = 'elevated';
    interpretation.patterns.push('Impulsive trades increase 2-3x below 50%');
    interpretation.patterns.push('Risk of revenge trading rises significantly');
    interpretation.patterns.push('Plan adherence typically drops by 25-40%');
    interpretation.recommendation = 'Strongly consider taking a break before next trade';
  } else {
    interpretation.riskLevel = 'critical';
    interpretation.patterns.push('Decision quality is severely compromised');
    interpretation.patterns.push('Revenge trading likelihood is very high');
    interpretation.patterns.push('Most significant losses occur at this battery level');
    interpretation.recommendation = 'Stop trading - take extended break to recover';
  }

  // Add context from drain factors
  if (drainFactors.length > 0) {
    const drainTypes = drainFactors.map((d) => d.type);

    if (drainTypes.includes('impulsive_reentry')) {
      interpretation.patterns.push('Impulsive re-entries detected - patience is wearing thin');
    }
    if (drainTypes.includes('large_loss')) {
      interpretation.patterns.push('Large losses affecting emotional state - revenge trade risk elevated');
    }
    if (drainTypes.includes('clustered_trades')) {
      interpretation.patterns.push('Trade clustering suggests urgency-driven decisions');
    }
    if (drainTypes.includes('emotional_volatility')) {
      interpretation.patterns.push('Emotional swings detected - decision consistency at risk');
    }
  }

  return interpretation;
};

/**
 * Calculate mental battery based on today's trades
 * @param {Array} todayTrades - Trades from today
 * @param {Object} plan - Trading plan
 * @param {number} planControlPercent - Current plan control percentage
 * @returns {Object} Battery status
 */
const calculateMentalBattery = (todayTrades, plan, planControlPercent = 0) => {
  logger.info('[MentalBattery] Calculating for %d trades', todayTrades.length);

  // Start at 100%
  let battery = 100;
  const drainFactors = [];
  const rechargeFactors = [];
  const planRisk = plan?.riskPercentPerTrade || 1;

  // No trades today
  if (!todayTrades || todayTrades.length === 0) {
    logger.info('[MentalBattery] No trades today, returning 100%%');
    return {
      battery: 100,
      status: 'optimal',
      message: 'No activity today',
      drainFactors: [],
      rechargeFactors: [],
    };
  }

  // Sort trades by entry time
  const sortedTrades = [...todayTrades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  // === DRAIN CALCULATIONS ===

  // Impulsive re-entries: -15% each
  let impulsiveCount = 0;
  for (let i = 1; i < sortedTrades.length; i++) {
    if (isImpulsiveReentry(sortedTrades[i], sortedTrades[i - 1])) {
      impulsiveCount++;
      battery -= 15;
      drainFactors.push({
        type: 'impulsive_reentry',
        impact: -15,
        tradeIndex: i,
        message: `Impulsive re-entry on trade ${i + 1}`,
      });
    }
  }
  logger.info('[MentalBattery] Impulsive re-entries: %d', impulsiveCount);

  // Oversized trades: -10% each
  let oversizedCount = 0;
  sortedTrades.forEach((trade, idx) => {
    if (isOversizedTrade(trade, planRisk)) {
      oversizedCount++;
      battery -= 10;
      drainFactors.push({
        type: 'oversized_trade',
        impact: -10,
        tradeIndex: idx,
        message: `Oversized trade ${idx + 1} (${trade.riskPercentUsed?.toFixed(1) || 0}% vs ${planRisk}% plan)`,
      });
    }
  });
  logger.info('[MentalBattery] Oversized trades: %d', oversizedCount);

  // Clustered trades: -8% per cluster (max 2)
  const clusterCount = detectClusters(sortedTrades);
  if (clusterCount > 0) {
    const clusterDrain = clusterCount * 8;
    battery -= clusterDrain;
    drainFactors.push({
      type: 'clustered_trades',
      impact: -clusterDrain,
      count: clusterCount,
      message: `${clusterCount} trade cluster(s) detected`,
    });
  }
  logger.info('[MentalBattery] Clusters: %d', clusterCount);

  // Large losses: -20% each
  let largeLossCount = 0;
  sortedTrades.forEach((trade, idx) => {
    if (isLargeLoss(trade, planRisk)) {
      largeLossCount++;
      battery -= 20;
      drainFactors.push({
        type: 'large_loss',
        impact: -20,
        tradeIndex: idx,
        message: `Large loss on trade ${idx + 1}`,
      });
    }
  });
  logger.info('[MentalBattery] Large losses: %d', largeLossCount);

  // Emotional volatility: -12% (one-time)
  if (hasEmotionalVolatility(sortedTrades)) {
    battery -= 12;
    drainFactors.push({
      type: 'emotional_volatility',
      impact: -12,
      message: 'Mixed impulsive and hesitant behavior detected',
    });
    logger.info('[MentalBattery] Emotional volatility detected');
  }

  // === RECHARGE CALCULATIONS ===

  // Disciplined pauses: +5% per gap (max +15%)
  const pauseCount = detectDisciplinedPauses(sortedTrades);
  if (pauseCount > 0) {
    const pauseRecharge = Math.min(pauseCount * 5, 15);
    battery += pauseRecharge;
    rechargeFactors.push({
      type: 'disciplined_pauses',
      impact: pauseRecharge,
      count: pauseCount,
      message: `${pauseCount} disciplined pause(s) taken`,
    });
  }
  logger.info('[MentalBattery] Disciplined pauses: %d', pauseCount);

  // High plan compliance: +8% once (if planControl >= 80%)
  if (planControlPercent >= 80) {
    battery += 8;
    rechargeFactors.push({
      type: 'high_plan_compliance',
      impact: 8,
      message: `High plan compliance (${planControlPercent.toFixed(0)}%)`,
    });
    logger.info('[MentalBattery] High plan compliance bonus applied');
  }

  // Stable risk usage: +5% once
  if (hasStableRiskUsage(sortedTrades, planRisk)) {
    battery += 5;
    rechargeFactors.push({
      type: 'stable_risk',
      impact: 5,
      message: 'Stable risk management across all trades',
    });
    logger.info('[MentalBattery] Stable risk bonus applied');
  }

  // Clamp battery between 0 and 100
  battery = Math.max(0, Math.min(100, battery));

  // Determine status
  let status;
  if (battery >= 80) {
    status = 'optimal';
  } else if (battery >= 50) {
    status = 'strained';
  } else {
    status = 'high_risk';
  }

  logger.info('[MentalBattery] Final battery: %d%% status: %s', battery, status);

  // Get behavioral interpretation
  const behavioralInterpretation = getBehavioralInterpretation(battery, drainFactors);
  logger.info('[MentalBattery] Risk level: %s', behavioralInterpretation.riskLevel);

  return {
    battery: Math.round(battery),
    status,
    message: getStatusMessage(status),
    behavioralInterpretation,
    drainFactors,
    rechargeFactors,
    tradesAnalyzed: sortedTrades.length,
  };
};

module.exports = {
  calculateMentalBattery,
  isImpulsiveReentry,
  isOversizedTrade,
  isLargeLoss,
  detectClusters,
  detectDisciplinedPauses,
  hasStableRiskUsage,
  hasEmotionalVolatility,
};
