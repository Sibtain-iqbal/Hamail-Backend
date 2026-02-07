const logger = require('../../config/logger');

/**
 * Check if trade is in an allowed session
 */
const isInAllowedSession = (trade, preferredSessions) => {
  if (!preferredSessions || preferredSessions.length === 0) return true;
  return preferredSessions.includes(trade.session);
};

/**
 * Check if trade has proper SL/TP placement
 * +30 if SL & TP exist AND RR >= plan.minRR
 */
const hasProperSlTp = (trade, targetRR) => {
  // If stopLossHit is defined, SL exists
  // Check if RR achieved meets target or target percent achieved is good
  if (trade.stopLossHit === false && trade.targetPercentAchieved >= 80) {
    return true;
  }
  if (trade.riskRewardAchieved && trade.riskRewardAchieved >= targetRR) {
    return true;
  }
  return false;
};

/**
 * Check if trade has correct position sizing (within ±10% of planRisk)
 */
const hasCorrectPositionSize = (trade, planRisk) => {
  if (!trade.riskPercentUsed || !planRisk) return false;
  const minRisk = planRisk * 0.9;
  const maxRisk = planRisk * 1.1;
  return trade.riskPercentUsed >= minRisk && trade.riskPercentUsed <= maxRisk;
};

/**
 * Check if trade has notes populated
 */
const hasNotes = (trade) => {
  return trade.notes && trade.notes.trim().length > 0;
};

/**
 * Check timing discipline (no entry within 30 mins of previous exit)
 */
const hasTimingDiscipline = (trade, previousTrade) => {
  if (!previousTrade) return true; // First trade always passes
  const entryTime = new Date(trade.entryTime);
  const prevExitTime = new Date(previousTrade.exitTime);
  const diffMinutes = (entryTime - prevExitTime) / (1000 * 60);
  return diffMinutes >= 30;
};

/**
 * Calculate score for a single trade (0-100)
 * Criteria:
 * - Allowed Session: 20 pts
 * - Proper SL/TP: 30 pts
 * - Correct Position Size: 25 pts
 * - Notes: 10 pts
 * - Timing: 15 pts
 */
const calculateTradeScore = (trade, plan, previousTrade = null) => {
  let score = 0;
  const breakdown = [];

  const planRisk = plan?.riskPercentPerTrade || 1;
  const targetRR = plan?.targetRiskRewardRatio || 1;
  const preferredSessions = plan?.preferredSessions || [];

  // Allowed Session: 20 pts
  if (isInAllowedSession(trade, preferredSessions)) {
    score += 20;
    breakdown.push({ criterion: 'allowedSession', points: 20, passed: true });
  } else {
    breakdown.push({ criterion: 'allowedSession', points: 0, passed: false });
  }

  // Proper SL/TP: 30 pts
  if (hasProperSlTp(trade, targetRR)) {
    score += 30;
    breakdown.push({ criterion: 'properSlTp', points: 30, passed: true });
  } else {
    breakdown.push({ criterion: 'properSlTp', points: 0, passed: false });
  }

  // Correct Position Size: 25 pts
  if (hasCorrectPositionSize(trade, planRisk)) {
    score += 25;
    breakdown.push({ criterion: 'correctPositionSize', points: 25, passed: true });
  } else {
    breakdown.push({ criterion: 'correctPositionSize', points: 0, passed: false });
  }

  // Notes: 10 pts
  if (hasNotes(trade)) {
    score += 10;
    breakdown.push({ criterion: 'notes', points: 10, passed: true });
  } else {
    breakdown.push({ criterion: 'notes', points: 0, passed: false });
  }

  // Timing: 15 pts
  if (hasTimingDiscipline(trade, previousTrade)) {
    score += 15;
    breakdown.push({ criterion: 'timing', points: 15, passed: true });
  } else {
    breakdown.push({ criterion: 'timing', points: 0, passed: false });
  }

  return { score, breakdown };
};

/**
 * Calculate Plan Control % based on last up to 5 trades
 * @param {Array} trades - Recent trades (should be sorted by entryTime desc)
 * @param {Object} plan - Trading plan
 * @returns {Object} Plan control result
 */
const calculatePlanControl = (trades, plan) => {
  logger.info('[PlanControl] Calculating for %d trades', trades.length);

  if (!trades || trades.length === 0) {
    logger.info('[PlanControl] No trades available');
    return {
      percentage: 0,
      tradesAnalyzed: 0,
      message: 'No trades to analyze',
      tradeScores: [],
    };
  }

  // Take last 5 trades (sorted by entry time ascending for proper timing calculation)
  const recentTrades = trades.slice(0, 5);
  const sortedTrades = [...recentTrades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  const tradeScores = [];
  let totalScore = 0;

  sortedTrades.forEach((trade, index) => {
    const previousTrade = index > 0 ? sortedTrades[index - 1] : null;
    const { score, breakdown } = calculateTradeScore(trade, plan, previousTrade);
    tradeScores.push({
      tradeId: trade._id,
      entryTime: trade.entryTime,
      score,
      breakdown,
    });
    totalScore += score;
  });

  const percentage = Math.round(totalScore / sortedTrades.length);

  logger.info('[PlanControl] Calculated percentage: %d%% from %d trades', percentage, sortedTrades.length);

  return {
    percentage,
    tradesAnalyzed: sortedTrades.length,
    message: getPlanControlMessage(percentage),
    tradeScores,
  };
};

const getPlanControlMessage = (percentage) => {
  if (percentage >= 80) {
    return 'You executed with strong alignment to your trading plan. Decisions were deliberate, risk was respected, and emotion stayed secondary to process. This is a high-control state — protect it.';
  } else if (percentage >= 60) {
    return 'You followed your plan for the most part, but certain moments showed hesitation or premature decision-making. This often reflects doubt rather than poor analysis. Strengthen trust in your process and allow trades to play out as designed.';
  } else if (percentage >= 40) {
    return 'Your execution consistency is unstable. Several trades deviated from your plan during moments of uncertainty or emotional pressure. Focus on slowing decision-making and tightening pre-trade criteria.';
  } else {
    return 'Your plan was frequently overridden by impulse or emotion. Stress, urgency, or outcome-focus likely took control. Step back, reduce exposure, and rebuild discipline before increasing activity.';
  }
};

/**
 * Analyze deviation attribution - WHY plan deviations occurred
 * @param {Array} tradeScores - Array of trade scores with breakdowns
 * @param {Array} trades - Original trades with full data
 * @param {number} mentalBatteryLevel - Current mental battery level (optional)
 * @returns {Object} Deviation attribution analysis
 */
const analyzeDeviationAttribution = (tradeScores, trades, mentalBatteryLevel = null) => {
  const attribution = {
    primaryCause: null,
    message: null,
    patterns: [],
  };

  // Find trades with deviations (score < 70)
  const deviationTrades = tradeScores.filter((ts) => ts.score < 70);

  if (deviationTrades.length === 0) {
    attribution.message = 'No significant plan deviations detected';
    return attribution;
  }

  // Analyze deviation patterns
  const deviationCriteria = {
    timing: 0,
    positionSize: 0,
    session: 0,
    slTp: 0,
    notes: 0,
  };

  deviationTrades.forEach((ts) => {
    ts.breakdown.forEach((b) => {
      if (!b.passed) {
        if (b.criterion === 'timing') deviationCriteria.timing++;
        if (b.criterion === 'correctPositionSize') deviationCriteria.positionSize++;
        if (b.criterion === 'allowedSession') deviationCriteria.session++;
        if (b.criterion === 'properSlTp') deviationCriteria.slTp++;
        if (b.criterion === 'notes') deviationCriteria.notes++;
      }
    });
  });

  // Check for consecutive trades pattern
  const sortedDeviations = deviationTrades
    .map((dt) => {
      const trade = trades.find((t) => t._id?.toString() === dt.tradeId?.toString());
      return { ...dt, trade };
    })
    .filter((d) => d.trade);

  // Check for high-frequency trading pattern
  let highFrequencyDeviations = 0;
  for (let i = 1; i < sortedDeviations.length; i++) {
    const prev = sortedDeviations[i - 1].trade;
    const curr = sortedDeviations[i].trade;
    if (prev && curr) {
      const timeDiff = (new Date(curr.entryTime) - new Date(prev.exitTime)) / (1000 * 60);
      if (timeDiff < 30) {
        highFrequencyDeviations++;
      }
    }
  }

  // Check for consecutive wins/losses before deviations
  let afterWinDeviations = 0;
  let afterLossDeviations = 0;
  sortedDeviations.forEach((d, idx) => {
    if (idx > 0) {
      const prevTrade = trades.find((t) => new Date(t.exitTime) < new Date(d.trade?.entryTime));
      if (prevTrade) {
        if (prevTrade.profitLoss > 0) afterWinDeviations++;
        if (prevTrade.profitLoss < 0) afterLossDeviations++;
      }
    }
  });

  // Determine primary cause based on patterns
  const causes = [];

  // Mental battery correlation
  if (mentalBatteryLevel !== null && mentalBatteryLevel < 50 && deviationTrades.length > 0) {
    causes.push({
      type: 'low_battery',
      weight: 3,
      message: 'Most plan deviations occurred when mental battery was low',
    });
  }

  // High frequency pattern
  if (highFrequencyDeviations > 0) {
    causes.push({
      type: 'high_frequency',
      weight: highFrequencyDeviations * 2,
      message: 'Plan deviations cluster during high-frequency trading periods',
    });
  }

  // Timing issues
  if (deviationCriteria.timing >= 2) {
    causes.push({
      type: 'impulsive_timing',
      weight: deviationCriteria.timing,
      message: 'Impulsive re-entries are the main deviation pattern',
    });
  }

  // Position sizing issues
  if (deviationCriteria.positionSize >= 2) {
    causes.push({
      type: 'position_sizing',
      weight: deviationCriteria.positionSize,
      message: 'Position sizing deviations are frequent - risk management slipping',
    });
  }

  // Session violations
  if (deviationCriteria.session >= 2) {
    causes.push({
      type: 'session_violation',
      weight: deviationCriteria.session,
      message: 'Trading outside preferred sessions leads to more rule breaks',
    });
  }

  // After consecutive wins
  if (afterWinDeviations >= 2) {
    causes.push({
      type: 'after_wins',
      weight: afterWinDeviations,
      message: 'Plan deviations increase after consecutive wins - overconfidence risk',
    });
  }

  // After losses (revenge trading pattern)
  if (afterLossDeviations >= 2) {
    causes.push({
      type: 'after_losses',
      weight: afterLossDeviations * 1.5,
      message: 'Plan deviations follow losses - possible revenge trading pattern',
    });
  }

  // Sort by weight and pick primary cause
  causes.sort((a, b) => b.weight - a.weight);

  if (causes.length > 0) {
    attribution.primaryCause = causes[0].type;
    attribution.message = causes[0].message;
    attribution.patterns = causes.slice(0, 3).map((c) => c.message);
  } else {
    attribution.message = `${deviationTrades.length} plan deviation(s) detected - review trade discipline`;
  }

  logger.info('[PlanControl] Deviation attribution: %s', attribution.primaryCause || 'general');

  return attribution;
};

/**
 * Enhanced Plan Control calculation with deviation attribution
 */
const calculatePlanControlWithAttribution = (trades, plan, mentalBatteryLevel = null) => {
  const baseResult = calculatePlanControl(trades, plan);

  if (baseResult.tradesAnalyzed === 0) {
    return {
      ...baseResult,
      deviationAttribution: {
        primaryCause: null,
        message: 'No trades to analyze',
        patterns: [],
      },
    };
  }

  const deviationAttribution = analyzeDeviationAttribution(baseResult.tradeScores, trades.slice(0, 5), mentalBatteryLevel);

  return {
    ...baseResult,
    deviationAttribution,
  };
};

module.exports = {
  calculatePlanControl,
  calculatePlanControlWithAttribution,
  calculateTradeScore,
  analyzeDeviationAttribution,
  isInAllowedSession,
  hasProperSlTp,
  hasCorrectPositionSize,
  hasNotes,
  hasTimingDiscipline,
};
