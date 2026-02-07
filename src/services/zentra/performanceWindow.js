const logger = require('../../config/logger');

/**
 * Improvement detection priority order:
 * 1. Avoided revenge trades
 * 2. Stable risk
 * 3. No impulsive entries
 * 4. Improved plan control
 * 5. No hesitation
 * 6. Consistent timing
 */
const IMPROVEMENTS = [
  {
    id: 'avoided_revenge',
    priority: 1,
    message:
      'You treated losses as information, not a signal to act. By stepping back instead of chasing recovery, you maintained emotional balance and allowed discipline to guide your next decision.',
    description: 'No revenge trades detected after losses',
  },
  {
    id: 'stable_risk',
    priority: 2,
    message:
      'You respected your predefined risk limits across all trades, keeping position sizing and exposure consistent. This kind of risk discipline allows your edge to play out over time without unnecessary drawdowns.',
    description: 'All trades within planned risk parameters',
  },
  {
    id: 'no_impulsive',
    priority: 3,
    message:
      'Trades were spaced with intention, allowing enough time between decisions to reset mentally. This helped prevent emotionally driven re-entries and kept execution aligned with logic rather than impulse.',
    description: 'No impulsive re-entries detected',
  },
  {
    id: 'improved_plan_control',
    priority: 4,
    message:
      'Your recent executions show stronger alignment with your trading plan compared to previous sessions. This suggests growing consistency between what you intend to do and what you actually execute in the market.',
    description: 'Plan compliance improved vs previous trades',
  },
  {
    id: 'no_hesitation',
    priority: 5,
    message:
      'When trades moved in your favour, you allowed them the space to develop instead of exiting early. This reflects increased comfort with open profit and reduced fear of giving gains back.',
    description: 'No early exits on winning trades',
  },
  {
    id: 'consistent_timing',
    priority: 6,
    message:
      'Your trade timing remained well-paced, avoiding clusters of back-to-back executions. This rhythm supports clearer thinking, lowers mental fatigue, and reduces the likelihood of overtrading.',
    description: 'Trades spaced 1-4 hours apart',
  },
];

/**
 * Check if revenge trades were avoided
 * Revenge trade = loss followed by oversized trade
 */
const checkAvoidedRevenge = (trades, planRisk) => {
  if (trades.length < 2) return true;

  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  for (let i = 1; i < sortedTrades.length; i++) {
    const prevTrade = sortedTrades[i - 1];
    const currTrade = sortedTrades[i];
    // Revenge trade: previous was a loss AND current is oversized
    if (prevTrade.profitLoss < 0 && currTrade.riskPercentUsed && currTrade.riskPercentUsed > planRisk * 1.3) {
      return false;
    }
  }

  return true;
};

/**
 * Check if risk usage is stable (all within ±10% of planRisk)
 */
const checkStableRisk = (trades, planRisk) => {
  if (trades.length === 0 || !planRisk) return false;

  const minRisk = planRisk * 0.9;
  const maxRisk = planRisk * 1.1;

  return trades.every((trade) => {
    if (!trade.riskPercentUsed) return false;
    return trade.riskPercentUsed >= minRisk && trade.riskPercentUsed <= maxRisk;
  });
};

/**
 * Check for no impulsive entries (all gaps >= 30 mins)
 */
const checkNoImpulsive = (trades) => {
  if (trades.length < 2) return true;

  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  for (let i = 1; i < sortedTrades.length; i++) {
    const prevExit = new Date(sortedTrades[i - 1].exitTime);
    const currEntry = new Date(sortedTrades[i].entryTime);
    const diffMinutes = (currEntry - prevExit) / (1000 * 60);
    if (diffMinutes < 30 && diffMinutes >= 0) {
      return false;
    }
  }

  return true;
};

/**
 * Check if plan control improved vs previous window
 */
const checkImprovedPlanControl = (currentPlanControl, previousPlanControl) => {
  if (previousPlanControl === null || previousPlanControl === undefined) return false;
  return currentPlanControl > previousPlanControl;
};

/**
 * Check for no hesitation (no early exits)
 */
const checkNoHesitation = (trades) => {
  return trades.every((trade) => !trade.exitedEarly);
};

/**
 * Check for consistent timing (trades spaced 1-4 hours apart)
 */
const checkConsistentTiming = (trades) => {
  if (trades.length < 2) return true;

  const sortedTrades = [...trades].sort((a, b) => new Date(a.entryTime) - new Date(b.entryTime));

  for (let i = 1; i < sortedTrades.length; i++) {
    const prevExit = new Date(sortedTrades[i - 1].exitTime);
    const currEntry = new Date(sortedTrades[i].entryTime);
    const diffHours = (currEntry - prevExit) / (1000 * 60 * 60);
    if (diffHours < 1 || diffHours > 4) {
      return false;
    }
  }

  return true;
};

/**
 * Detect improvements and return the highest priority one
 * @param {Array} trades - Last 5 trades
 * @param {Object} plan - Trading plan
 * @param {number} currentPlanControl - Current plan control %
 * @param {number} previousPlanControl - Previous window plan control %
 * @returns {Object} Performance window result
 */
const getPerformanceWindow = (trades, plan, currentPlanControl, previousPlanControl = null) => {
  logger.info('[PerformanceWindow] Analyzing %d trades', trades.length);

  if (!trades || trades.length === 0) {
    return {
      hasImprovement: false,
      message: null,
      description: null,
      tradesAnalyzed: 0,
      improvements: [],
    };
  }

  const planRisk = plan?.riskPercentPerTrade || 1;
  const detectedImprovements = [];

  // Check all improvements
  if (checkAvoidedRevenge(trades, planRisk)) {
    detectedImprovements.push(IMPROVEMENTS.find((i) => i.id === 'avoided_revenge'));
  }

  if (checkStableRisk(trades, planRisk)) {
    detectedImprovements.push(IMPROVEMENTS.find((i) => i.id === 'stable_risk'));
  }

  if (checkNoImpulsive(trades)) {
    detectedImprovements.push(IMPROVEMENTS.find((i) => i.id === 'no_impulsive'));
  }

  if (checkImprovedPlanControl(currentPlanControl, previousPlanControl)) {
    detectedImprovements.push(IMPROVEMENTS.find((i) => i.id === 'improved_plan_control'));
  }

  if (checkNoHesitation(trades)) {
    detectedImprovements.push(IMPROVEMENTS.find((i) => i.id === 'no_hesitation'));
  }

  if (checkConsistentTiming(trades)) {
    detectedImprovements.push(IMPROVEMENTS.find((i) => i.id === 'consistent_timing'));
  }

  // Sort by priority and get highest
  detectedImprovements.sort((a, b) => a.priority - b.priority);

  const topImprovement = detectedImprovements[0] || null;

  logger.info(
    '[PerformanceWindow] Detected %d improvements, top: %s',
    detectedImprovements.length,
    topImprovement?.id || 'none'
  );

  return {
    hasImprovement: detectedImprovements.length > 0,
    message: topImprovement?.message || null,
    description: topImprovement?.description || null,
    tradesAnalyzed: trades.length,
    improvements: detectedImprovements.map((i) => ({
      id: i.id,
      message: i.message,
      description: i.description,
    })),
  };
};

module.exports = {
  getPerformanceWindow,
  checkAvoidedRevenge,
  checkStableRisk,
  checkNoImpulsive,
  checkImprovedPlanControl,
  checkNoHesitation,
  checkConsistentTiming,
  IMPROVEMENTS,
};
