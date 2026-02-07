/**
 * Generate alerts based on trading data and psychological state
 * @param {Array} trades
 * @param {Object} psychologicalState
 * @returns {Array}
 */
const generateAlerts = (trades, psychologicalState) => {
  const alerts = [];

  if (trades.length === 0) {
    return alerts;
  }

  // Calculate metrics for alerts
  const winRate = trades.filter((t) => t.profitLoss > 0).length / trades.length;

  // Calculate avgRisk only from trades with non-null riskPercentUsed
  const tradesWithRisk = trades.filter((t) => t.riskPercentUsed != null);
  const avgRisk =
    tradesWithRisk.length > 0 ? tradesWithRisk.reduce((sum, t) => sum + t.riskPercentUsed, 0) / tradesWithRisk.length : 0;
  const recentTrades = trades.slice(-5); // Last 5 trades
  const recentWinRate = recentTrades.filter((t) => t.profitLoss > 0).length / recentTrades.length;

  // Win rate alerts
  if (winRate >= 0.7) {
    alerts.push({
      type: 'SUCCESS',
      message: 'Excellent win rate achieved',
      priority: 'MEDIUM',
    });
  } else if (winRate <= 0.3) {
    alerts.push({
      type: 'WARNING',
      message: 'Low win rate - review trading strategy',
      priority: 'HIGH',
    });
  }

  // Risk management alerts
  if (avgRisk > 3) {
    alerts.push({
      type: 'WARNING',
      message: 'Risk per trade above recommended level',
      priority: 'HIGH',
    });
  } else if (avgRisk < 1) {
    alerts.push({
      type: 'INFO',
      message: 'Consider increasing position sizes gradually',
      priority: 'LOW',
    });
  }

  // Recent performance alerts
  if (recentWinRate > winRate + 0.2) {
    alerts.push({
      type: 'SUCCESS',
      message: 'Recent performance showing improvement',
      priority: 'MEDIUM',
    });
  } else if (recentWinRate < winRate - 0.2) {
    alerts.push({
      type: 'WARNING',
      message: 'Recent performance declining',
      priority: 'HIGH',
    });
  }

  // Psychological state alerts
  if (psychologicalState.state === 'AGGRESSIVE') {
    alerts.push({
      type: 'WARNING',
      message: 'Aggressive behavior detected - reduce risk to plan level',
      priority: 'HIGH',
    });
  } else if (psychologicalState.state === 'HESITANT') {
    alerts.push({
      type: 'INFO',
      message: 'Hesitancy detected - define clear exit rules and trust them',
      priority: 'MEDIUM',
    });
  } else if (psychologicalState.state === 'OVEREXTENDED') {
    alerts.push({
      type: 'WARNING',
      message: 'Overextended - respect daily trade cap and session plan',
      priority: 'HIGH',
    });
  }

  return alerts;
};

module.exports = generateAlerts;
