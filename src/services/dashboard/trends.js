/**
 * Calculate trends from trades
 * @param {Array} trades
 * @returns {Object}
 */
const calculateTrends = (trades) => {
  if (trades.length < 2) {
    return {
      pnlTrend: 'STABLE',
      winRateTrend: 'STABLE',
      riskTrend: 'STABLE',
    };
  }

  // Split trades into two halves for comparison
  const midPoint = Math.floor(trades.length / 2);
  const firstHalf = trades.slice(0, midPoint);
  const secondHalf = trades.slice(midPoint);

  // P&L trend
  const firstHalfPnL = firstHalf.reduce((sum, t) => sum + t.profitLoss, 0);
  const secondHalfPnL = secondHalf.reduce((sum, t) => sum + t.profitLoss, 0);
  let pnlTrend = 'STABLE';
  if (secondHalfPnL > firstHalfPnL) {
    pnlTrend = 'UP';
  } else if (secondHalfPnL < firstHalfPnL) {
    pnlTrend = 'DOWN';
  }

  // Win rate trend
  const firstHalfWinRate = firstHalf.filter((t) => t.profitLoss > 0).length / firstHalf.length;
  const secondHalfWinRate = secondHalf.filter((t) => t.profitLoss > 0).length / secondHalf.length;
  let winRateTrend = 'STABLE';
  if (secondHalfWinRate > firstHalfWinRate) {
    winRateTrend = 'UP';
  } else if (secondHalfWinRate < firstHalfWinRate) {
    winRateTrend = 'DOWN';
  }

  // Risk trend - only calculate from trades with non-null riskPercentUsed
  const firstHalfWithRisk = firstHalf.filter((t) => t.riskPercentUsed != null);
  const secondHalfWithRisk = secondHalf.filter((t) => t.riskPercentUsed != null);
  const firstHalfRisk =
    firstHalfWithRisk.length > 0
      ? firstHalfWithRisk.reduce((sum, t) => sum + t.riskPercentUsed, 0) / firstHalfWithRisk.length
      : 0;
  const secondHalfRisk =
    secondHalfWithRisk.length > 0
      ? secondHalfWithRisk.reduce((sum, t) => sum + t.riskPercentUsed, 0) / secondHalfWithRisk.length
      : 0;
  let riskTrend = 'STABLE';
  if (secondHalfRisk > firstHalfRisk) {
    riskTrend = 'UP';
  } else if (secondHalfRisk < firstHalfRisk) {
    riskTrend = 'DOWN';
  }

  return {
    pnlTrend,
    winRateTrend,
    riskTrend,
  };
};

module.exports = calculateTrends;
