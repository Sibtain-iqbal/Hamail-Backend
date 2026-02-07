/**
 * Calculate session performance metrics
 * @param {Array} trades
 * @returns {Array}
 */
const calculateSessionPerformance = (trades) => {
  const sessionStats = {};

  trades.forEach((trade) => {
    const { session } = trade;
    if (!sessionStats[session]) {
      sessionStats[session] = {
        trades: 0,
        profitLoss: 0,
        winningTrades: 0,
      };
    }
    sessionStats[session].trades += 1;
    sessionStats[session].profitLoss += trade.profitLoss;
    if (trade.profitLoss > 0) {
      sessionStats[session].winningTrades += 1;
    }
  });

  return Object.entries(sessionStats).map(([session, stats]) => ({
    session,
    trades: stats.trades,
    profitLoss: Math.round(stats.profitLoss * 100) / 100,
    winRate: Math.round((stats.winningTrades / stats.trades) * 100 * 100) / 100,
  }));
};

module.exports = calculateSessionPerformance;
