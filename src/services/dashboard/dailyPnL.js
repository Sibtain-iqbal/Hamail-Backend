/**
 * Calculate daily P&L from trades
 * @param {Array} trades
 * @returns {Array}
 */
const calculateDailyPnL = (trades) => {
  const dailyPnL = {};

  trades.forEach((trade) => {
    const date = new Date(trade.entryTime).toISOString().split('T')[0];
    if (!dailyPnL[date]) {
      dailyPnL[date] = 0;
    }
    dailyPnL[date] += trade.profitLoss;
  });

  return Object.entries(dailyPnL)
    .map(([date, profitLoss]) => ({
      date,
      profitLoss: Math.round(profitLoss * 100) / 100,
    }))
    .sort((a, b) => new Date(a.date) - new Date(b.date));
};

module.exports = calculateDailyPnL;
