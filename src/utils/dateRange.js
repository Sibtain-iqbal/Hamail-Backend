/**
 * Get date range for period
 * @param {string} period - WEEK, MONTH, QUARTER, YEAR
 * @returns {Object} { start: Date, end: Date }
 */
const getDateRange = (period) => {
  const now = new Date();
  const start = new Date();

  switch (period) {
    case 'WEEK':
      start.setDate(now.getDate() - 7);
      break;
    case 'MONTH':
      start.setMonth(now.getMonth() - 1);
      break;
    case 'QUARTER':
      start.setMonth(now.getMonth() - 3);
      break;
    case 'YEAR':
      start.setFullYear(now.getFullYear() - 1);
      break;
    default:
      start.setMonth(now.getMonth() - 1);
  }

  return { start, end: now };
};

module.exports = getDateRange;
