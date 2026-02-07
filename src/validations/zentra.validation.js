const Joi = require('joi');

const getMentalBattery = {
  // No query parameters needed
};

const getPlanControl = {
  // No query parameters needed
};

const getBehaviorHeatmap = {
  // No query parameters needed
};

const getPsychologicalRadar = {
  // No query parameters needed
};

const getBreathworkSuggestion = {
  // No query parameters needed
};

const getPerformanceWindow = {
  // No query parameters needed
};

const getConsistencyTrend = {
  query: Joi.object().keys({
    days: Joi.string().valid('7', '10', '20', 'all').default('7'),
  }),
};

const getDailyQuote = {
  // No query parameters needed
};

const getHeatmapHistory = {
  query: Joi.object().keys({
    startDate: Joi.date().iso().optional(),
    endDate: Joi.date().iso().optional(),
  }),
};

const getStabilityHistory = {
  query: Joi.object().keys({
    startDate: Joi.date().iso().optional(),
    endDate: Joi.date().iso().optional(),
  }),
};

module.exports = {
  getMentalBattery,
  getPlanControl,
  getBehaviorHeatmap,
  getPsychologicalRadar,
  getBreathworkSuggestion,
  getPerformanceWindow,
  getConsistencyTrend,
  getDailyQuote,
  getHeatmapHistory,
  getStabilityHistory,
};
