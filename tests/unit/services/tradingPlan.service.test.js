const mongoose = require('mongoose');
const { TradingPlan } = require('../../../src/models');
const { tradingPlanService } = require('../../../src/services');
const ApiError = require('../../../src/utils/ApiError');
const { tradingPlanOne, insertTradingPlans } = require('../../fixtures/tradingPlan.fixture');
const setupTestDB = require('../../utils/setupTestDB');

setupTestDB();

describe('TradingPlan service', () => {
  describe('createOrUpdateTradingPlan', () => {
    let newTradingPlan;

    beforeEach(() => {
      newTradingPlan = {
        maxTradesPerDay: 5,
        riskPercentPerTrade: 2.0,
        targetRiskRewardRatio: 1.5,
        preferredSessions: ['LONDON', 'NY'],
        stopLossDiscipline: 'ALWAYS',
      };
    });

    test('should create trading plan successfully', async () => {
      const userId = mongoose.Types.ObjectId();

      const result = await tradingPlanService.createOrUpdateTradingPlan(userId, newTradingPlan);

      expect(result).toBeDefined();
      expect(result.userId.toString()).toBe(userId.toString());
      expect(result.maxTradesPerDay).toBe(newTradingPlan.maxTradesPerDay);
      expect(result.riskPercentPerTrade).toBe(newTradingPlan.riskPercentPerTrade);
      expect(result.targetRiskRewardRatio).toBe(newTradingPlan.targetRiskRewardRatio);
      expect(result.preferredSessions.toObject()).toEqual(newTradingPlan.preferredSessions);
      expect(result.stopLossDiscipline).toBe(newTradingPlan.stopLossDiscipline);
      expect(result.id).toBeDefined();

      const dbTradingPlan = await TradingPlan.findById(result.id);
      expect(dbTradingPlan).toBeDefined();
      expect(dbTradingPlan.userId.toString()).toBe(userId.toString());
      expect(dbTradingPlan.maxTradesPerDay).toBe(newTradingPlan.maxTradesPerDay);
      expect(dbTradingPlan.riskPercentPerTrade).toBe(newTradingPlan.riskPercentPerTrade);
      expect(dbTradingPlan.targetRiskRewardRatio).toBe(newTradingPlan.targetRiskRewardRatio);
      expect(dbTradingPlan.preferredSessions.toObject()).toEqual(newTradingPlan.preferredSessions);
      expect(dbTradingPlan.stopLossDiscipline).toBe(newTradingPlan.stopLossDiscipline);
    });

    test('should update existing trading plan successfully', async () => {
      const userId = mongoose.Types.ObjectId();
      await insertTradingPlans([{ ...tradingPlanOne, userId }]);

      const updateData = {
        maxTradesPerDay: 10,
        riskPercentPerTrade: 3.0,
        targetRiskRewardRatio: 2.0,
        preferredSessions: ['ASIA'],
        stopLossDiscipline: 'FLEXIBLE',
      };

      const result = await tradingPlanService.createOrUpdateTradingPlan(userId, updateData);

      expect(result).toBeDefined();
      expect(result.userId.toString()).toBe(userId.toString());
      expect(result.maxTradesPerDay).toBe(updateData.maxTradesPerDay);
      expect(result.riskPercentPerTrade).toBe(updateData.riskPercentPerTrade);
      expect(result.targetRiskRewardRatio).toBe(updateData.targetRiskRewardRatio);
      expect(result.preferredSessions.toObject()).toEqual(updateData.preferredSessions);
      expect(result.stopLossDiscipline).toBe(updateData.stopLossDiscipline);
      expect(result.id).toBeDefined();

      const dbTradingPlan = await TradingPlan.findOne({ userId });
      expect(dbTradingPlan).toBeDefined();
      expect(dbTradingPlan.userId.toString()).toBe(userId.toString());
      expect(dbTradingPlan.maxTradesPerDay).toBe(updateData.maxTradesPerDay);
      expect(dbTradingPlan.riskPercentPerTrade).toBe(updateData.riskPercentPerTrade);
      expect(dbTradingPlan.targetRiskRewardRatio).toBe(updateData.targetRiskRewardRatio);
      expect(dbTradingPlan.preferredSessions.toObject()).toEqual(updateData.preferredSessions);
      expect(dbTradingPlan.stopLossDiscipline).toBe(updateData.stopLossDiscipline);
    });
  });

  describe('getTradingPlanByUserId', () => {
    test('should return trading plan if found', async () => {
      const userId = mongoose.Types.ObjectId();
      await insertTradingPlans([{ ...tradingPlanOne, userId }]);

      const result = await tradingPlanService.getTradingPlanByUserId(userId);

      expect(result).toBeDefined();
      expect(result.userId.toString()).toBe(userId.toString());
      expect(result.maxTradesPerDay).toBe(tradingPlanOne.maxTradesPerDay);
      expect(result.riskPercentPerTrade).toBe(tradingPlanOne.riskPercentPerTrade);
      expect(result.targetRiskRewardRatio).toBe(tradingPlanOne.targetRiskRewardRatio);
      expect(result.preferredSessions.toObject()).toEqual(tradingPlanOne.preferredSessions);
      expect(result.stopLossDiscipline).toBe(tradingPlanOne.stopLossDiscipline);
      expect(result.id).toBeDefined();
    });

    test('should return null if trading plan not found', async () => {
      const userId = mongoose.Types.ObjectId();

      const result = await tradingPlanService.getTradingPlanByUserId(userId);

      expect(result).toBeNull();
    });
  });

  describe('deleteTradingPlanByUserId', () => {
    test('should delete trading plan successfully', async () => {
      const userId = mongoose.Types.ObjectId();
      await insertTradingPlans([{ ...tradingPlanOne, userId }]);

      await tradingPlanService.deleteTradingPlanByUserId(userId);

      const dbTradingPlan = await TradingPlan.findOne({ userId });
      expect(dbTradingPlan).toBeNull();
    });

    test('should throw ApiError if trading plan not found', async () => {
      const userId = mongoose.Types.ObjectId();

      await expect(tradingPlanService.deleteTradingPlanByUserId(userId)).rejects.toThrow(ApiError);
      await expect(tradingPlanService.deleteTradingPlanByUserId(userId)).rejects.toThrow('Trading plan not found');
    });
  });
});
