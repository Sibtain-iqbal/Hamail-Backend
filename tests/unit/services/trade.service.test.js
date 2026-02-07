const mongoose = require('mongoose');
const { Trade } = require('../../../src/models');
const { tradeService } = require('../../../src/services');
const ApiError = require('../../../src/utils/ApiError');
const { tradeOne, tradeTwo, insertTrades } = require('../../fixtures/trade.fixture');
const setupTestDB = require('../../utils/setupTestDB');

setupTestDB();

describe('Trade service', () => {
  describe('createTrade', () => {
    let newTrade;

    beforeEach(() => {
      newTrade = {
        entryTime: new Date('2023-01-01T09:00:00Z'),
        exitTime: new Date('2023-01-01T10:30:00Z'),
        riskPercentUsed: 2.0,
        profitLoss: 150.0,
        riskRewardAchieved: 1.5,
        session: 'LONDON',
        stopLossHit: false,
        exitedEarly: false,
        targetPercentAchieved: 100.0,
        notes: 'Good trade setup',
      };
    });

    test('should create trade successfully', async () => {
      const userId = mongoose.Types.ObjectId();

      const result = await tradeService.createTrade(userId, newTrade);

      expect(result).toBeDefined();
      expect(result.userId.toString()).toBe(userId.toString());
      expect(result.entryTime.toISOString()).toBe(newTrade.entryTime.toISOString());
      expect(result.exitTime.toISOString()).toBe(newTrade.exitTime.toISOString());
      expect(result.riskPercentUsed).toBe(newTrade.riskPercentUsed);
      expect(result.profitLoss).toBe(newTrade.profitLoss);
      expect(result.riskRewardAchieved).toBe(newTrade.riskRewardAchieved);
      expect(result.session).toBe(newTrade.session);
      expect(result.stopLossHit).toBe(newTrade.stopLossHit);
      expect(result.exitedEarly).toBe(newTrade.exitedEarly);
      expect(result.targetPercentAchieved).toBe(newTrade.targetPercentAchieved);
      expect(result.notes).toBe(newTrade.notes);
      expect(result.id).toBeDefined();

      const dbTrade = await Trade.findById(result.id);
      expect(dbTrade).toBeDefined();
      expect(dbTrade.userId.toString()).toBe(userId.toString());
      expect(dbTrade.entryTime.toISOString()).toBe(newTrade.entryTime.toISOString());
      expect(dbTrade.exitTime.toISOString()).toBe(newTrade.exitTime.toISOString());
      expect(dbTrade.riskPercentUsed).toBe(newTrade.riskPercentUsed);
      expect(dbTrade.profitLoss).toBe(newTrade.profitLoss);
      expect(dbTrade.riskRewardAchieved).toBe(newTrade.riskRewardAchieved);
      expect(dbTrade.session).toBe(newTrade.session);
      expect(dbTrade.stopLossHit).toBe(newTrade.stopLossHit);
      expect(dbTrade.exitedEarly).toBe(newTrade.exitedEarly);
      expect(dbTrade.targetPercentAchieved).toBe(newTrade.targetPercentAchieved);
      expect(dbTrade.notes).toBe(newTrade.notes);
    });
  });

  describe('createBulkTrades', () => {
    let bulkTrades;

    beforeEach(() => {
      bulkTrades = [
        {
          entryTime: new Date('2023-01-01T09:00:00Z'),
          exitTime: new Date('2023-01-01T10:30:00Z'),
          riskPercentUsed: 2.0,
          profitLoss: 150.0,
          riskRewardAchieved: 1.5,
          session: 'LONDON',
          stopLossHit: false,
          exitedEarly: false,
          targetPercentAchieved: 100.0,
          notes: 'Good trade',
        },
        {
          entryTime: new Date('2023-01-02T14:00:00Z'),
          exitTime: new Date('2023-01-02T15:45:00Z'),
          riskPercentUsed: 1.5,
          profitLoss: -75.0,
          riskRewardAchieved: 0.0,
          session: 'NY',
          stopLossHit: true,
          exitedEarly: false,
          targetPercentAchieved: 0.0,
          notes: 'Stop loss hit',
        },
      ];
    });

    test('should create bulk trades successfully', async () => {
      const userId = mongoose.Types.ObjectId();

      const result = await tradeService.createBulkTrades(userId, bulkTrades);

      expect(result).toBeDefined();
      expect(result).toHaveLength(2);
      expect(result[0].userId.toString()).toBe(userId.toString());
      expect(result[1].userId.toString()).toBe(userId.toString());

      const dbTrades = await Trade.find({ userId });
      expect(dbTrades).toHaveLength(2);
    });
  });

  describe('queryTrades', () => {
    test('should return trades with pagination', async () => {
      const userId = mongoose.Types.ObjectId();
      await insertTrades([
        { ...tradeOne, userId },
        { ...tradeTwo, userId },
      ]);

      const filter = { userId };
      const options = { limit: 10, page: 1 };

      const result = await tradeService.queryTrades(filter, options);

      expect(result).toBeDefined();
      expect(result.results).toHaveLength(2);
      expect(result.page).toBe(1);
      expect(result.limit).toBe(10);
      expect(result.totalResults).toBe(2);
    });

    test('should apply filters correctly', async () => {
      const userId = mongoose.Types.ObjectId();
      await insertTrades([
        { ...tradeOne, userId },
        { ...tradeTwo, userId },
      ]);

      const filter = { userId, session: 'LONDON' };
      const options = { limit: 10, page: 1 };

      const result = await tradeService.queryTrades(filter, options);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].session).toBe('LONDON');
    });
  });

  describe('getTradeById', () => {
    test('should return trade if found', async () => {
      const userId = mongoose.Types.ObjectId();
      await insertTrades([{ ...tradeOne, userId }]);

      const result = await tradeService.getTradeById(tradeOne._id, userId);

      expect(result).toBeDefined();
      expect(result.userId.toString()).toBe(userId.toString());
      expect(result.entryTime.toISOString()).toBe(tradeOne.entryTime.toISOString());
      expect(result.exitTime.toISOString()).toBe(tradeOne.exitTime.toISOString());
      expect(result.riskPercentUsed).toBe(tradeOne.riskPercentUsed);
      expect(result.profitLoss).toBe(tradeOne.profitLoss);
      expect(result.riskRewardAchieved).toBe(tradeOne.riskRewardAchieved);
      expect(result.session).toBe(tradeOne.session);
      expect(result.stopLossHit).toBe(tradeOne.stopLossHit);
      expect(result.exitedEarly).toBe(tradeOne.exitedEarly);
      expect(result.targetPercentAchieved).toBe(tradeOne.targetPercentAchieved);
      expect(result.notes).toBe(tradeOne.notes);
      expect(result.id).toBeDefined();
    });

    test('should return null if trade not found', async () => {
      const userId = mongoose.Types.ObjectId();

      const result = await tradeService.getTradeById(tradeOne._id, userId);

      expect(result).toBeNull();
    });
  });

  describe('updateTradeById', () => {
    test('should update trade successfully', async () => {
      const userId = mongoose.Types.ObjectId();
      await insertTrades([{ ...tradeOne, userId }]);

      const updateData = {
        profitLoss: 200.0,
        notes: 'Updated notes',
      };

      const result = await tradeService.updateTradeById(tradeOne._id, userId, updateData);

      expect(result).toBeDefined();
      expect(result.profitLoss).toBe(updateData.profitLoss);
      expect(result.notes).toBe(updateData.notes);
      expect(result.id).toBeDefined();

      const dbTrade = await Trade.findById(tradeOne._id);
      expect(dbTrade.profitLoss).toBe(updateData.profitLoss);
      expect(dbTrade.notes).toBe(updateData.notes);
    });

    test('should throw ApiError if trade not found', async () => {
      const userId = mongoose.Types.ObjectId();
      const updateData = { profitLoss: 200.0 };

      await expect(tradeService.updateTradeById(tradeOne._id, userId, updateData)).rejects.toThrow(ApiError);
      await expect(tradeService.updateTradeById(tradeOne._id, userId, updateData)).rejects.toThrow('Trade not found');
    });
  });

  describe('deleteTradeById', () => {
    test('should delete trade successfully', async () => {
      const userId = mongoose.Types.ObjectId();
      await insertTrades([{ ...tradeOne, userId }]);

      await tradeService.deleteTradeById(tradeOne._id, userId);

      const dbTrade = await Trade.findById(tradeOne._id);
      expect(dbTrade).toBeNull();
    });

    test('should throw ApiError if trade not found', async () => {
      const userId = mongoose.Types.ObjectId();

      await expect(tradeService.deleteTradeById(tradeOne._id, userId)).rejects.toThrow(ApiError);
      await expect(tradeService.deleteTradeById(tradeOne._id, userId)).rejects.toThrow('Trade not found');
    });
  });
});
