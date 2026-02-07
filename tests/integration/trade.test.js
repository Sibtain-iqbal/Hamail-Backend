const request = require('supertest');
const httpStatus = require('http-status');
const app = require('../../src/app');
const setupTestDB = require('../utils/setupTestDB');
const { Trade } = require('../../src/models');
const { userOne, insertUsers } = require('../fixtures/user.fixture');
const { userOneAccessToken } = require('../fixtures/token.fixture');
const { tradeOne, tradeTwo, insertTrades } = require('../fixtures/trade.fixture');

setupTestDB();

jest.setTimeout(10000);

describe('Trade routes', () => {
  describe('POST /v1/trades', () => {
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

    test('should return 201 and successfully create new trade if data is ok', async () => {
      await insertUsers([userOne]);

      const res = await request(app)
        .post('/v1/trades')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTrade)
        .expect(httpStatus.CREATED);

      expect(res.body).toEqual({
        id: expect.anything(),
        userId: userOne._id.toHexString(),
        entryTime: newTrade.entryTime.toISOString(),
        exitTime: newTrade.exitTime.toISOString(),
        riskPercentUsed: newTrade.riskPercentUsed,
        profitLoss: newTrade.profitLoss,
        riskRewardAchieved: newTrade.riskRewardAchieved,
        session: newTrade.session,
        stopLossHit: newTrade.stopLossHit,
        exitedEarly: newTrade.exitedEarly,
        targetPercentAchieved: newTrade.targetPercentAchieved,
        notes: newTrade.notes,
      });

      const dbTrade = await Trade.findById(res.body.id);
      expect(dbTrade).toBeDefined();
      expect(dbTrade.userId.toString()).toBe(userOne._id.toString());
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

    test('should return 401 error if access token is missing', async () => {
      await request(app).post('/v1/trades').send(newTrade).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 400 error if required fields are missing', async () => {
      await insertUsers([userOne]);
      const incompleteTrade = { entryTime: new Date() };

      await request(app)
        .post('/v1/trades')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(incompleteTrade)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if session is invalid', async () => {
      await insertUsers([userOne]);
      newTrade.session = 'INVALID';

      await request(app)
        .post('/v1/trades')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTrade)
        .expect(httpStatus.BAD_REQUEST);
    });

    test('should return 400 error if riskPercentUsed is negative', async () => {
      await insertUsers([userOne]);
      newTrade.riskPercentUsed = -1;

      await request(app)
        .post('/v1/trades')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(newTrade)
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('POST /v1/trades/bulk', () => {
    let bulkTrades;

    beforeEach(() => {
      bulkTrades = {
        trades: [
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
        ],
      };
    });

    test('should return 201 and successfully create bulk trades if data is ok', async () => {
      await insertUsers([userOne]);

      const res = await request(app)
        .post('/v1/trades/bulk')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(bulkTrades)
        .expect(httpStatus.CREATED);

      expect(res.body).toHaveProperty('trades');
      expect(res.body).toHaveProperty('count', 2);
      expect(res.body.trades).toHaveLength(2);

      const dbTrades = await Trade.find({ userId: userOne._id });
      expect(dbTrades).toHaveLength(2);
    });

    test('should return 401 error if access token is missing', async () => {
      await request(app).post('/v1/trades/bulk').send(bulkTrades).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 400 error if trades array is empty', async () => {
      await insertUsers([userOne]);
      const emptyBulkTrades = { trades: [] };

      await request(app)
        .post('/v1/trades/bulk')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(emptyBulkTrades)
        .expect(httpStatus.BAD_REQUEST);
    });
  });

  describe('GET /v1/trades', () => {
    test('should return 200 and apply the default query options', async () => {
      await insertUsers([userOne]);
      await insertTrades([
        { ...tradeOne, userId: userOne._id },
        { ...tradeTwo, userId: userOne._id },
      ]);

      const res = await request(app)
        .get('/v1/trades')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        results: expect.any(Array),
        page: 1,
        limit: 10,
        totalPages: 1,
        totalResults: 2,
      });
      expect(res.body.results).toHaveLength(2);
    });

    test('should return 401 error if access token is missing', async () => {
      await request(app).get('/v1/trades').send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should correctly apply filter on session field', async () => {
      await insertUsers([userOne]);
      await insertTrades([
        { ...tradeOne, userId: userOne._id },
        { ...tradeTwo, userId: userOne._id },
      ]);

      const res = await request(app)
        .get('/v1/trades')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .query({ session: 'LONDON' })
        .send()
        .expect(httpStatus.OK);

      expect(res.body.results).toHaveLength(1);
      expect(res.body.results[0].session).toBe('LONDON');
    });

    test('should correctly apply filter on stopLossHit field', async () => {
      await insertUsers([userOne]);
      await insertTrades([
        { ...tradeOne, userId: userOne._id },
        { ...tradeTwo, userId: userOne._id },
      ]);

      const res = await request(app)
        .get('/v1/trades')
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .query({ stopLossHit: true })
        .send()
        .expect(httpStatus.OK);

      expect(res.body.results).toHaveLength(1);
      expect(res.body.results[0].stopLossHit).toBe(true);
    });
  });

  describe('GET /v1/trades/:tradeId', () => {
    test('should return 200 and the trade object if data is ok', async () => {
      await insertUsers([userOne]);
      await insertTrades([{ ...tradeOne, userId: userOne._id }]);

      const res = await request(app)
        .get(`/v1/trades/${tradeOne._id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        id: tradeOne._id.toHexString(),
        userId: userOne._id.toHexString(),
        entryTime: tradeOne.entryTime.toISOString(),
        exitTime: tradeOne.exitTime.toISOString(),
        riskPercentUsed: tradeOne.riskPercentUsed,
        profitLoss: tradeOne.profitLoss,
        riskRewardAchieved: tradeOne.riskRewardAchieved,
        session: tradeOne.session,
        stopLossHit: tradeOne.stopLossHit,
        exitedEarly: tradeOne.exitedEarly,
        targetPercentAchieved: tradeOne.targetPercentAchieved,
        notes: tradeOne.notes,
      });
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);
      await insertTrades([{ ...tradeOne, userId: userOne._id }]);

      await request(app).get(`/v1/trades/${tradeOne._id}`).send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 404 error if trade is not found', async () => {
      await insertUsers([userOne]);

      await request(app)
        .get(`/v1/trades/${tradeOne._id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('PUT /v1/trades/:tradeId', () => {
    test('should return 200 and successfully update trade if data is ok', async () => {
      await insertUsers([userOne]);
      await insertTrades([{ ...tradeOne, userId: userOne._id }]);
      const updateBody = {
        profitLoss: 200.0,
        notes: 'Updated notes',
      };

      const res = await request(app)
        .put(`/v1/trades/${tradeOne._id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.OK);

      expect(res.body).toEqual({
        id: tradeOne._id.toHexString(),
        userId: userOne._id.toHexString(),
        entryTime: tradeOne.entryTime.toISOString(),
        exitTime: tradeOne.exitTime.toISOString(),
        riskPercentUsed: tradeOne.riskPercentUsed,
        profitLoss: updateBody.profitLoss,
        riskRewardAchieved: tradeOne.riskRewardAchieved,
        session: tradeOne.session,
        stopLossHit: tradeOne.stopLossHit,
        exitedEarly: tradeOne.exitedEarly,
        targetPercentAchieved: tradeOne.targetPercentAchieved,
        notes: updateBody.notes,
      });

      const dbTrade = await Trade.findById(tradeOne._id);
      expect(dbTrade).toBeDefined();
      expect(dbTrade.profitLoss).toBe(updateBody.profitLoss);
      expect(dbTrade.notes).toBe(updateBody.notes);
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);
      await insertTrades([{ ...tradeOne, userId: userOne._id }]);
      const updateBody = { profitLoss: 200.0 };

      await request(app).put(`/v1/trades/${tradeOne._id}`).send(updateBody).expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 404 error if trade is not found', async () => {
      await insertUsers([userOne]);
      const updateBody = { profitLoss: 200.0 };

      await request(app)
        .put(`/v1/trades/${tradeOne._id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send(updateBody)
        .expect(httpStatus.NOT_FOUND);
    });
  });

  describe('DELETE /v1/trades/:tradeId', () => {
    test('should return 204 if data is ok', async () => {
      await insertUsers([userOne]);
      await insertTrades([{ ...tradeOne, userId: userOne._id }]);

      await request(app)
        .delete(`/v1/trades/${tradeOne._id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.NO_CONTENT);

      const dbTrade = await Trade.findById(tradeOne._id);
      expect(dbTrade).toBeNull();
    });

    test('should return 401 error if access token is missing', async () => {
      await insertUsers([userOne]);
      await insertTrades([{ ...tradeOne, userId: userOne._id }]);

      await request(app).delete(`/v1/trades/${tradeOne._id}`).send().expect(httpStatus.UNAUTHORIZED);
    });

    test('should return 404 error if trade is not found', async () => {
      await insertUsers([userOne]);

      await request(app)
        .delete(`/v1/trades/${tradeOne._id}`)
        .set('Authorization', `Bearer ${userOneAccessToken}`)
        .send()
        .expect(httpStatus.NOT_FOUND);
    });
  });
});
