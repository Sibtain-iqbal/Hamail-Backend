const mongoose = require('mongoose');
const { StateAnalysis } = require('../../../src/models');
const { PsychologicalState } = require('../../../src/models/enums');
const setupTestDB = require('../../utils/setupTestDB');

setupTestDB();

describe('StateAnalysis model', () => {
  let stateAnalysisData;

  beforeEach(() => {
    stateAnalysisData = {
      userId: mongoose.Types.ObjectId(),
      state: PsychologicalState.CONFIDENT,
      confidence: 75,
      indicators: [
        {
          category: 'Win Rate',
          message: 'High win rate indicates confidence',
          severity: 'positive',
          value: 80,
        },
        {
          category: 'Risk Management',
          message: 'Good risk management',
          severity: 'positive',
          value: 85,
        },
      ],
      recommendations: ['Continue current trading approach', 'Consider increasing position size gradually'],
      metadata: {
        tradeCount: 20,
        analysisDate: new Date(),
        version: '1.0',
      },
    };
  });

  test('should create state analysis successfully', async () => {
    const stateAnalysis = new StateAnalysis(stateAnalysisData);
    const savedStateAnalysis = await stateAnalysis.save();

    expect(savedStateAnalysis._id).toBeDefined();
    expect(savedStateAnalysis.userId.toString()).toBe(stateAnalysisData.userId.toString());
    expect(savedStateAnalysis.state).toBe(stateAnalysisData.state);
    expect(savedStateAnalysis.confidence).toBe(stateAnalysisData.confidence);
    expect(savedStateAnalysis.indicators).toHaveLength(2);
    expect(savedStateAnalysis.recommendations).toEqual(stateAnalysisData.recommendations);
    expect(savedStateAnalysis.metadata).toEqual(stateAnalysisData.metadata);
    expect(savedStateAnalysis.createdAt).toBeDefined();
    expect(savedStateAnalysis.updatedAt).toBeDefined();
  });

  test('should require userId', async () => {
    delete stateAnalysisData.userId;
    const stateAnalysis = new StateAnalysis(stateAnalysisData);

    await expect(stateAnalysis.save()).rejects.toThrow();
  });

  test('should require state', async () => {
    delete stateAnalysisData.state;
    const stateAnalysis = new StateAnalysis(stateAnalysisData);

    await expect(stateAnalysis.save()).rejects.toThrow();
  });

  test('should require confidence', async () => {
    delete stateAnalysisData.confidence;
    const stateAnalysis = new StateAnalysis(stateAnalysisData);

    await expect(stateAnalysis.save()).rejects.toThrow();
  });

  test('should validate state enum values', async () => {
    stateAnalysisData.state = 'INVALID_STATE';
    const stateAnalysis = new StateAnalysis(stateAnalysisData);

    await expect(stateAnalysis.save()).rejects.toThrow();
  });

  test('should validate confidence range', async () => {
    stateAnalysisData.confidence = 150;
    const stateAnalysis = new StateAnalysis(stateAnalysisData);

    await expect(stateAnalysis.save()).rejects.toThrow();
  });

  test('should validate confidence minimum value', async () => {
    stateAnalysisData.confidence = -10;
    const stateAnalysis = new StateAnalysis(stateAnalysisData);

    await expect(stateAnalysis.save()).rejects.toThrow();
  });

  test('should allow all psychological states', async () => {
    Object.values(PsychologicalState).forEach(async (state) => {
      stateAnalysisData.state = state;
      const stateAnalysis = new StateAnalysis(stateAnalysisData);
      const savedStateAnalysis = await stateAnalysis.save();

      expect(savedStateAnalysis.state).toBe(state);
    });
  });

  test('should validate indicator severity enum', async () => {
    stateAnalysisData.indicators[0].severity = 'invalid';
    const stateAnalysis = new StateAnalysis(stateAnalysisData);

    await expect(stateAnalysis.save()).rejects.toThrow();
  });

  test('should allow all indicator severities', async () => {
    const severities = ['positive', 'neutral', 'warning', 'critical'];

    severities.forEach(async (severity) => {
      stateAnalysisData.indicators[0].severity = severity;
      const stateAnalysis = new StateAnalysis(stateAnalysisData);
      const savedStateAnalysis = await stateAnalysis.save();

      expect(savedStateAnalysis.indicators[0].severity).toBe(severity);
    });
  });

  test('should allow empty indicators array', async () => {
    stateAnalysisData.indicators = [];
    const stateAnalysis = new StateAnalysis(stateAnalysisData);
    const savedStateAnalysis = await stateAnalysis.save();

    expect(savedStateAnalysis.indicators).toEqual([]);
  });

  test('should allow empty recommendations array', async () => {
    stateAnalysisData.recommendations = [];
    const stateAnalysis = new StateAnalysis(stateAnalysisData);
    const savedStateAnalysis = await stateAnalysis.save();

    expect(savedStateAnalysis.recommendations).toEqual([]);
  });

  test('should allow optional metadata', async () => {
    delete stateAnalysisData.metadata;
    const stateAnalysis = new StateAnalysis(stateAnalysisData);
    const savedStateAnalysis = await stateAnalysis.save();

    expect(savedStateAnalysis.metadata).toBeUndefined();
  });

  test('should handle complex metadata', async () => {
    stateAnalysisData.metadata = {
      tradeCount: 50,
      analysisDate: new Date(),
      version: '2.0',
      customField: 'custom value',
      nested: {
        level1: {
          level2: 'deep value',
        },
      },
    };

    const stateAnalysis = new StateAnalysis(stateAnalysisData);
    const savedStateAnalysis = await stateAnalysis.save();

    expect(savedStateAnalysis.metadata).toEqual(stateAnalysisData.metadata);
  });

  test('should have toJSON plugin applied', async () => {
    const stateAnalysis = new StateAnalysis(stateAnalysisData);
    const savedStateAnalysis = await stateAnalysis.save();
    const json = savedStateAnalysis.toJSON();

    expect(json).not.toHaveProperty('_id');
    expect(json).not.toHaveProperty('__v');
    expect(json).toHaveProperty('id');
    expect(json.id).toBe(savedStateAnalysis._id.toString());
  });

  test('should have proper indexes', async () => {
    const indexes = StateAnalysis.collection.getIndexes();
    expect(indexes).toHaveProperty('userId_1');
    expect(indexes).toHaveProperty('state_1');
  });

  test('should handle edge case confidence values', async () => {
    const edgeCases = [0, 50, 100];

    edgeCases.forEach(async (confidence) => {
      stateAnalysisData.confidence = confidence;
      const stateAnalysis = new StateAnalysis(stateAnalysisData);
      const savedStateAnalysis = await stateAnalysis.save();

      expect(savedStateAnalysis.confidence).toBe(confidence);
    });
  });

  test('should handle multiple indicators', async () => {
    stateAnalysisData.indicators = [
      {
        category: 'Win Rate',
        message: 'High win rate',
        severity: 'positive',
        value: 80,
      },
      {
        category: 'Risk Management',
        message: 'Good risk management',
        severity: 'positive',
        value: 85,
      },
      {
        category: 'Emotional Control',
        message: 'Needs improvement',
        severity: 'warning',
        value: 60,
      },
    ];

    const stateAnalysis = new StateAnalysis(stateAnalysisData);
    const savedStateAnalysis = await stateAnalysis.save();

    expect(savedStateAnalysis.indicators).toHaveLength(3);
    expect(savedStateAnalysis.indicators[0].category).toBe('Win Rate');
    expect(savedStateAnalysis.indicators[1].category).toBe('Risk Management');
    expect(savedStateAnalysis.indicators[2].category).toBe('Emotional Control');
  });

  test('should handle indicators without values', async () => {
    stateAnalysisData.indicators[0].value = undefined;
    const stateAnalysis = new StateAnalysis(stateAnalysisData);
    const savedStateAnalysis = await stateAnalysis.save();

    expect(savedStateAnalysis.indicators[0].value).toBeUndefined();
  });
});
