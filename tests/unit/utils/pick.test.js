const pick = require('../../../src/utils/pick');

describe('pick', () => {
  test('should pick specified keys from object', () => {
    const object = {
      name: 'John',
      age: 30,
      email: 'john@example.com',
      password: 'secret',
    };
    const keys = ['name', 'email'];

    const result = pick(object, keys);

    expect(result).toEqual({
      name: 'John',
      email: 'john@example.com',
    });
  });

  test('should return empty object when no keys are specified', () => {
    const object = {
      name: 'John',
      age: 30,
      email: 'john@example.com',
    };
    const keys = [];

    const result = pick(object, keys);

    expect(result).toEqual({});
  });

  test('should ignore keys that do not exist in object', () => {
    const object = {
      name: 'John',
      age: 30,
    };
    const keys = ['name', 'email', 'phone'];

    const result = pick(object, keys);

    expect(result).toEqual({
      name: 'John',
    });
  });

  test('should handle null object', () => {
    const object = null;
    const keys = ['name', 'email'];

    const result = pick(object, keys);

    expect(result).toEqual({});
  });

  test('should handle undefined object', () => {
    const object = undefined;
    const keys = ['name', 'email'];

    const result = pick(object, keys);

    expect(result).toEqual({});
  });

  test('should handle empty object', () => {
    const object = {};
    const keys = ['name', 'email'];

    const result = pick(object, keys);

    expect(result).toEqual({});
  });

  test('should handle object with inherited properties', () => {
    const parent = { inherited: 'value' };
    const object = Object.create(parent);
    object.own = 'property';
    const keys = ['own', 'inherited'];

    const result = pick(object, keys);

    expect(result).toEqual({
      own: 'property',
    });
  });

  test('should handle nested object values', () => {
    const object = {
      user: {
        name: 'John',
        age: 30,
      },
      settings: {
        theme: 'dark',
      },
      active: true,
    };
    const keys = ['user', 'active'];

    const result = pick(object, keys);

    expect(result).toEqual({
      user: {
        name: 'John',
        age: 30,
      },
      active: true,
    });
  });

  test('should handle array values', () => {
    const object = {
      tags: ['javascript', 'nodejs'],
      count: 5,
      items: [1, 2, 3],
    };
    const keys = ['tags', 'count'];

    const result = pick(object, keys);

    expect(result).toEqual({
      tags: ['javascript', 'nodejs'],
      count: 5,
    });
  });

  test('should handle duplicate keys in keys array', () => {
    const object = {
      name: 'John',
      age: 30,
      email: 'john@example.com',
    };
    const keys = ['name', 'age', 'name']; // duplicate 'name'

    const result = pick(object, keys);

    expect(result).toEqual({
      name: 'John',
      age: 30,
    });
  });
});
