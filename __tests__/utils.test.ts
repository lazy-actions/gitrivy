import { isIterable } from '../src/utils';

describe('isIterable', () => {
  test.each([
    ['test', true],
    [[], true],
    [['this', 'is', 'test'], true],
    [{ id: 'test' }, false],
  ])('input %s', (obj, expected) => {
    expect(isIterable(obj)).toBe(expected);
  });
});
