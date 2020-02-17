export function isIterable(obj: Object): Boolean {
  return obj != null && typeof obj[Symbol.iterator] === 'function';
}
