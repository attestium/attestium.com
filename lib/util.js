/**
 * Attestium - shared utilities
 *
 * Canonical JSON, hashing helpers, and strict input validation used by
 * every other module.  Nothing in here touches the network or spawns
 * processes.
 *
 * @license MIT
 */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

/**
 * Serialize a value to canonical JSON: object keys sorted by UTF-16 code
 * units (as Array.prototype.sort() compares strings; this differs from code
 * point order above U+FFFF), no insignificant whitespace.  Two structurally
 * equal values always produce the same string, which makes the output safe
 * to hash and sign.
 *
 * Supported: null, booleans, finite numbers, strings, arrays and plain
 * objects.  Object properties whose value is `undefined` are omitted (as
 * with JSON.stringify).  Anything else throws a TypeError instead of being
 * silently coerced, so a signature can never cover an ambiguous encoding.
 *
 * @param {*} value
 * @returns {string}
 */
function canonicalize(value) {
  if (value === null) {
    return 'null';
  }

  switch (typeof value) {
    case 'boolean': {
      return value ? 'true' : 'false';
    }

    case 'number': {
      if (!Number.isFinite(value)) {
        throw new TypeError('Cannot canonicalize a non-finite number');
      }

      return JSON.stringify(value);
    }

    case 'string': {
      return JSON.stringify(value);
    }

    case 'object': {
      if (Array.isArray(value)) {
        // Array.from visits holes (as undefined); map would skip them.
        return `[${Array.from(value, item => {
          if (item === undefined) {
            throw new TypeError('Cannot canonicalize undefined inside an array');
          }

          return canonicalize(item);
        }).join(',')}]`;
      }

      if (!isPlainObject(value)) {
        throw new TypeError('Cannot canonicalize a non-plain object');
      }

      const keys = Object.keys(value).filter(key => value[key] !== undefined).sort();
      return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
    }

    default: {
      throw new TypeError(`Cannot canonicalize a value of type ${typeof value}`);
    }
  }
}

/**
 * @param {*} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  if (value === null || typeof value !== 'object') {
    return false;
  }

  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * SHA-256 hex digest.
 * @param {string|Buffer|Uint8Array} data
 * @returns {string}
 */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * SHA-256 hex digest of the canonical JSON encoding of a value.
 * @param {*} value
 * @returns {string}
 */
function digestOf(value) {
  return sha256(canonicalize(value));
}

/**
 * Constant-time comparison of two strings (e.g. hex digests).
 * Returns false for non-strings or different lengths.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);
  if (bufferA.length !== bufferB.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufferA, bufferB);
}

/**
 * Validate and normalize a process id.  Accepts a positive integer (as a
 * number or a decimal string) or the literal "self".  Anything else throws,
 * which keeps untrusted input out of /proc paths and command arguments.
 *
 * @param {string|number} pid
 * @returns {string}
 */
function normalizePid(pid) {
  if (pid === 'self') {
    return 'self';
  }

  const text = String(pid);
  if (!/^[1-9]\d{0,9}$/.test(text) || Number(text) > 4_294_967_295) {
    throw new TypeError(`Invalid process id: ${JSON.stringify(text).slice(0, 40)}`);
  }

  return text;
}

/**
 * Validate a nonce supplied by a verifier: 16-64 bytes, hex encoded.
 *
 * @param {string} nonce
 * @returns {string} lower-case hex nonce
 */
function normalizeNonce(nonce) {
  if (typeof nonce !== 'string' || !/^(?:[\da-fA-F]{2}){16,64}$/.test(nonce)) {
    throw new TypeError('Nonce must be 16 to 64 bytes of hex');
  }

  return nonce.toLowerCase();
}

/**
 * Generate a random nonce (hex).
 * @param {number} [bytes=32]
 * @returns {string}
 */
function generateNonce(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Run async task thunks with a concurrency limit, preserving order.
 *
 * @template T
 * @param {Array<() => Promise<T>>} tasks
 * @param {number} concurrency
 * @returns {Promise<T[]>}
 */
async function parallelMap(tasks, concurrency) {
  const results = Array.from({length: tasks.length});
  let next = 0;
  const worker = async () => {
    while (next < tasks.length) {
      const index = next++;
      results[index] = await tasks[index]();
    }
  };

  const workers = [];
  for (let i = 0; i < Math.max(1, Math.min(concurrency, tasks.length)); i++) {
    workers.push(worker());
  }

  await Promise.all(workers);
  return results;
}

/**
 * Whether a path exists, by stat().  fs.existsSync() uses access(), which
 * Linux checks with the real user and without file capabilities, so a
 * process granted CAP_DAC_READ_SEARCH through its executable would be told
 * that files it can read do not exist.
 *
 * @param {string} file
 * @returns {boolean}
 */
function exists(file) {
  try {
    fs.statSync(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * Set an own property, even one named __proto__ (a file can have that
 * name; a plain assignment would change the object's prototype instead).
 *
 * @param {Object} object
 * @param {string} key
 * @param {*} value
 */
function setOwn(object, key, value) {
  Object.defineProperty(object, key, {
    value, enumerable: true, writable: true, configurable: true,
  });
}

module.exports = {
  setOwn,
  exists,
  canonicalize,
  isPlainObject,
  sha256,
  digestOf,
  safeEqual,
  normalizePid,
  normalizeNonce,
  generateNonce,
  parallelMap,
};
