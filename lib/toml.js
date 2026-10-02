/**
 * Attestium - TOML reader
 *
 * Enough of TOML 1.0 for lockfiles and manifests (uv.lock, poetry.lock,
 * pylock.toml, Cargo.lock, pyproject.toml): tables, arrays of tables,
 * dotted and quoted keys, inline tables, arrays, all string forms,
 * integers, floats and booleans.  Dates and times are returned as strings.
 * Redefinitions are errors, as the specification requires.
 *
 * @license MIT
 */

'use strict';

const {setOwn} = require('./util');

class TomlError extends Error {
  constructor(message, line) {
    super(`TOML: ${message} (line ${line})`);
    this.name = 'TomlError';
  }
}

const BARE_KEY = /[\w-]/;
const DATE = /^\d{4}-\d{2}-\d{2}(?:[t ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:z|[+-]\d{2}:\d{2})?)?|^\d{2}:\d{2}:\d{2}(?:\.\d+)?/i;

/**
 * Parse a TOML document.
 * @param {string} text
 * @returns {Object}
 */
function parseToml(text) {
  let index = 0;
  let line = 1;
  const root = Object.create(null);
  // Tables created by a header or dotted key, and inline tables, may not be
  // extended later; arrays of tables are tracked by their array.
  const defined = new Set();
  const frozen = new Set();
  let current = root;

  const peek = (offset = 0) => text[index + offset];
  const fail = message => {
    throw new TomlError(message, line);
  };

  const skipWhitespace = () => {
    while (peek() === ' ' || peek() === '\t') {
      index++;
    }
  };

  const skipComment = () => {
    if (peek() === '#') {
      while (index < text.length && peek() !== '\n') {
        index++;
      }
    }
  };

  const skipBlank = () => {
    // Whitespace, comments and newlines (inside arrays).
    for (;;) {
      skipWhitespace();
      skipComment();
      if (peek() === '\n') {
        index++;
        line++;
      } else if (peek() === '\r' && peek(1) === '\n') {
        index += 2;
        line++;
      } else {
        return;
      }
    }
  };

  const expectLineEnd = () => {
    skipWhitespace();
    skipComment();
    if (index < text.length) {
      if (peek() === '\n') {
        index++;
        line++;
      } else if (peek() === '\r' && peek(1) === '\n') {
        index += 2;
        line++;
      } else {
        fail(`unexpected ${JSON.stringify(peek())}`);
      }
    }
  };

  const escape = () => {
    const char = text[++index];
    index++;
    switch (char) {
      case 'b': {
        return '\b';
      }

      case 't': {
        return '\t';
      }

      case 'n': {
        return '\n';
      }

      case 'f': {
        return '\f';
      }

      case 'r': {
        return '\r';
      }

      case '"': {
        return '"';
      }

      case '\\': {
        return '\\';
      }

      case 'u':
      case 'U': {
        const length = char === 'u' ? 4 : 8;
        const hex = text.slice(index, index + length);
        if (!/^[\da-fA-F]+$/.test(hex) || hex.length !== length) {
          fail('invalid unicode escape');
        }

        index += length;
        return String.fromCodePoint(Number.parseInt(hex, 16));
      }

      default: {
        return fail(`invalid escape \\${char}`);
      }
    }
  };

  const parseString = () => {
    const quote = peek();
    const multi = text.startsWith(quote.repeat(3), index);
    const literal = quote === '\'';
    let value = '';
    if (multi) {
      index += 3;
      // A newline right after the opening delimiter is trimmed.
      if (peek() === '\n') {
        index++;
        line++;
      } else if (peek() === '\r' && peek(1) === '\n') {
        index += 2;
        line++;
      }

      for (;;) {
        if (index >= text.length) {
          fail('unterminated string');
        }

        if (text.startsWith(quote.repeat(3), index)) {
          // Up to two quotes may end the content before the delimiter.
          let extra = 0;
          while (text[index + 3 + extra] === quote && extra < 2) {
            extra++;
          }

          value += quote.repeat(extra);
          index += 3 + extra;
          return value;
        }

        const char = peek();
        if (!literal && char === '\\') {
          // A backslash at the end of a line trims the newline and leading whitespace.
          let ahead = index + 1;
          while (text[ahead] === ' ' || text[ahead] === '\t') {
            ahead++;
          }

          if (text[ahead] === '\n' || (text[ahead] === '\r' && text[ahead + 1] === '\n')) {
            index = ahead;
            while (/\s/.test(peek() || '')) {
              if (peek() === '\n') {
                line++;
              }

              index++;
            }

            continue;
          }

          value += escape();
          continue;
        }

        if (char === '\n') {
          line++;
        }

        value += char;
        index++;
      }
    }

    index++;
    for (;;) {
      const char = peek();
      if (char === undefined || char === '\n') {
        fail('unterminated string');
      }

      if (char === quote) {
        index++;
        return value;
      }

      if (!literal && char === '\\') {
        value += escape();
      } else {
        value += char;
        index++;
      }
    }
  };

  const parseKey = () => {
    const parts = [];
    for (;;) {
      skipWhitespace();
      if (peek() === '"' || peek() === '\'') {
        parts.push(parseString());
      } else {
        const start = index;
        while (index < text.length && BARE_KEY.test(peek())) {
          index++;
        }

        if (start === index) {
          fail('expected a key');
        }

        parts.push(text.slice(start, index));
      }

      skipWhitespace();
      if (peek() !== '.') {
        return parts;
      }

      index++;
    }
  };

  const parseNumberOrDate = () => {
    const rest = text.slice(index);
    const date = rest.match(DATE);
    if (date && /^\d{4}-|^\d{2}:/.test(rest)) {
      index += date[0].length;
      return date[0];
    }

    const token = rest.match(/^[+-]?(?:0x[\da-fA-F_]+|0o[0-7_]+|0b[01_]+|inf|nan|[\d_]+(?:\.[\d_]+)?(?:[eE][+-]?[\d_]+)?)/);
    if (!token) {
      return fail(`invalid value starting ${JSON.stringify(rest.slice(0, 10))}`);
    }

    index += token[0].length;
    const raw = token[0].replaceAll('_', '');
    if (raw.endsWith('inf')) {
      return raw.startsWith('-') ? -Infinity : Infinity;
    }

    if (raw.endsWith('nan')) {
      return Number.NaN;
    }

    if (/^[+-]?0[xob]/.test(raw)) {
      const sign = raw.startsWith('-') ? -1 : 1;
      const body = raw.replace(/^[+-]/, '');
      return sign * Number.parseInt(body.slice(2), {x: 16, o: 8, b: 2}[body[1]]);
    }

    return Number(raw);
  };

  const parseValue = () => {
    const char = peek();
    if (char === '"' || char === '\'') {
      return parseString();
    }

    if (char === '[') {
      index++;
      const array = [];
      for (;;) {
        skipBlank();
        if (peek() === ']') {
          index++;
          return array;
        }

        array.push(parseValue());
        skipBlank();
        if (peek() === ',') {
          index++;
        } else if (peek() === ']') {
          index++;
          return array;
        } else {
          fail('expected , or ] in array');
        }
      }
    }

    if (char === '{') {
      index++;
      const table = Object.create(null);
      const inlineDefined = new Set();
      skipWhitespace();
      if (peek() === '}') {
        index++;
        frozen.add(table);
        return table;
      }

      for (;;) {
        const key = parseKey();
        skipWhitespace();
        if (peek() !== '=') {
          fail('expected = in inline table');
        }

        index++;
        skipWhitespace();
        assign(table, key, parseValue(), inlineDefined);
        skipWhitespace();
        if (peek() === ',') {
          index++;
          skipWhitespace();
        } else if (peek() === '}') {
          index++;
          frozen.add(table);
          return table;
        } else {
          fail('expected , or } in inline table');
        }
      }
    }

    if (text.startsWith('true', index)) {
      index += 4;
      return true;
    }

    if (text.startsWith('false', index)) {
      index += 5;
      return false;
    }

    return parseNumberOrDate();
  };

  const isTable = value => value !== null && typeof value === 'object' && !Array.isArray(value);

  function assign(table, key, value, implicit) {
    let target = table;
    for (const part of key.slice(0, -1)) {
      if (target[part] === undefined) {
        target[part] = Object.create(null);
        implicit.add(target[part]);
      } else if (!isTable(target[part]) || frozen.has(target[part]) || (!implicit.has(target[part]) && defined.has(target[part]))) {
        fail(`cannot extend ${key.join('.')}`);
      }

      target = target[part];
    }

    const last = key.at(-1);
    if (last in target) {
      fail(`duplicate key ${key.join('.')}`);
    }

    target[last] = value;
  }

  // Tables created by dotted keys outside inline tables.
  const implicitKeys = new Set();
  const openTable = (key, isArray) => {
    let target = root;
    for (const [position, part] of key.entries()) {
      const lastPart = position === key.length - 1;
      if (lastPart && isArray) {
        if (target[part] === undefined) {
          target[part] = [];
        } else if (!Array.isArray(target[part]) || frozen.has(target[part])) {
          fail(`cannot redefine ${key.join('.')} as an array of tables`);
        }

        const entry = Object.create(null);
        target[part].push(entry);
        return entry;
      }

      if (target[part] === undefined) {
        target[part] = Object.create(null);
      } else if (Array.isArray(target[part]) && !frozen.has(target[part])) {
        target = target[part].at(-1);
        continue;
      } else if (!isTable(target[part]) || frozen.has(target[part])) {
        fail(`cannot redefine ${key.join('.')}`);
      } else if (lastPart && (defined.has(target[part]) || implicitKeys.has(target[part]))) {
        // Defined by an earlier header or by dotted keys.
        fail(`table ${key.join('.')} is defined twice`);
      }

      target = target[part];
    }

    defined.add(target);
    return target;
  };

  while (index < text.length) {
    skipBlank();
    if (index >= text.length) {
      break;
    }

    if (peek() === '[') {
      const isArray = peek(1) === '[';
      index += isArray ? 2 : 1;
      const key = parseKey();
      if (!text.startsWith(isArray ? ']]' : ']', index)) {
        fail('expected ] after table name');
      }

      index += isArray ? 2 : 1;
      current = openTable(key, isArray);
      expectLineEnd();
      continue;
    }

    const key = parseKey();
    skipWhitespace();
    if (peek() !== '=') {
      fail('expected =');
    }

    index++;
    skipWhitespace();
    const value = parseValue();
    if (Array.isArray(value)) {
      // A static array cannot be extended by [[...]] or entered by [...].
      frozen.add(value);
    }

    assign(current, key, value, implicitKeys);
    expectLineEnd();
  }

  return toPlain(root);
}

/**
 * Convert null-prototype objects to ordinary ones.
 */
function toPlain(value) {
  if (Array.isArray(value)) {
    return value.map(item => toPlain(item));
  }

  if (value !== null && typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      // A key named __proto__ is a key, not the object's prototype.
      setOwn(result, key, toPlain(item));
    }

    return result;
  }

  return value;
}

module.exports = {parseToml, TomlError};
