/**
 * Attestium - JSON Schema validation (the subset the evidence format uses)
 *
 * Evidence comes from the machine being audited, so a verifier checks its
 * shape before using any field.  The evidence format is published as a JSON
 * Schema (../schema/evidence.schema.json); this validator implements the
 * keywords that schema uses, so the published schema is also the check:
 *
 *   type (string, number, integer, boolean, object, array, null, or a list),
 *   properties, required, additionalProperties (boolean or schema),
 *   patternProperties, propertyNames, items, minItems, maxItems, enum,
 *   const, pattern, minLength, maxLength, minimum, maximum, anyOf, oneOf,
 *   $ref (local, "#/$defs/..."), $defs, and contentEncoding "base64" as an
 *   assertion (the length a multiple of 4, which no pattern can check in
 *   linear time without backtracking on every 4 characters; the pattern
 *   checks the alphabet and the padding)
 *
 * Unknown keywords are errors, so the schema cannot silently skip a check.
 *
 * @license MIT
 */

'use strict';

const KNOWN = new Set([
  '$schema',
  '$id',
  '$ref',
  '$defs',
  '$comment',
  'title',
  'description',
  'type',
  'properties',
  'required',
  'additionalProperties',
  'patternProperties',
  'propertyNames',
  'items',
  'minItems',
  'maxItems',
  'enum',
  'const',
  'pattern',
  'contentEncoding',
  'minLength',
  'maxLength',
  'minimum',
  'maximum',
  'anyOf',
  'oneOf',
  'examples',
  'default',
]);

const typeOf = value => {
  if (value === null) {
    return 'null';
  }

  if (Array.isArray(value)) {
    return 'array';
  }

  if (Number.isInteger(value)) {
    return 'integer';
  }

  return typeof value;
};

/**
 * The number of code points in a string, counted up to `limit` (a string
 * from evidence can be large; it is not copied into an array to count).
 * @param {string} value
 * @param {number} limit
 * @returns {number}
 */
function codePoints(value, limit) {
  let count = 0;
  for (const _ of value) {
    if (++count >= limit) {
      break;
    }
  }

  return count;
}

/**
 * Compile a schema into a validator.
 *
 * @param {Object} root
 * @param {Object} [options]
 * @param {number} [options.maxErrors=20]
 * @returns {(value: *) => {valid: boolean, errors: string[]}}
 */
function compile(root, options = {}) {
  const maxErrors = options.maxErrors || 20;
  const patterns = new Map();
  const regex = source => {
    if (!patterns.has(source)) {
      patterns.set(source, new RegExp(source, 'u'));
    }

    return patterns.get(source);
  };

  // A pattern the regular expression engine cannot finish (its backtracking
  // stack exhausted by a huge string) is a failed match, not an exception.
  const matches = (source, value) => {
    try {
      return regex(source).test(value);
    } catch {
      return false;
    }
  };

  const resolve = reference => {
    const match = reference.match(/^#\/\$defs\/([\w-]+)$/);
    if (!match || !root.$defs || !root.$defs[match[1]]) {
      throw new Error(`Unresolvable $ref ${reference}`);
    }

    return root.$defs[match[1]];
  };

  // Check the schema itself once, so typos in it are found early.
  const audit = (schema, where) => {
    if (typeof schema === 'boolean') {
      return;
    }

    for (const key of Object.keys(schema)) {
      if (!KNOWN.has(key)) {
        throw new Error(`Unsupported schema keyword ${key} at ${where}`);
      }
    }

    if (schema.$ref) {
      resolve(schema.$ref);
    }

    for (const [key, child] of Object.entries(schema.properties || {})) {
      audit(child, `${where}.properties.${key}`);
    }

    for (const [key, child] of Object.entries(schema.patternProperties || {})) {
      regex(key);
      audit(child, `${where}.patternProperties`);
    }

    for (const key of ['additionalProperties', 'items', 'propertyNames']) {
      if (schema[key] !== undefined && typeof schema[key] === 'object') {
        audit(schema[key], `${where}.${key}`);
      }
    }

    for (const key of ['anyOf', 'oneOf']) {
      for (const [index, child] of (schema[key] || []).entries()) {
        audit(child, `${where}.${key}[${index}]`);
      }
    }

    if (schema.pattern) {
      regex(schema.pattern);
    }

    if (schema.contentEncoding !== undefined && schema.contentEncoding !== 'base64') {
      throw new Error(`Unsupported contentEncoding ${schema.contentEncoding} at ${where}`);
    }
  };

  audit(root, '#');
  for (const [name, definition] of Object.entries(root.$defs || {})) {
    audit(definition, `#/$defs/${name}`);
  }

  const check = (schema, value, at, errors) => {
    if (errors.length >= maxErrors) {
      return;
    }

    if (schema === true) {
      return;
    }

    if (schema === false) {
      errors.push(`${at} is not allowed`);
      return;
    }

    if (schema.$ref) {
      check(resolve(schema.$ref), value, at, errors);
    }

    const actual = typeOf(value);
    if (schema.type !== undefined) {
      const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
      if (!allowed.includes(actual) && !(actual === 'integer' && allowed.includes('number'))) {
        errors.push(`${at} must be ${allowed.join(' or ')}`);
        return;
      }
    }

    if (schema.const !== undefined && value !== schema.const) {
      errors.push(`${at} must be ${JSON.stringify(schema.const)}`);
    }

    if (schema.enum && !schema.enum.includes(value)) {
      errors.push(`${at} must be one of ${schema.enum.map(item => JSON.stringify(item)).join(', ')}`);
    }

    if (typeof value === 'string') {
      if (schema.minLength !== undefined && codePoints(value, schema.minLength) < schema.minLength) {
        errors.push(`${at} is shorter than ${schema.minLength}`);
      }

      if (schema.maxLength !== undefined && codePoints(value, schema.maxLength + 1) > schema.maxLength) {
        errors.push(`${at} is longer than ${schema.maxLength}`);
      }

      if (schema.pattern && !matches(schema.pattern, value)) {
        errors.push(`${at} does not match ${schema.pattern}`);
      }

      if (schema.contentEncoding === 'base64' && value.length % 4 !== 0) {
        errors.push(`${at} is not padded base64`);
      }
    }

    if (typeof value === 'number') {
      if (schema.minimum !== undefined && value < schema.minimum) {
        errors.push(`${at} is below ${schema.minimum}`);
      }

      if (schema.maximum !== undefined && value > schema.maximum) {
        errors.push(`${at} is above ${schema.maximum}`);
      }
    }

    if (actual === 'array') {
      if (schema.minItems !== undefined && value.length < schema.minItems) {
        errors.push(`${at} has fewer than ${schema.minItems} items`);
      }

      if (schema.maxItems !== undefined && value.length > schema.maxItems) {
        errors.push(`${at} has more than ${schema.maxItems} items`);
      }

      if (schema.items !== undefined) {
        for (const [index, item] of value.entries()) {
          check(schema.items, item, `${at}[${index}]`, errors);
        }
      }
    }

    if (actual === 'object') {
      // Undefined properties are absent, as in JSON.
      for (const key of schema.required || []) {
        if (value[key] === undefined || !Object.hasOwn(value, key)) {
          errors.push(`${at}.${key} is required`);
        }
      }

      for (const [key, item] of Object.entries(value)) {
        if (item === undefined) {
          continue;
        }

        const where = `${at}.${key}`;
        if (schema.propertyNames) {
          check(schema.propertyNames, key, `${at} key ${JSON.stringify(key.slice(0, 80))}`, errors);
        }

        let matched = false;
        if (schema.properties && Object.hasOwn(schema.properties, key)) {
          check(schema.properties[key], item, where, errors);
          matched = true;
        }

        for (const [pattern, child] of Object.entries(schema.patternProperties || {})) {
          if (regex(pattern).test(key)) {
            check(child, item, where, errors);
            matched = true;
          }
        }

        if (!matched && schema.additionalProperties !== undefined) {
          check(schema.additionalProperties, item, where, errors);
        }
      }
    }

    if (schema.anyOf && !schema.anyOf.some(child => {
      const nested = [];
      check(child, value, at, nested);
      return nested.length === 0;
    })) {
      errors.push(`${at} does not match any allowed form`);
    }

    if (schema.oneOf) {
      const attempts = schema.oneOf.map(child => {
        const nested = [];
        check(child, value, at, nested);
        return nested;
      });
      const matches = attempts.filter(nested => nested.length === 0).length;
      if (matches === 0) {
        // The closest form's problems say more than "no form matched".
        const closest = attempts.reduce((best, nested) => (nested.length < best.length ? nested : best));
        errors.push(...closest.slice(0, maxErrors - errors.length));
      } else if (matches > 1) {
        errors.push(`${at} must match exactly one allowed form (matches ${matches})`);
      }
    }
  };

  return value => {
    const errors = [];
    check(root, value, '$', errors);
    return {valid: errors.length === 0, errors};
  };
}

module.exports = {compile};
