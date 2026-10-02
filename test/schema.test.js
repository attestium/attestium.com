'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {compile} = require('../lib/schema');

const errorsOf = (schema, value, options) => compile(schema, options)(value).errors;

test('type, including lists and integers as numbers', () => {
  const check = compile({type: ['string', 'null']});
  assert.deepStrictEqual(check('x'), {valid: true, errors: []});
  assert.deepStrictEqual(check(null), {valid: true, errors: []});
  assert.deepStrictEqual(check(1), {valid: false, errors: ['$ must be string or null']});
  assert.deepStrictEqual(errorsOf({type: 'number'}, 3), []);
  assert.deepStrictEqual(errorsOf({type: 'number'}, 3.5), []);
  assert.deepStrictEqual(errorsOf({type: 'integer'}, 3.5), ['$ must be integer']);
  assert.deepStrictEqual(errorsOf({type: 'array'}, {}), ['$ must be array']);
  assert.deepStrictEqual(errorsOf({type: 'object'}, []), ['$ must be object']);
  assert.deepStrictEqual(errorsOf({type: 'boolean'}, 'true'), ['$ must be boolean']);
  // A wrong type stops the other checks on that value.
  assert.deepStrictEqual(errorsOf({type: 'string', minLength: 3}, 5), ['$ must be string']);
});

test('const, enum and string constraints', () => {
  assert.deepStrictEqual(errorsOf({const: 2}, 3), ['$ must be 2']);
  assert.deepStrictEqual(errorsOf({const: false}, false), []);
  assert.deepStrictEqual(errorsOf({enum: ['a', 1]}, 'b'), ['$ must be one of "a", 1']);
  assert.deepStrictEqual(errorsOf({enum: ['a', 1]}, 1), []);
  const string = {
    type: 'string', minLength: 2, maxLength: 3, pattern: '^[a-z✓]+$',
  };
  assert.deepStrictEqual(errorsOf(string, 'ab'), []);
  // Lengths count code points.
  assert.deepStrictEqual(errorsOf(string, '✓✓✓'), []);
  assert.deepStrictEqual(errorsOf({maxLength: 1}, '😀'), []);
  assert.deepStrictEqual(errorsOf(string, 'a'), ['$ is shorter than 2']);
  assert.deepStrictEqual(errorsOf(string, 'abcd'), ['$ is longer than 3']);
  assert.deepStrictEqual(errorsOf(string, 'A1'), ['$ does not match ^[a-z✓]+$']);
  // String constraints ignore other types.
  assert.deepStrictEqual(errorsOf({minLength: 2, pattern: 'x'}, 5), []);
});

test('number and array constraints', () => {
  const number = {minimum: 1, maximum: 10};
  assert.deepStrictEqual(errorsOf(number, 1), []);
  assert.deepStrictEqual(errorsOf(number, 0), ['$ is below 1']);
  assert.deepStrictEqual(errorsOf(number, 10.5), ['$ is above 10']);
  assert.deepStrictEqual(errorsOf(number, 'x'), []);
  const array = {
    type: 'array', minItems: 1, maxItems: 2, items: {type: 'integer'},
  };
  assert.deepStrictEqual(errorsOf(array, [1, 2]), []);
  assert.deepStrictEqual(errorsOf(array, []), ['$ has fewer than 1 items']);
  assert.deepStrictEqual(errorsOf(array, [1, 'b', 3]), ['$ has more than 2 items', '$[1] must be integer']);
  assert.deepStrictEqual(errorsOf({minItems: 1}, 'not an array'), []);
});

test('objects: properties, required, patternProperties, additionalProperties, propertyNames', () => {
  const schema = {
    type: 'object',
    required: ['id', 'name'],
    properties: {id: {type: 'integer'}, name: {type: 'string'}},
    patternProperties: {'^x-': {type: 'string'}, '^x-n': {maxLength: 2}},
    additionalProperties: false,
    propertyNames: {maxLength: 8},
  };
  assert.deepStrictEqual(errorsOf(schema, {id: 1, name: 'a', 'x-note': 'long'}), ['$.x-note is longer than 2']);
  assert.deepStrictEqual(errorsOf(schema, {id: 1, name: 'a', 'x-a': 'ok'}), []);
  assert.deepStrictEqual(errorsOf(schema, {id: 'one', extra: true}), [
    '$.name is required',
    '$.id must be integer',
    '$.extra is not allowed',
  ]);
  assert.deepStrictEqual(errorsOf(schema, {id: 1, name: 'a', averyverylongname: 1}), [
    '$ key "averyverylongname" is longer than 8',
    '$.averyverylongname is not allowed',
  ]);
  // Undefined properties are absent, as in JSON.
  assert.deepStrictEqual(errorsOf(schema, {id: 1, name: undefined, other: undefined}), ['$.name is required']);
  // Inherited properties are not own properties.
  assert.deepStrictEqual(errorsOf({required: ['toString']}, {}), ['$.toString is required']);
  assert.deepStrictEqual(errorsOf({properties: {toString: {type: 'string'}}}, {}), []);
  // Additional properties described by a schema.
  const map = {type: 'object', additionalProperties: {type: 'integer'}};
  assert.deepStrictEqual(errorsOf(map, {a: 1, b: 'x'}), ['$.b must be integer']);
  assert.deepStrictEqual(errorsOf({additionalProperties: true}, {a: 1}), []);
  assert.deepStrictEqual(errorsOf({properties: {a: {type: 'string'}}}, {b: 1}), []);
});

test('$ref, $defs, anyOf and oneOf', () => {
  const schema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://example.com/shape',
    $comment: 'shapes',
    title: 'Shape',
    description: 'A shape',
    examples: [{kind: 'circle', r: 1}],
    default: null,
    oneOf: [{$ref: '#/$defs/circle'}, {$ref: '#/$defs/square'}],
    $defs: {
      circle: {
        type: 'object', required: ['kind', 'r'], properties: {kind: {const: 'circle'}, r: {type: 'number'}},
      },
      square: {
        type: 'object', required: ['kind', 'side'], properties: {kind: {const: 'square'}, side: {type: 'number'}},
      },
      'size-or-null': {anyOf: [{type: 'null'}, {type: 'integer', minimum: 0}]},
    },
  };
  const check = compile(schema);
  assert.strictEqual(check({kind: 'circle', r: 2}).valid, true);
  assert.strictEqual(check({kind: 'square', side: 2}).valid, true);
  // The closest form's problems are reported.
  assert.deepStrictEqual(check({kind: 'square'}).errors, ['$.side is required']);
  assert.deepStrictEqual(check('circle').errors, ['$ must be object']);

  const ambiguous = compile({oneOf: [{type: 'integer'}, {minimum: 0}]});
  assert.deepStrictEqual(ambiguous(5).errors, ['$ must match exactly one allowed form (matches 2)']);
  assert.deepStrictEqual(ambiguous(-5).errors, []);

  const anyOf = compile({type: 'array', items: {$ref: '#/$defs/size'}, $defs: {size: schema.$defs['size-or-null']}});
  assert.deepStrictEqual(anyOf([null, 0, 3]).errors, []);
  assert.deepStrictEqual(anyOf([-1, 'x']).errors, ['$[0] does not match any allowed form', '$[1] does not match any allowed form']);
});

test('boolean schemas', () => {
  assert.deepStrictEqual(errorsOf(true, {anything: 1}), []);
  assert.deepStrictEqual(errorsOf(false, 1), ['$ is not allowed']);
  assert.deepStrictEqual(errorsOf({items: false}, [1]), ['$[0] is not allowed']);
  assert.deepStrictEqual(errorsOf({items: false}, []), []);
});

test('maxErrors limits the report', () => {
  const schema = {type: 'array', items: {type: 'string'}};
  const values = Array.from({length: 50}, (_, index) => index);
  assert.strictEqual(errorsOf(schema, values).length, 20);
  assert.strictEqual(errorsOf(schema, values, {maxErrors: 3}).length, 3);
  // The closest oneOf form's errors fill only what is left.
  const oneOf = {
    type: 'array',
    items: {
      oneOf: [
        {type: 'object', required: ['a', 'b', 'c']},
        {type: 'object', required: ['a', 'b', 'c', 'd']},
      ],
    },
  };
  assert.deepStrictEqual(errorsOf(oneOf, [{}, {}], {maxErrors: 4}), ['$[0].a is required', '$[0].b is required', '$[0].c is required', '$[1].a is required']);
});

test('the schema itself is checked when compiled', () => {
  assert.throws(() => compile({type: 'string', format: 'email'}), /Unsupported schema keyword format at #/);
  assert.throws(() => compile({properties: {a: {minimum: 1, exclusiveMinimum: 0}}}), /Unsupported schema keyword exclusiveMinimum at #.properties.a/);
  assert.throws(() => compile({patternProperties: {x: {unknown: 1}}}), /at #.patternProperties/);
  assert.throws(() => compile({patternProperties: {'(': {}}}), SyntaxError);
  assert.throws(() => compile({pattern: '['}), SyntaxError);
  assert.throws(() => compile({items: {nope: true}}), /at #.items/);
  assert.throws(() => compile({additionalProperties: {nope: true}}), /at #.additionalProperties/);
  assert.throws(() => compile({propertyNames: {nope: true}}), /at #.propertyNames/);
  assert.throws(() => compile({anyOf: [{}, {nope: true}]}), /at #.anyOf\[1]/);
  assert.throws(() => compile({oneOf: [{nope: true}]}), /at #.oneOf\[0]/);
  assert.throws(() => compile({$defs: {thing: {nope: true}}}), /at #\/\$defs\/thing/);
  assert.throws(() => compile({$ref: '#/$defs/missing', $defs: {}}), /Unresolvable \$ref #\/\$defs\/missing/);
  assert.throws(() => compile({$ref: '#/$defs/missing'}), /Unresolvable/);
  assert.throws(() => compile({$ref: 'https://example.com/other.json'}), /Unresolvable/);
  assert.throws(() => compile({properties: {a: {contentEncoding: 'base32'}}}), /Unsupported contentEncoding base32 at #.properties.a/);
  assert.ok(compile({items: true, additionalProperties: false, anyOf: [true]}));
});

test('contentEncoding base64 requires padding, and a pattern that cannot finish is a failed match', () => {
  const check = compile({contentEncoding: 'base64'});
  assert.deepEqual(check('QUJD').errors, []);
  assert.deepEqual(check('QUJ').errors, ['$ is not padded base64']);
  assert.deepEqual(check(5).errors, []);
  // A backtracking pattern on a string long enough to exhaust the engine's
  // stack reports a mismatch instead of throwing.
  const backtracking = compile({type: 'string', pattern: '^(?:[A-Z]{4})*$'});
  assert.deepEqual(backtracking('ABCD'.repeat(4 * 1024 * 1024)).errors, ['$ does not match ^(?:[A-Z]{4})*$']);
  assert.deepEqual(backtracking('ABCD').errors, []);
});

test('string lengths are counted without copying the string', () => {
  // A long string from evidence is not expanded into an array of its code
  // points (eight or more times its size) to check a maximum length.
  const script = `
    const {compile} = require(${JSON.stringify(require.resolve('../lib/schema'))});
    const check = compile({type: 'string', maxLength: 64, minLength: 1});
    const value = 'x'.repeat(48 * 1024 * 1024);
    const result = check(value);
    if (result.valid || result.errors[0] !== '$ is longer than 64') process.exit(2);
    if (!check('\u{1F600}'.repeat(64)).valid || check('').valid) process.exit(3);
  `;
  const {status, stderr} = require('node:child_process').spawnSync(process.execPath, ['--max-old-space-size=160', '-e', script], {encoding: 'utf8'});
  assert.equal(status, 0, stderr.slice(-300));
});
