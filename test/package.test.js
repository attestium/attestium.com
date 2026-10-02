'use strict';

// The package's entry points: package.json "exports", their type
// declarations, and the subpath table of docs/api.md.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const Attestium = require('..');
const pkg = require('../package.json');

const root = path.join(__dirname, '..');

function target(entry) {
  return typeof entry === 'string' ? entry : entry.default;
}

test('every export exists, and every module has type declarations', () => {
  for (const [subpath, entry] of Object.entries(pkg.exports)) {
    const file = path.join(root, target(entry));
    assert.ok(fs.existsSync(file), `${subpath}: ${target(entry)} does not exist`);
    if (file.endsWith('.js')) {
      const types = typeof entry === 'object' && entry.types ? path.join(root, entry.types) : file.replace(/\.js$/, '.d.ts');
      assert.ok(fs.existsSync(types), `${subpath}: no type declarations (${path.relative(root, types)})`);
    }
  }
});

test('docs/api.md names every subpath, and the property of the main export it is', () => {
  const api = fs.readFileSync(path.join(root, 'docs', 'api.md'), 'utf8');
  const rows = api.split('\n').filter(line => /^\| `attestium[/`]/.test(line));
  const documented = new Set();
  for (const row of rows) {
    // "`attestium/zip`, `attestium/toml`, none for `asn1`": asn1 has no subpath.
    const [subpaths, properties] = row.split('|').slice(1, 3).map(cell => [...cell.matchAll(/`([^`]+)`/g)].map(match => match[1]));
    const named = subpaths.filter(name => name.startsWith('attestium'));
    subpaths.length = named.length;
    for (const [index, name] of subpaths.entries()) {
      const subpath = name === 'attestium' ? '.' : `./${name.slice('attestium/'.length)}`;
      documented.add(subpath);
      assert.ok(Object.hasOwn(pkg.exports, subpath), `docs/api.md names ${name}, which package.json does not export`);
      const property = properties[index];
      if (property && !name.endsWith('.json')) {
        assert.strictEqual(require(path.join(root, target(pkg.exports[subpath]))), Attestium[property], `${name} is not Attestium.${property}`);
      }
    }
  }

  for (const subpath of Object.keys(pkg.exports).filter(subpath => subpath !== './package.json')) {
    assert.ok(documented.has(subpath), `docs/api.md does not name ${subpath}`);
  }
});
