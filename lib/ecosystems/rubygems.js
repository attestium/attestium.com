/**
 * Attestium - Ruby gems (RubyGems, Bundler)
 *
 * Attester: a gem directory (GEM_HOME, or Bundler's vendor/bundle/ruby/X.Y.Z)
 * is scanned: every installed gem's files, its specification (a Ruby file
 * RubyGems loads at start-up), compiled extensions, executables' wrappers
 * in bin/ and RubyGems plugins.
 *
 * Verifier: Gemfile.lock's CHECKSUMS section (Bundler 2.6 and later) pins
 * each .gem file's SHA-256.  The .gem is downloaded, checked, and its
 * data.tar.gz compared with the installed directory.  Specifications are
 * Ruby code, so each must consist only of literal values (no method calls
 * other than the ones RubyGems writes) and agree with the gem's own
 * metadata; executable wrappers must match RubyGems' generated template.
 *
 * Gems with native extensions are compiled on the server; their build
 * output cannot be compared with anything and is reported as such.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const yaml = require('js-yaml');
const {walkTree} = require('../file-tree');
const {readTar, readGzipTarFiles} = require('../tar');
const {
  sha256, parallelMap, exists, setOwn,
} = require('../util');
const {
  NoLockfileError, compareFiles, collect, scanIssues, hashFiles,
} = require('./common');

const LOCKFILES = ['Gemfile.lock', 'gems.locked'];

// ─── attester ──────────────────────────────────────────────────────────

/**
 * Bundler install directories under a project root.
 * @param {string} root
 * @returns {string[]}
 */
function detect(root) {
  const found = [];
  for (const base of [path.join(root, 'vendor', 'bundle', 'ruby'), path.join(root, '.bundle', 'ruby')]) {
    let versions = [];
    try {
      versions = fs.readdirSync(base).filter(name => /^\d+\.\d+\.\d+$/.test(name)).sort();
    } catch {}

    for (const version of versions) {
      if (exists(path.join(base, version, 'specifications'))) {
        found.push(path.join(base, version));
      }
    }
  }

  return found;
}

function installRoot(gemHome) {
  return gemHome;
}

async function readSmall(file, limit = 256 * 1024) {
  const content = await fs.promises.readFile(file);
  return content.length <= limit ? content.toString('utf8') : null;
}

/**
 * Scan a gem directory.
 * @param {string} gemHome
 * @returns {Promise<Object>}
 */
async function scan(gemHome) {
  gemHome = path.resolve(gemHome);
  const errors = [];
  const unaccounted = [];
  let gems = [];
  try {
    gems = (await fs.promises.readdir(path.join(gemHome, 'gems'), {withFileTypes: true})).filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
  } catch (error) {
    errors.push({path: 'gems', error: error.code});
  }

  let specifications = [];
  try {
    specifications = (await fs.promises.readdir(path.join(gemHome, 'specifications'))).sort();
  } catch {}

  const extensionDirs = new Map();
  const extensionRoot = path.join(gemHome, 'extensions');
  try {
    for (const platform of await fs.promises.readdir(extensionRoot)) {
      for (const abi of await fs.promises.readdir(path.join(extensionRoot, platform))) {
        for (const full of await fs.promises.readdir(path.join(extensionRoot, platform, abi))) {
          extensionDirs.set(full, `extensions/${platform}/${abi}/${full}`);
        }
      }
    }
  } catch {}

  const packages = await parallelMap(gems.map(full => async () => {
    const item = {
      name: null, version: null, path: `gems/${full}`, files: {}, meta: {full},
    };
    const walk = await walkTree(path.join(gemHome, 'gems', full));
    for (const entry of walk.entries) {
      setOwn(item.files, entry.path, entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256);
    }

    for (const walkError of walk.errors) {
      errors.push({path: `gems/${full}/${walkError.path}`, error: walkError.error});
    }

    const specFile = `${full}.gemspec`;
    if (specifications.includes(specFile)) {
      try {
        item.meta.gemspec = await readSmall(path.join(gemHome, 'specifications', specFile));
      } catch (error) {
        errors.push({path: `specifications/${specFile}`, error: error.code});
      }
    }

    if (extensionDirs.has(full)) {
      const extension = await walkTree(path.join(gemHome, ...extensionDirs.get(full).split('/')));
      item.meta.extension = Object.fromEntries(extension.entries.map(entry => [entry.path, entry.sha256]));
      item.meta.extensionPath = extensionDirs.get(full);
      for (const walkError of extension.errors) {
        errors.push({path: `${extensionDirs.get(full)}/${walkError.path}`, error: walkError.error});
      }
    }

    return item;
  }), 8);

  for (const item of packages) {
    const spec = parseGemspecSafely(item.meta.gemspec);
    item.name = spec ? spec.name : null;
    item.version = spec ? spec.version : null;
    if (!item.name) {
      // Without a readable specification, name the gem by its directory.
      const match = item.meta.full.match(/^(.+)-(\d[^-]*)(?:-(.+))?$/);
      item.name = match ? match[1] : item.meta.full;
      item.version = match ? match[2] : null;
    }
  }

  // Specifications and extensions without an installed gem, and anything
  // else loaded at start-up.
  for (const file of specifications) {
    if (!gems.includes(file.replace(/\.gemspec$/, ''))) {
      unaccounted.push(`specifications/${file}`);
    }
  }

  for (const [full, relative] of extensionDirs) {
    if (!gems.includes(full)) {
      unaccounted.push(`${relative}/`);
    }
  }

  const meta = {bin: {}, plugins: {}};
  for (const directory of ['bin', 'plugins']) {
    let names = [];
    try {
      names = await fs.promises.readdir(path.join(gemHome, directory));
    } catch {}

    for (const name of names) {
      try {
        meta[directory][name] = await readSmall(path.join(gemHome, directory, name), 64 * 1024);
      } catch (error) {
        errors.push({path: `${directory}/${name}`, error: error.code});
      }
    }
  }

  return {
    packages, unaccounted: unaccounted.sort(), links: [], caches: [], errors, meta,
  };
}

// ─── specifications ────────────────────────────────────────────────────

// The attributes RubyGems writes into installed specifications.
const SPEC_ATTRIBUTES = new Set([
  'name',
  'version',
  'platform',
  'original_platform',
  'required_rubygems_version',
  'required_ruby_version',
  'metadata',
  'require_paths',
  'authors',
  'date',
  'description',
  'email',
  'executables',
  'extensions',
  'extra_rdoc_files',
  'files',
  'homepage',
  'licenses',
  'license',
  'rdoc_options',
  'rubygems_version',
  'summary',
  'installed_by_version',
  'specification_version',
  'bindir',
  'post_install_message',
  'signing_key',
  'cert_chain',
  'rubyforge_project',
  'default_executable',
  'test_files',
  'requirements',
  'autorequire',
  'has_rdoc',
]);
const DEPENDENCY_METHODS = new Set(['add_runtime_dependency', 'add_development_dependency', 'add_dependency']);

class GemspecError extends Error {}

/**
 * Tokenize a specification, accepting only what RubyGems generates:
 * literals, `s.<attribute> = ...`, dependency calls, `.freeze`, and a few
 * constructors.  Anything that could run code is rejected.
 */
function tokenize(text) {
  const tokens = [];
  let index = 0;
  const fail = message => {
    throw new GemspecError(`${message} at offset ${index}`);
  };

  while (index < text.length) {
    const char = text[index];
    if (char === '\n') {
      tokens.push({type: 'newline'});
      index++;
    } else if (/\s/.test(char)) {
      index++;
    } else if (char === '#') {
      while (index < text.length && text[index] !== '\n') {
        index++;
      }
    } else if (char === '"') {
      let value = '';
      index++;
      for (;;) {
        const current = text[index];
        if (current === undefined) {
          fail('unterminated string');
        }

        if (current === '"') {
          index++;
          break;
        }

        if (current === '#' && /[{@$]/.test(text[index + 1] || '')) {
          fail('interpolation in a string');
        }

        if (current === '\\') {
          const next = text[index + 1];
          const escapes = {
            n: '\n', t: '\t', r: '\r', e: '\u001B', s: ' ', 0: '\0', '"': '"', '\\': '\\', '#': '#',
          };
          if (next === 'u') {
            const hex = text.slice(index + 2).match(/^(?:{([\da-fA-F]{1,6})}|([\da-fA-F]{4}))/);
            if (!hex) {
              fail('invalid unicode escape');
            }

            value += String.fromCodePoint(Number.parseInt(hex[1] || hex[2], 16));
            index += 2 + hex[0].length;
            continue;
          }

          if (!(next in escapes)) {
            fail(`unsupported escape \\${next}`);
          }

          value += escapes[next];
          index += 2;
          continue;
        }

        value += current;
        index++;
      }

      tokens.push({type: 'string', value});
    } else if (text.startsWith('%q<', index)) {
      // Nested angle brackets are allowed inside %q<...>.
      let depth = 1;
      let value = '';
      index += 3;
      while (depth > 0) {
        const current = text[index];
        if (current === undefined) {
          fail('unterminated %q string');
        }

        if (current === '<') {
          depth++;
        } else if (current === '>') {
          depth--;
          if (depth === 0) {
            index++;
            break;
          }
        } else if (current === '\\' && /[<>\\]/.test(text[index + 1] || '')) {
          value += text[index + 1];
          index += 2;
          continue;
        }

        value += current;
        index++;
      }

      tokens.push({type: 'string', value});
    } else if (/\d/.test(char) || (char === '-' && /\d/.test(text[index + 1] || ''))) {
      const match = text.slice(index).match(/^-?\d+(?:\.\d+)?/);
      tokens.push({type: 'number', value: Number(match[0])});
      index += match[0].length;
    } else if (char === ':' && text[index + 1] === ':') {
      tokens.push({type: 'punct', value: '::'});
      index += 2;
    } else if (char === ':' && /[a-z_]/.test(text[index + 1] || '')) {
      const match = text.slice(index + 1).match(/^[a-z_]+=?/);
      tokens.push({type: 'symbol', value: match[0]});
      index += 1 + match[0].length;
    } else if (text.startsWith('=>', index)) {
      tokens.push({type: 'punct', value: '=>'});
      index += 2;
    } else if ('[](){}|,=.'.includes(char)) {
      tokens.push({type: 'punct', value: char});
      index++;
    } else if (/[A-Za-z_]/.test(char)) {
      const match = text.slice(index).match(/^[A-Za-z_]\w*[?!]?/);
      tokens.push({type: 'word', value: match[0]});
      index += match[0].length;
    } else {
      fail(`unexpected ${JSON.stringify(char)}`);
    }
  }

  return tokens;
}

/**
 * Evaluate a generated specification's literal values.
 *
 * @param {string} text
 * @returns {{name: string, version: string, platform: string, require_paths: string[], bindir: string, executables: string[], extensions: string[], dependencies: Array<[string, string[]]>}}
 * @throws {GemspecError} when the file contains anything but literals
 */
function parseGemspec(text) {
  const tokens = tokenize(text);
  let index = 0;
  const peek = (offset = 0) => tokens[index + offset];
  const is = (type, value, offset = 0) => peek(offset) && peek(offset).type === type && (value === undefined || peek(offset).value === value);
  const expect = (type, value) => {
    if (!is(type, value)) {
      throw new GemspecError(`expected ${value || type}, found ${JSON.stringify(peek())}`);
    }

    return tokens[index++];
  };

  const skipNewlines = () => {
    while (is('newline')) {
      index++;
    }
  };

  const parseArguments = () => {
    expect('punct', '(');
    const values = [];
    skipNewlines();
    while (!is('punct', ')')) {
      values.push(parseValue());
      skipNewlines();
      if (is('punct', ',')) {
        index++;
        skipNewlines();
      }
    }

    index++;
    return values;
  };

  function parseValue() {
    let value;
    if (is('string') || is('number')) {
      value = tokens[index++].value;
    } else if (is('word', 'nil') || is('word', 'true') || is('word', 'false')) {
      value = {nil: null, true: true, false: false}[tokens[index++].value];
    } else if (is('punct', '[')) {
      index++;
      value = [];
      skipNewlines();
      while (!is('punct', ']')) {
        value.push(parseValue());
        skipNewlines();
        if (is('punct', ',')) {
          index++;
          skipNewlines();
        }
      }

      index++;
    } else if (is('punct', '{')) {
      index++;
      value = {};
      skipNewlines();
      while (!is('punct', '}')) {
        const key = parseValue();
        expect('punct', '=>');
        value[String(key)] = parseValue();
        skipNewlines();
        if (is('punct', ',')) {
          index++;
          skipNewlines();
        }
      }

      index++;
    } else if (is('word', 'Gem') && is('punct', '::', 1)) {
      index += 2;
      const kind = expect('word').value;
      if (!['Requirement', 'Version', 'Platform'].includes(kind)) {
        throw new GemspecError(`unexpected Gem::${kind}`);
      }

      expect('punct', '.');
      expect('word', 'new');
      value = {[kind]: parseArguments()};
    } else if (is('word', 'Time') && is('punct', '.', 1) && is('word', 'utc', 2)) {
      index += 3;
      value = {Time: parseArguments()};
    } else {
      throw new GemspecError(`unexpected ${JSON.stringify(peek())}`);
    }

    // A trailing .freeze does not change a literal.
    while (is('punct', '.') && is('word', 'freeze', 1)) {
      index += 2;
    }

    return value;
  }

  const spec = {dependencies: []};
  const parseCondition = () => {
    // "if s.respond_to? :attr=" (optionally followed by "then")
    expect('word', 'if');
    expect('word', 's');
    expect('punct', '.');
    expect('word', 'respond_to?');
    if (is('punct', '(')) {
      index++;
      expect('symbol');
      expect('punct', ')');
    } else {
      expect('symbol');
    }

    if (is('word', 'then')) {
      index++;
    }
  };

  skipNewlines();
  expect('word', 'Gem');
  expect('punct', '::');
  expect('word', 'Specification');
  expect('punct', '.');
  expect('word', 'new');
  expect('word', 'do');
  expect('punct', '|');
  expect('word', 's');
  expect('punct', '|');
  let depth = 0;
  for (;;) {
    skipNewlines();
    if (is('word', 'end')) {
      index++;
      if (depth === 0) {
        break;
      }

      depth--;
      continue;
    }

    if (is('word', 'else')) {
      index++;
      continue;
    }

    if (is('word', 'if')) {
      parseCondition();
      depth++;
      continue;
    }

    expect('word', 's');
    expect('punct', '.');
    const name = expect('word').value;
    if (DEPENDENCY_METHODS.has(name)) {
      const args = is('punct', '(') ? parseArguments() : [parseValue(), ...(is('punct', ',') ? (index++, [parseValue()]) : [])];
      spec.dependencies.push(args);
    } else if (SPEC_ATTRIBUTES.has(name) && is('punct', '=')) {
      index++;
      spec[name] = parseValue();
    } else {
      throw new GemspecError(`unexpected s.${name}`);
    }

    // A trailing modifier "if s.respond_to? :attr=".
    if (is('word', 'if')) {
      parseCondition();
    }

    if (!is('newline') && !is('word', 'end') && peek() !== undefined) {
      throw new GemspecError(`unexpected ${JSON.stringify(peek())} after s.${name}`);
    }
  }

  skipNewlines();
  if (peek() !== undefined) {
    throw new GemspecError('content after the specification');
  }

  return {
    name: typeof spec.name === 'string' ? spec.name : null,
    version: typeof spec.version === 'string' ? spec.version : null,
    platform: typeof spec.platform === 'string' ? spec.platform : 'ruby',
    // eslint-disable-next-line camelcase -- the gemspec attribute's name
    require_paths: spec.require_paths ?? ['lib'],
    bindir: spec.bindir ?? 'bin',
    executables: spec.executables ?? [],
    extensions: spec.extensions ?? [],
    dependencies: spec.dependencies,
  };
}

function parseGemspecSafely(text) {
  try {
    return typeof text === 'string' ? parseGemspec(text) : null;
  } catch {
    return null;
  }
}

/**
 * Whether an executable wrapper in bin/ is what RubyGems generates for a
 * gem's executable.
 *
 * @param {string} content
 * @returns {{gem: string, executable: string}|null}
 */
function binstubTarget(content) {
  const load = content.match(/load Gem\.activate_bin_path\('([\w.-]+)', '([\w.-]+)', version\)/);
  if (!load) {
    return null;
  }

  const [, gem, executable] = load;
  const escape = value => value.replaceAll(/[$()*+.?[\\\]^{|}]/g, String.raw`\$&`);
  const call = `\\('${escape(gem)}', '${escape(executable)}', version\\)`;
  const ending = [
    // RubyGems 3.7 and later.
    [String.raw`if Gem\.respond_to\?\(:activate_and_load_bin_path\)`, `  Gem\\.activate_and_load_bin_path${call}`, 'else', `  load Gem\\.activate_bin_path${call}`, 'end'],
    // RubyGems 2.x to 3.6.
    [
      String.raw`if Gem\.respond_to\?\(:activate_bin_path\)`,
      `load Gem\\.activate_bin_path${call}`,
      'else',
      `gem "${escape(gem)}", version`,
      `load Gem\\.bin_path\\("${escape(gem)}", "${escape(executable)}", version\\)`,
      'end',
    ],
  ].map(block => block.join(String.raw`\n`));
  const lines = [
    String.raw`#![^\n]*`,
    '#',
    String.raw`# This file was generated by RubyGems\.`,
    '#',
    `# The application '${escape(gem)}' is installed as part of a gem, and`,
    String.raw`# this file is here to facilitate running it\.`,
    '#',
    '',
    'require \'rubygems\'',
    '',
    String.raw`(?:Gem\.use_gemdeps\n\n)?version = "(?:>= 0\.a|>= 0)"`,
    '',
    // RubyGems 3 and later, and 2.x.
    String.raw`(?:str = ARGV\.first\nif str\n  str = str\.b\[/\\A_\(\.\*\)_\\z/, 1\]\n  if str and Gem::Version\.correct\?\(str\)\n    version = str\n    ARGV\.shift\n  end\nend|if ARGV\.first\n  str = ARGV\.first\n  str = str\.dup\.force_encoding\("BINARY"\)\n  if str =~ /\\A_\(\.\*\)_\\z/ and Gem::Version\.correct\?\(\$1\) then\n    version = \$1\n    ARGV\.shift\n  end\nend)`,
    '',
    `(?:${ending.join('|')})`,
    '',
  ];
  return new RegExp(`^${lines.join(String.raw`\n`)}$`).test(content) ? {gem, executable} : null;
}

// ─── lockfile ──────────────────────────────────────────────────────────

/**
 * Parse Gemfile.lock: gem sources, git sources, and checksums.
 * @param {string} text
 * @returns {{gems: Map<string, {name: string, version: string, platform: string, source: Object}>, checksums: Map<string, string>}}
 */
function parseGemfileLock(text) {
  const gems = new Map();
  const checksums = new Map();
  let section = null;
  let source = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^[A-Z]/.test(line)) {
      section = line.trim();
      source = {GEM: {type: 'gem', remote: null}, GIT: {type: 'git', remote: null, revision: null}, PATH: {type: 'path'}}[section] || null;
      continue;
    }

    if (section === 'CHECKSUMS') {
      const match = line.match(/^ {2}(\S+) \(([^)]+)\)(?: sha256=([\da-f]{64}))?/);
      if (match && match[3]) {
        checksums.set(`${match[1]}-${match[2]}`, match[3]);
      }

      continue;
    }

    if (!source) {
      continue;
    }

    const remote = line.match(/^ {2}remote: (\S+)/);
    if (remote) {
      source.remote = remote[1];
      continue;
    }

    const revision = line.match(/^ {2}revision: ([\da-f]{40})/);
    if (revision) {
      source.revision = revision[1];
      continue;
    }

    const spec = line.match(/^ {4}(\S+) \(([^)]+)\)$/);
    if (spec) {
      const [version, ...platform] = spec[2].split('-');
      const full = `${spec[1]}-${spec[2]}`;
      gems.set(full, {
        name: spec[1], version, platform: platform.join('-') || 'ruby', full, source,
      });
    }
  }

  return {gems, checksums};
}

/**
 * @param {string} repoDir
 * @param {Object} [options]
 * @param {string} [options.lockfile]
 * @returns {{format: string, file: string, gems: Map, checksums: Map}}
 */
function readLock(repoDir, options = {}) {
  const candidates = options.lockfile ? [options.lockfile] : LOCKFILES;
  const file = candidates.find(name => exists(path.join(repoDir, name)));
  if (!file) {
    throw new NoLockfileError(`No Ruby lockfile found (${candidates.join(', ')})`);
  }

  return {format: 'bundler', file, ...parseGemfileLock(fs.readFileSync(path.join(repoDir, file), 'utf8'))};
}

// ─── references ────────────────────────────────────────────────────────

/**
 * Parse gem metadata YAML (Ruby object tags are ignored).
 * @param {string} text
 * @returns {Object}
 */
function parseGemMetadata(text) {
  const plain = text.replaceAll(/!ruby\/[\w:/]+/g, '').replaceAll('!binary ', '');
  const spec = yaml.load(plain, {schema: yaml.JSON_SCHEMA, json: true}) || {};
  const version = spec.version && typeof spec.version === 'object' ? spec.version.version : spec.version;
  return {
    name: spec.name,
    version: String(version),
    platform: typeof spec.platform === 'string' ? spec.platform : 'ruby',
    // eslint-disable-next-line camelcase -- the gemspec attribute's name
    require_paths: spec.require_paths || ['lib'],
    bindir: spec.bindir || 'bin',
    executables: spec.executables || [],
    extensions: spec.extensions || [],
  };
}

/**
 * Contents and metadata of a .gem file.
 * @param {Buffer} buffer
 * @returns {{files: Object<string, string>, metadata: Object}}
 */
function readGem(buffer) {
  // Regular files (readTar reports a NUL type flag as '0').
  const members = new Map(readTar(buffer).filter(entry => entry.type === '0').map(entry => [entry.name, entry.data]));
  const data = members.get('data.tar.gz');
  const metadata = members.get('metadata.gz');
  if (!data || !metadata) {
    throw new Error('Not a gem file (no data.tar.gz or metadata.gz)');
  }

  return {
    files: hashFiles(readGzipTarFiles(data)),
    metadata: parseGemMetadata(zlib.gunzipSync(metadata, {maxOutputLength: 16 * 1024 * 1024}).toString('utf8')),
  };
}

function gemManifest(store, full, checksum) {
  return store.memo(`rubygems-gem:v1:${full}:${checksum}`, async () => {
    const buffer = await store.get(`${store.urls.rubygems}/gems/${encodeURIComponent(full)}.gem`, {maxBytes: 512 * 1024 * 1024});
    if (sha256(buffer) !== checksum) {
      throw new Error(`Downloaded ${full}.gem does not match its checksum`);
    }

    return readGem(buffer);
  });
}

/**
 * The registry's checksum for a gem the lockfile does not pin.
 */
function registryChecksum(store, name, version, platform) {
  return store.memo(`rubygems-sha:v1:${name}-${version}-${platform}`, async () => {
    const versions = await store.getJson(`${store.urls.rubygems}/api/v1/versions/${encodeURIComponent(name)}.json`, {maxBytes: 64 * 1024 * 1024});
    const match = versions.find(entry => entry.number === version && (entry.platform || 'ruby') === platform);
    if (!match || !/^[\da-f]{64}$/.test(match.sha || '')) {
      throw new Error(`the registry has no checksum for ${name} ${version} (${platform})`);
    }

    return match.sha;
  }, {persist: false});
}

/**
 * Compare a gem directory scan with Gemfile.lock.
 * @param {Object} input
 * @returns {Promise<Object>}
 */
async function compare({scan: installed, lock, store}) {
  const issues = [];
  const built = [];
  const unpinned = [];
  const results = await parallelMap(installed.packages.map(item => async () => {
    const {full} = item.meta;
    const locked = lock ? lock.gems.get(full) : null;
    if (!locked) {
      // Bundler installs itself and default gems ship with Ruby.
      return {status: 'failed', item, reason: lock ? 'installed gem is not in the lockfile' : 'no lockfile pins this gem'};
    }

    if (locked.source.type === 'git') {
      return {status: 'unverifiable', item, reason: `installed from git (${locked.source.remote}); only gems from a gem server are compared`};
    }

    let checksum = lock.checksums.get(full);
    if (!checksum) {
      try {
        checksum = await registryChecksum(store, locked.name, locked.version, locked.platform);
        unpinned.push(full);
      } catch (error) {
        return {status: 'error', item, reason: error.message};
      }
    }

    let reference;
    try {
      reference = await gemManifest(store, full, checksum);
    } catch (error) {
      return {status: /does not match/.test(error.message) ? 'failed' : 'error', item, reason: error.message};
    }

    // The specification is Ruby that RubyGems loads: only literals, and
    // the fields that decide what is loaded must match the gem's metadata.
    let spec;
    try {
      spec = parseGemspec(item.meta.gemspec ?? '');
    } catch (error) {
      return {status: 'failed', item, reason: `its specification is not a generated literal specification: ${error.message}`};
    }

    const fields = ['name', 'version', 'platform', 'require_paths', 'bindir', 'executables', 'extensions'];
    const differing = fields.filter(field => JSON.stringify(spec[field]) !== JSON.stringify(reference.metadata[field]));
    if (differing.length > 0) {
      return {status: 'failed', item, reason: `its specification differs from the gem's metadata (${differing.join(', ')})`};
    }

    const hasExtensions = reference.metadata.extensions.length > 0;
    // Building an extension adds its output (shared libraries, makefiles,
    // logs) to the gem directory; it adds no Ruby source outside ext/.
    const comparison = compareFiles(item.files, reference.files, {allowExtra: file => hasExtensions && (file.startsWith('ext/') || !file.endsWith('.rb'))});
    if (comparison.modified.length > 0 || comparison.missing.length > 0 || comparison.added.length > 0) {
      return {
        status: 'failed', item, reason: 'files differ from the gem', ...comparison,
      };
    }

    if (item.meta.extension && !hasExtensions) {
      return {status: 'failed', item, reason: `compiled extension files for a gem that has no extensions (${item.meta.extensionPath})`};
    }

    if (hasExtensions) {
      built.push(`${full} (${Object.keys(item.meta.extension || {}).length} files in ${item.meta.extensionPath || 'no extensions directory'})`);
      return {status: 'built', item};
    }

    return {status: 'verified', item};
  }), store.concurrency);

  if (unpinned.length > 0) {
    issues.push({severity: 'warn', message: 'Gemfile.lock has no checksums for these gems; they were compared with the registry\'s checksum instead (Bundler 2.6 and later write them: `bundle lock --add-checksums`)', items: unpinned.sort()});
  }

  if (built.length > 0) {
    issues.push({severity: 'warn', message: 'Gems with native extensions were compiled on the server; their unchanged sources match, but the compiled output cannot be compared with anything', items: built.sort()});
  }

  // Wrappers in bin/ run a gem's executable; plugins are loaded by RubyGems.
  const executables = new Map();
  for (const result of results) {
    if (result.status === 'verified' || result.status === 'built') {
      const spec = parseGemspecSafely(result.item.meta.gemspec);
      for (const executable of spec.executables) {
        executables.set(executable, spec.name);
      }
    }
  }

  const badBin = [];
  for (const [name, content] of Object.entries(installed.meta.bin || {})) {
    const target = content === null ? null : binstubTarget(content);
    if (!target || target.executable !== name || executables.get(name) !== target.gem) {
      badBin.push(`bin/${name}`);
    }
  }

  if (badBin.length > 0) {
    issues.push({severity: 'fail', message: 'Files in bin/ that are not the wrapper RubyGems generates for a verified gem\'s executable', items: badBin.sort()});
  }

  const plugins = Object.keys(installed.meta.plugins || {});
  if (plugins.length > 0) {
    issues.push({severity: 'fail', message: 'RubyGems plugins are installed (RubyGems loads them into every Ruby process)', items: plugins.map(name => `plugins/${name}`)});
  }

  if (installed.unaccounted.length > 0) {
    issues.push({severity: 'fail', message: 'Specifications or extensions without an installed gem', items: installed.unaccounted});
  }

  issues.push(...scanIssues(installed));
  return collect(results, issues);
}

/**
 * Compare the directory of one installed gem that no lockfile pins (Bundler
 * itself, loaded through RUBYLIB by `bundle exec`) with the gem the
 * registry serves: the registry's checksum, the downloaded .gem, and its
 * files.
 *
 * @param {Object} input
 * @param {string} input.name
 * @param {string} input.version
 * @param {Object<string, string>} input.files - path in the gem directory -> SHA-256 (or symlink:target)
 * @param {ReferenceStore} input.store
 * @returns {Promise<{modified: string[], missing: string[], added: string[]}>}
 */
async function compareGemDirectory({name, version, files, store}) {
  const checksum = await registryChecksum(store, name, version, 'ruby');
  const reference = await gemManifest(store, `${name}-${version}`, checksum);
  return compareFiles(files, reference.files);
}

module.exports = {
  name: 'rubygems',
  label: 'RubyGems',
  lockfiles: LOCKFILES,
  detect,
  installRoot,
  scan,
  readLock,
  compare,
  parseGemspec,
  parseGemfileLock,
  parseGemMetadata,
  binstubTarget,
  readGem,
  compareGemDirectory,
  GemspecError,
};
