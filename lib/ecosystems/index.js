/**
 * Attestium - package ecosystem plugins
 *
 * Installed-package ecosystems (scanned where packages are installed):
 *
 *   npm        node_modules (npm, pnpm)           package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml
 *   pypi       virtual environments               uv.lock, pylock.toml, poetry.lock, Pipfile.lock, requirements.txt with hashes
 *   rubygems   Bundler's vendor/bundle             Gemfile.lock with CHECKSUMS
 *   hex        Mix's deps/                        mix.lock
 *   composer   vendor/                            composer.lock
 *   maven      directories of jars                gradle/verification-metadata.xml, lockfile.json
 *   nuget      published .NET applications        packages.lock.json
 *
 * Compiled-in ecosystems (checked inside a binary):
 *
 *   go         Go build information               go.sum
 *   cargo      cargo-auditable crate list          Cargo.lock
 *
 * See ./common for the plugin shape.
 *
 * @license MIT
 */

'use strict';

const common = require('./common');

const INSTALLED = {
  npm: require('./npm'),
  pypi: require('./pypi'),
  rubygems: require('./rubygems'),
  hex: require('./hex'),
  composer: require('./composer'),
  maven: require('./maven'),
  nuget: require('./nuget'),
};

const COMPILED = {
  go: require('./go'),
  cargo: require('./cargo'),
};

/**
 * Where packages of each enabled ecosystem are installed under a root.
 *
 * @param {string} root
 * @param {string[]} [names] - ecosystems to look for (default: all)
 * @returns {Array<{ecosystem: string, dir: string, installRoot: string}>}
 */
function detectInstalls(root, names = Object.keys(INSTALLED)) {
  const found = [];
  for (const name of names) {
    const plugin = INSTALLED[name];
    if (!plugin) {
      throw new Error(`Unknown package ecosystem: ${name}`);
    }

    for (const dir of plugin.detect(root)) {
      found.push({ecosystem: name, dir, installRoot: plugin.installRoot(dir)});
    }
  }

  return found;
}

module.exports = {
  ...INSTALLED,
  ...COMPILED,
  INSTALLED,
  COMPILED,
  detectInstalls,
  ReferenceStore: common.ReferenceStore,
  NoLockfileError: common.NoLockfileError,
  compareFiles: common.compareFiles,
  collect: common.collect,
  parseCsv: common.parseCsv,
};
