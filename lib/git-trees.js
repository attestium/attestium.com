/**
 * Attestium - file lists of commits in other repositories
 *
 * Some ecosystems install packages straight from a repository at a pinned
 * commit (Composer, Bundler's git sources).  A commit names its tree, so
 * the tree is the reference: file paths and git blob ids, read from a
 * blobless clone (trees only; single files fetched on demand).
 *
 * Git runs with hooks off, no prompts, no system or global configuration,
 * no replacement objects or grafts, and only https (or file, for tests) URLs.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {execFile} = require('node:child_process');
const {sha256} = require('./util');

const COMMIT = /^[\da-f]{40}$/;

class GitTrees {
  /**
   * @param {Object} options
   * @param {string} options.cacheDir
   * @param {string} [options.git='git']
   * @param {number} [options.timeout=600000]
   * @param {boolean} [options.allowFileUrls=false] - for tests
   */
  constructor({cacheDir, git = 'git', timeout = 600_000, allowFileUrls = false}) {
    this.cacheDir = path.resolve(cacheDir);
    this.git = git;
    this.timeout = timeout;
    this.allowFileUrls = allowFileUrls;
    this._repos = new Map();
    this._trees = new Map();
  }

  _run(args) {
    return new Promise((resolve, reject) => {
      // Replacement refs and grafts would substitute other objects for the
      // commit and tree asked for, so neither is honored.
      execFile(this.git, ['--no-replace-objects', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.ext.allow=never', '-c', 'protocol.fd.allow=never', '-c', 'protocol.file.allow=' + (this.allowFileUrls ? 'always' : 'never'), ...args], {
        timeout: this.timeout,
        maxBuffer: 512 * 1024 * 1024,
        encoding: 'buffer',
        env: {
          PATH: process.env.PATH, HOME: this.cacheDir, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_NO_REPLACE_OBJECTS: '1', GIT_GRAFT_FILE: '/dev/null', LC_ALL: 'C',
        },
      }, (error, stdout, stderr) => {
        if (error) {
          // The subcommand is the first argument that is not an option or an option's value.
          const command = args.find((argument, index) => !argument.startsWith('-') && args[index - 1] !== '-c' && args[index - 1] !== '--git-dir');
          error.message = `git ${command} failed: ${(String(stderr).trim() || error.message).split('\n').pop()}`;
          reject(error);
          return;
        }

        resolve(stdout);
      });
    });
  }

  _checkUrl(url) {
    if (/^https:\/\/[\w.-]+(?::\d+)?\/[\w./~%-]+$/.test(url) && !url.includes('..')) {
      return;
    }

    if (this.allowFileUrls && /^(?:file:\/\/)?\/[\w./-]+$/.test(url)) {
      return;
    }

    throw new Error(`Unsupported repository URL: ${String(url).slice(0, 100)}`);
  }

  /**
   * A bare, blobless clone holding `commit`.
   * @param {string} url
   * @param {string} commit
   * @returns {Promise<string>} git directory
   */
  async _repository(url, commit) {
    this._checkUrl(url);
    if (!COMMIT.test(commit)) {
      throw new TypeError(`Invalid commit id: ${String(commit).slice(0, 50)}`);
    }

    const directory = path.join(this.cacheDir, `${sha256(url).slice(0, 16)}.git`);
    const key = `${url}#${commit}`;
    if (!this._repos.has(key)) {
      this._repos.set(key, (async () => {
        if (!fs.existsSync(path.join(directory, 'HEAD'))) {
          fs.mkdirSync(this.cacheDir, {recursive: true});
          await this._run(['init', '--bare', '--quiet', directory]);
          await this._run(['--git-dir', directory, 'remote', 'add', 'origin', url]);
        }

        try {
          await this._run(['--git-dir', directory, 'cat-file', '-e', `${commit}^{commit}`]);
        } catch {
          await this._run(['--git-dir', directory, '-c', 'remote.origin.promisor=true', '-c', 'remote.origin.partialclonefilter=blob:none', 'fetch', '--quiet', '--filter=blob:none', 'origin', commit]);
        }

        return directory;
      })());
      this._repos.get(key).catch(() => this._repos.delete(key));
    }

    return this._repos.get(key);
  }

  /**
   * Every file in a commit's tree.
   * @param {string} url
   * @param {string} commit
   * @returns {Promise<Map<string, {mode: string, blob: string}>>}
   */
  async tree(url, commit) {
    const key = `${url}#${commit}`;
    if (!this._trees.has(key)) {
      this._trees.set(key, (async () => {
        const directory = await this._repository(url, commit);
        const listing = (await this._run(['--git-dir', directory, 'ls-tree', '-r', '-z', '--full-tree', commit])).toString('utf8');
        const files = new Map();
        for (const record of listing.split('\0')) {
          const match = record.match(/^(\d{6}) (blob|commit) ([\da-f]{40,64})\t(.+)$/s);
          if (match && match[2] === 'blob') {
            files.set(match[4], {mode: match[1], blob: match[3]});
          }
        }

        return files;
      })());
      this._trees.get(key).catch(() => this._trees.delete(key));
    }

    return this._trees.get(key);
  }

  /**
   * One file's contents at a commit (fetched on demand).
   * @param {string} url
   * @param {string} commit
   * @param {string} file
   * @returns {Promise<Buffer|null>} null when the commit has no such file
   */
  async file(url, commit, file) {
    const files = await this.tree(url, commit);
    const entry = files.get(file);
    if (!entry) {
      return null;
    }

    const directory = await this._repository(url, commit);
    return this._run(['--git-dir', directory, '-c', 'remote.origin.promisor=true', '-c', 'remote.origin.partialclonefilter=blob:none', 'cat-file', 'blob', entry.blob]);
  }
}

/**
 * Paths `git archive` leaves out: the export-ignore attribute of a commit's
 * top-level .gitattributes (patterns are matched like .gitignore patterns
 * anchored at the top).
 *
 * @param {string|null} text - .gitattributes
 * @returns {(file: string) => boolean}
 */
function exportIgnore(text) {
  const patterns = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const [pattern, ...attributes] = line.split(/\s+/);
    if (attributes.includes('export-ignore')) {
      patterns.push(pattern);
    } else if (attributes.includes('-export-ignore') || attributes.includes('!export-ignore')) {
      patterns.push(`!${pattern}`);
    }
  }

  const toRegExp = pattern => {
    let source = pattern.replace(/^\//, '').replace(/\/$/, '');
    const anchored = pattern.startsWith('/') || source.includes('/');
    // A leading "**/" and a "/**/" match zero or more directories.
    source = source.replaceAll(/[$()+.[\\\]^{|}]/g, String.raw`\$&`)
      .replace(/^\*\*\//, '\u0001')
      .replaceAll('/**/', '/\u0001')
      .replaceAll('**', '\0')
      .replaceAll('*', '[^/]*')
      .replaceAll('?', '[^/]')
      .replaceAll('\0', '.*')
      .replaceAll('\u0001', '(?:.*/)?');
    return new RegExp(`^${anchored ? '' : '(?:.*/)?'}${source}(?:/.*)?$`);
  };

  const rules = patterns.map(pattern => (pattern.startsWith('!') ? {negate: true, regex: toRegExp(pattern.slice(1))} : {negate: false, regex: toRegExp(pattern)}));
  return file => {
    let ignored = false;
    for (const rule of rules) {
      if (rule.regex.test(file)) {
        ignored = !rule.negate;
      }
    }

    return ignored;
  };
}

module.exports = {GitTrees, exportIgnore};
