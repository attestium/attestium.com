/**
 * Attestium - language runtime profiles
 *
 * Every language runtime has its own ways to load code that is not part of
 * the application: environment variables, command-line options, start-up
 * hooks and debug ports.  A profile names them so a process can be checked
 * for them whatever it is written in.
 *
 * Detection uses what the kernel shows about a process: the executable's
 * name and the shared libraries it has mapped (libjvm.so is the JVM whatever
 * the launcher is called).  Nothing is executed.
 *
 * inspect() returns findings of three severities:
 *   critical  code other than the application's can run in the process
 *   warning   the process could be controlled or inspected from outside,
 *             or its start-up options cannot be read
 *   info      context
 *
 * @license MIT
 */

'use strict';

const path = require('node:path');

// ─── Node.js ───────────────────────────────────────────────────────────

// Options that run or load code other than the application's entry point.
const NODE_PRELOAD_FLAGS = new Set([
  '-r',
  '--require',
  '--import',
  '--loader',
  '--experimental-loader',
  '-e',
  '--eval',
  '-p',
  '--print',
  '--env-file',
  '--env-file-if-exists',
  '--experimental-config-file',
  '--experimental-policy',
  '--snapshot-blob',
]);
// Options that open the inspector.  --inspect-port and --inspect-publish-uid
// only configure it (Node.js 24's test runner passes both to every child);
// an inspector opened later with SIGUSR1 is found by its listening port.
const NODE_INSPECT_FLAG = /^--inspect(?:-brk(?:-node)?|-wait)?(?:=|$)/;
// Options whose value may follow as a separate argument; the value is not
// the script name.
const INSPECT_PORT_FLAGS = new Set(['--inspect-port', '--debug-port']);
const NODE_VALUE_FLAGS = new Set([
  '--inspect-port',
  '--debug-port',
  '--inspect-publish-uid',
  '--disable-warning',
  '--allow-fs-read',
  '--allow-fs-write',
  '--watch-kill-signal',
  '--test-shard',
  '--experimental-sea-config',
  '--run',
  '--v8-pool-size',
  '-C',
  '--conditions',
  '--title',
  '--input-type',
  '--icu-data-dir',
  '--openssl-config',
  '--tls-cipher-list',
  '--tls-keylog',
  '--diagnostic-dir',
  '--report-dir',
  '--report-directory',
  '--report-filename',
  '--report-signal',
  '--secure-heap',
  '--secure-heap-min',
  '--unhandled-rejections',
  '--trace-event-categories',
  '--trace-event-file-pattern',
  '--heapsnapshot-signal',
  '--redirect-warnings',
  '--use-largepages',
  '--dns-result-order',
  '--disable-proto',
  '--experimental-default-type',
  '--watch-path',
  '--localstorage-file',
  '--cpu-prof-dir',
  '--cpu-prof-name',
  '--heap-prof-dir',
  '--heap-prof-name',
  '--test-reporter',
  '--test-reporter-destination',
  '--test-name-pattern',
  '--test-skip-pattern',
  '--test-concurrency',
  '--test-timeout',
  '--max-http-header-size',
  '--stack-trace-limit',
]);

/**
 * Split an options string into arguments (supports double quotes), as
 * NODE_OPTIONS and similar variables are split.
 * @param {string} value
 * @returns {string[]}
 */
function splitOptions(value) {
  const args = [];
  let current = '';
  let quoted = false;
  let any = false;
  for (let i = 0; i < value.length; i++) {
    const char = value[i];
    if (char === '\\' && quoted && i + 1 < value.length) {
      current += value[++i];
      any = true;
    } else if (char === '"') {
      quoted = !quoted;
      any = true;
    } else if (/\s/.test(char) && !quoted) {
      if (any) {
        args.push(current);
      }

      current = '';
      any = false;
    } else {
      current += char;
      any = true;
    }
  }

  if (any) {
    args.push(current);
  }

  return args;
}

/**
 * Find Node.js preload/loader/inspector flags in an argument list.
 *
 * In a command line, scanning stops at the script name because later
 * arguments belong to the application.  A non-option right after an
 * unrecognized option may be that option's value, so scanning continues
 * past it.  NODE_OPTIONS has no script and is scanned to the end.
 *
 * @param {string[]} args
 * @param {Object} [options]
 * @param {boolean} [options.hasScript=true]
 * @returns {{preloads: string[], inspector: string[], ports: number[]}}
 */
function findNodeInjectionFlags(args, options = {}) {
  const hasScript = options.hasScript !== false;
  const preloads = [];
  const inspector = [];
  const ports = [];
  const addPort = value => {
    const match = String(value).match(/(?:^|:)(\d{1,5})$/);
    if (match) {
      ports.push(Number(match[1]));
    }
  };

  let previousUnknown = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--') {
      break;
    }

    const equals = arg.indexOf('=');
    const flag = equals === -1 ? arg : arg.slice(0, equals);
    // The inspector's port, for finding it listening after SIGUSR1.
    if (INSPECT_PORT_FLAGS.has(flag)) {
      addPort(equals === -1 ? args[i + 1] || '' : arg.slice(equals + 1));
    } else if (NODE_INSPECT_FLAG.test(arg) && equals !== -1) {
      addPort(arg.slice(equals + 1));
    }

    if (NODE_PRELOAD_FLAGS.has(flag)) {
      preloads.push(equals === -1 ? `${flag} ${args[i + 1] || ''}`.trim() : arg);
      if (equals === -1) {
        i++;
      }
    } else if (NODE_INSPECT_FLAG.test(arg)) {
      inspector.push(arg);
    } else if (NODE_VALUE_FLAGS.has(arg)) {
      i++;
    } else if (!arg.startsWith('-') && hasScript && !previousUnknown) {
      break;
    }

    previousUnknown = arg.startsWith('-') && equals === -1 && !NODE_PRELOAD_FLAGS.has(flag) && !NODE_VALUE_FLAGS.has(arg) && !NODE_INSPECT_FLAG.test(arg);
  }

  return {preloads, inspector, ports};
}

/**
 * The Node.js options PM2 started an application with, from its pm2_env
 * environment variable (JSON).
 *
 * @param {string|null} value
 * @returns {{name: string|null, script: string|null, nodeArgs: string[], interpreterArgs: string[]}|null}
 */
function parsePm2Environment(value) {
  if (typeof value !== 'string' || value.length > 4 * 1024 * 1024) {
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== 'object') {
    return null;
  }

  const argsOf = option => {
    if (Array.isArray(option)) {
      return option.map(String);
    }

    return typeof option === 'string' ? splitOptions(option) : [];
  };

  return {
    name: typeof parsed.name === 'string' ? parsed.name : null,
    script: typeof parsed.pm_exec_path === 'string' ? parsed.pm_exec_path : null,
    nodeArgs: argsOf(parsed.node_args),
    interpreterArgs: argsOf(parsed.interpreter_args),
  };
}

/**
 * The same from the variables PM2's fork mode sets instead (lists joined
 * with commas).
 *
 * @param {Object<string, string>} fields
 * @returns {{name: string|null, script: string, nodeArgs: string[], interpreterArgs: string[]}|null}
 */
function parsePm2Fields(fields) {
  if (fields.pm_exec_path === undefined) {
    return null;
  }

  const argsOf = value => (value ? value.split(',').flatMap(part => splitOptions(part)) : []);
  return {
    name: fields.name ?? null,
    script: fields.pm_exec_path,
    nodeArgs: argsOf(fields.node_args),
    interpreterArgs: argsOf(fields.interpreter_args),
  };
}

function inspectNode({environment, cmdline, raw, parentIsPm2}) {
  const findings = [];
  const ports = [];
  const add = (type, value, severity = 'critical') => findings.push({type, value, severity});
  const extra = {};

  if (environment.NODE_PATH !== undefined) {
    // Extra module directories, searched when node_modules has no match.
    add('NODE_PATH', environment.NODE_PATH, 'warning');
  }

  if (environment.NODE_OPTIONS !== undefined) {
    const flags = findNodeInjectionFlags(splitOptions(environment.NODE_OPTIONS), {hasScript: false});
    ports.push(...flags.ports);
    for (const preload of flags.preloads) {
      add('NODE_OPTIONS-preload', preload);
    }

    for (const inspect of flags.inspector) {
      add('NODE_OPTIONS-inspector', inspect);
    }
  }

  if (cmdline) {
    const flags = findNodeInjectionFlags(cmdline.slice(1));
    ports.push(...flags.ports);
    for (const preload of flags.preloads) {
      add('argv-preload', preload);
    }

    for (const inspect of flags.inspector) {
      add('argv-inspector', inspect);
    }

    // PM2 starts applications with the options in its configuration
    // (node_args), which it passes in the pm2_env variable, or as separate
    // variables in fork mode.
    const fields = {};
    for (const key of ['pm_exec_path', 'node_args', 'interpreter_args', 'name']) {
      if (environment[key] !== undefined) {
        fields[key] = environment[key];
      }
    }

    const pm2 = parsePm2Environment(environment.pm2_env ?? null) || parsePm2Fields(fields);
    if (pm2) {
      extra.pm2 = pm2;
      for (const args of [pm2.nodeArgs, pm2.interpreterArgs]) {
        const pm2Flags = findNodeInjectionFlags(args, {hasScript: false});
        ports.push(...pm2Flags.ports);
        for (const preload of pm2Flags.preloads) {
          add('pm2-node_args-preload', preload);
        }

        for (const inspect of pm2Flags.inspector) {
          add('pm2-node_args-inspector', inspect);
        }
      }
    }

    // A process that sets process.title overwrites its argument area,
    // hiding the options it started with.  A shorter title leaves NUL
    // padding (trailing empty arguments add one NUL each, so a few are not
    // padding); a title of any length leaves a single argument, where
    // Node.js running a script has at least two.
    const padding = raw.length - raw.replace(/\0+$/, '').length - 1;
    if (padding >= 3 || cmdline.length === 1) {
      extra.cmdlineRewritten = {hiddenBytes: Math.max(padding, 0), originalBytes: raw.length};
      // PM2 renames the applications it starts, whose options it passes in
      // pm2_env; only a child of the PM2 daemon is taken as one.  The
      // daemon itself is not exempt: any process can take its title, so
      // start the daemon outside the service's directory.
      if (!pm2 || !parentIsPm2()) {
        add('argv-rewritten', `the command line was replaced (${raw.length} bytes); the options the process started with cannot be read from it`, 'warning');
      }
    }
  }

  return {findings, ports, extra};
}

// ─── option scanners shared by the other runtimes ─────────────────────

/**
 * Scan an argument list for options, the way most runtimes parse theirs:
 * `-x value`, `-xvalue`, `--flag value`, `--flag=value`, stopping at the
 * first argument that is not an option (the script or main class).
 *
 * @param {string[]} args - arguments after the executable
 * @param {Object} spec
 * @param {Set<string>} spec.withValue - options that take a value
 * @param {Set<string>} [spec.terminal] - options after which the rest belongs to the program (-c, -m, -jar)
 * @param {boolean} [spec.combined=false] - single-letter options may be combined (-Es)
 * @param {Set<string>} [spec.attachedOnly] - combined options whose optional value is always attached
 * @param {boolean} [spec.all=false] - scan every argument (option strings in variables)
 * @returns {Array<{flag: string, value: string|null}>}
 */
function scanOptions(args, spec) {
  const found = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--') {
      break;
    }

    if (!arg.startsWith('-') || arg === '-') {
      if (spec.all) {
        continue;
      }

      break;
    }

    const equals = arg.indexOf('=');
    if (arg.startsWith('--')) {
      const flag = equals === -1 ? arg : arg.slice(0, equals);
      let value = equals === -1 ? null : arg.slice(equals + 1);
      if (value === null && spec.withValue.has(flag)) {
        value = args[++i] ?? '';
      }

      found.push({flag, value});
      if (spec.terminal && spec.terminal.has(flag)) {
        break;
      }

      continue;
    }

    if (spec.combined) {
      // -Es, -Wignore, -c "code": letters until one that takes a value.
      let stop = false;
      for (let j = 1; j < arg.length; j++) {
        const flag = `-${arg[j]}`;
        if (spec.attachedOnly && spec.attachedOnly.has(flag)) {
          // An optional value that can only be attached (perl -d:Trace, ruby -W2).
          found.push({flag, value: arg.slice(j + 1)});
          break;
        }

        if (spec.withValue.has(flag)) {
          const value = j + 1 < arg.length ? arg.slice(j + 1) : (args[++i] ?? '');
          found.push({flag, value});
          stop = spec.terminal && spec.terminal.has(flag);
          break;
        }

        found.push({flag, value: null});
      }

      if (stop) {
        break;
      }

      continue;
    }

    // Single-dash long options (-javaagent:x, -Dkey=value, -agentlib:jdwp=...)
    const known = [...spec.withValue].find(flag => arg === flag);
    if (known) {
      found.push({flag: known, value: args[++i] ?? ''});
      if (spec.terminal && spec.terminal.has(known)) {
        break;
      }

      continue;
    }

    found.push({flag: arg, value: null});
    if (spec.terminal && spec.terminal.has(arg)) {
      break;
    }
  }

  return found;
}

const addPortFrom = (ports, text) => {
  const match = String(text).match(/(?:^|[:=*])(\d{1,5})(?:$|[,/])/);
  if (match) {
    ports.push(Number(match[1]));
  }
};

// ─── Python ────────────────────────────────────────────────────────────

const PYTHON_WITH_VALUE = new Set(['-c', '-m', '-W', '-X', '--check-hash-based-pycs']);
const PYTHON_TERMINAL = new Set(['-c', '-m']);

function inspectPython({environment, cmdline}) {
  const findings = [];
  const ports = [];
  const add = (type, value, severity = 'critical') => findings.push({type, value, severity});
  const options = scanOptions((cmdline || []).slice(1), {withValue: PYTHON_WITH_VALUE, terminal: PYTHON_TERMINAL, combined: true});
  const has = flag => options.some(option => option.flag === flag);
  // -E and -I make Python ignore every PYTHON* variable.
  const ignoresEnvironment = has('-E') || has('-I');
  const noSite = has('-S');

  for (const option of options) {
    if (option.flag === '-c') {
      add('argv-code', option.value);
    } else if (option.flag === '-i') {
      add('argv-interactive', '-i', 'warning');
    } else if (option.flag === '-m' && /^(?:debugpy|ptvsd|pdb|pydevd)(?:\.|$)/.test(option.value)) {
      add('debugger', `-m ${option.value}`);
    } else if (option.flag === '-W' && warningImports(option.value)) {
      add('argv-warnings-import', option.value);
    } else if (option.flag === '-X' && option.value.startsWith('pycache_prefix=')) {
      add('argv-pycache-prefix', option.value);
    }
  }

  if (!ignoresEnvironment) {
    const critical = ['PYTHONPATH', 'PYTHONHOME', 'PYTHONPLATLIBDIR', 'PYTHONPYCACHEPREFIX', 'PYTHONEXECUTABLE'];
    for (const name of critical) {
      if (environment[name] !== undefined && environment[name] !== '') {
        add(name, environment[name]);
      }
    }

    if (environment.PYTHONINSPECT) {
      add('PYTHONINSPECT', environment.PYTHONINSPECT, 'warning');
    }

    if (environment.PYTHONSTARTUP) {
      // Only interactive sessions run it.
      add('PYTHONSTARTUP', environment.PYTHONSTARTUP, 'warning');
    }

    if (environment.PYTHONUSERBASE && !environment.PYTHONNOUSERSITE && !has('-s') && !noSite) {
      add('PYTHONUSERBASE', environment.PYTHONUSERBASE, 'warning');
    }

    // Breakpoint() imports and calls whatever this names.
    const breakpoint = environment.PYTHONBREAKPOINT;
    if (breakpoint !== undefined && breakpoint !== '' && breakpoint !== '0' && breakpoint !== 'pdb.set_trace') {
      add('PYTHONBREAKPOINT', breakpoint);
    }

    if (environment.PYTHONWARNINGS && environment.PYTHONWARNINGS.split(',').some(filter => warningImports(filter))) {
      add('PYTHONWARNINGS-import', environment.PYTHONWARNINGS);
    }
  }

  if (environment.DEBUGPY_LAUNCHER_PORT !== undefined || environment.PYDEVD_LOAD_VALUES_ASYNC !== undefined) {
    add('debugger', 'debugpy environment present');
  }

  return {findings, ports, extra: {ignoresEnvironment, noSite}};
}

/**
 * A warnings filter "action:message:category:module:lineno" whose category
 * names a class in a module: Python imports that module to resolve it.
 * @param {string} filter
 * @returns {boolean}
 */
function warningImports(filter) {
  const category = String(filter).split(':')[2] || '';
  return category.includes('.');
}

// ─── JVM ───────────────────────────────────────────────────────────────

const JVM_WITH_VALUE = new Set(['-cp', '-classpath', '--class-path', '-jar', '--module-path', '-p', '-m', '--module', '--add-modules', '--add-opens', '--add-exports', '--add-reads', '--patch-module', '--upgrade-module-path', '--limit-modules']);
const JVM_TERMINAL = new Set(['-jar', '-m', '--module']);

function inspectJvm({environment, cmdline}) {
  const findings = [];
  const ports = [];
  const add = (type, value, severity = 'critical') => findings.push({type, value, severity});
  const sources = [
    ['JAVA_TOOL_OPTIONS', environment.JAVA_TOOL_OPTIONS],
    ['JDK_JAVA_OPTIONS', environment.JDK_JAVA_OPTIONS],
    ['_JAVA_OPTIONS', environment._JAVA_OPTIONS],
  ];
  const all = [];
  for (const [name, value] of sources) {
    if (value !== undefined) {
      all.push(...splitOptions(value).map(argument => [name, argument]));
    }
  }

  const argv = scanOptions((cmdline || []).slice(1), {withValue: JVM_WITH_VALUE, terminal: JVM_TERMINAL});
  for (const option of argv) {
    all.push(['argv', option.value === null ? option.flag : `${option.flag}=${option.value}`]);
  }

  let attachDisabled = false;
  let hasClassPath = false;
  for (const [source, argument] of all) {
    const label = `${source}: ${argument}`;
    if (argument.startsWith('-javaagent:')) {
      add('jvm-javaagent', label);
    } else if (argument.startsWith('-agentlib:jdwp')) {
      add('debugger', label);
      addPortFrom(ports, argument.replace(/^.*address=/, ''));
    } else if (/^-(?:agentlib|agentpath):/.test(argument)) {
      add('jvm-native-agent', label);
    } else if (/^-Xbootclasspath\/[ap]:/.test(argument)) {
      add('jvm-bootclasspath', label);
    } else if (/^-Djava\.system\.class\.loader=/.test(argument)) {
      add('jvm-system-class-loader', label);
    } else if (/^-Dcom\.sun\.management\.jmxremote(?:\.port|\.rmi\.port)?(?:=|$)/.test(argument)) {
      add('jvm-remote-management', label);
      if (/\.port=/.test(argument)) {
        addPortFrom(ports, argument.replace(/^.*=/, ''));
      }
    } else if (/^-XX:\+EnableDynamicAgentLoading$|^-Djdk\.attach\.allowAttachSelf=true$|^-XX:\+StartAttachListener$/.test(argument)) {
      add('jvm-attach', label, 'warning');
    } else if (/^-XX:On(?:Error|OutOfMemoryError)=/.test(argument)) {
      add('jvm-on-error-command', label, 'warning');
    } else if (argument === '-XX:+DisableAttachMechanism') {
      attachDisabled = true;
    } else if (/^(?:-cp|-classpath|--class-path|-jar)(?:=|$)/.test(argument)) {
      hasClassPath = true;
    }
  }

  // Without -cp, -classpath or -jar the JVM takes its class path from $CLASSPATH.
  if (environment.CLASSPATH !== undefined && !hasClassPath) {
    add('CLASSPATH', environment.CLASSPATH, 'warning');
  }

  return {findings, ports, extra: {attachDisabled}};
}

// ─── Ruby ──────────────────────────────────────────────────────────────

const RUBY_WITH_VALUE = new Set(['-r', '-I', '-e', '-C', '-E', '--encoding', '--external-encoding', '--internal-encoding', '--disable', '--enable', '--dump']);
const RUBY_ATTACHED = new Set(['-x', '-0', '-W', '-F', '-T']);

// `bundle exec` requires Bundler's setup through RUBYOPT and puts Bundler's
// own lib directory (the installed bundler gem's) first on RUBYLIB.
const BUNDLER_LIB = /^\/(?:[^/\0]+\/)*gems\/bundler-(\d+(?:\.[\da-z]+)*)\/lib$/;

/**
 * Bundler's own RUBYOPT and RUBYLIB, exactly as `bundle exec` sets them:
 * RUBYLIB is one directory, the lib directory of an installed bundler gem,
 * and RUBYOPT only requires bundler/setup (by name, or from that
 * directory).  Anything added to either is not Bundler's.
 *
 * @param {Object<string, string>} environment
 * @returns {{lib: string, version: string}|null}
 */
function bundlerSetup(environment) {
  const lib = environment.RUBYLIB;
  const match = typeof lib === 'string' ? lib.match(BUNDLER_LIB) : null;
  if (!match || lib.split('/').some(part => part === '.' || part === '..') || typeof environment.RUBYOPT !== 'string') {
    return null;
  }

  const setups = new Set([`${lib}/bundler/setup`, 'bundler/setup']);
  const options = splitOptions(environment.RUBYOPT);
  const required = options.length === 1 && options[0].startsWith('-r') ? options[0].slice(2) : (options.length === 2 && options[0] === '-r' ? options[1] : null);
  return setups.has(required) ? {lib, version: match[1]} : null;
}

/**
 * `bundle exec` with the Bundler a Ruby ships in its standard library (a
 * default gem, as Debian and Ubuntu install it): RUBYLIB is left alone
 * (empty), and RUBYOPT only requires the setup file from the interpreter's
 * own library directory, `<prefix>/lib/ruby/<version>/bundler/setup` for
 * `<prefix>/bin/ruby`.  That file is part of the standard library every
 * Ruby process of that interpreter loads from.
 *
 * @param {Object<string, string>} environment
 * @param {string} [exe] - the interpreter's path
 * @returns {{setup: string}|null}
 */
function standardBundlerSetup(environment, exe) {
  const prefix = typeof exe === 'string' ? exe.match(/^((?:\/[^/\0]+)*)\/bin\/ruby[\d.]*$/) : null;
  if (!prefix || environment.RUBYLIB || typeof environment.RUBYOPT !== 'string') {
    return null;
  }

  const options = splitOptions(environment.RUBYOPT);
  const required = options.length === 1 && options[0].startsWith('-r') ? options[0].slice(2) : (options.length === 2 && options[0] === '-r' ? options[1] : null);
  const library = `${prefix[1]}/lib/ruby/`;
  return typeof required === 'string' && required.startsWith(library) && /^\d+\.\d+\.\d+\/bundler\/setup$/.test(required.slice(library.length)) && !required.split('/').some(part => part === '.' || part === '..')
    ? {setup: required}
    : null;
}

function inspectRuby({environment, cmdline, exe}) {
  const findings = [];
  const ports = [];
  const add = (type, value, severity = 'critical') => findings.push({type, value, severity});
  const report = (source, options) => {
    for (const option of options) {
      switch (option.flag) {
        case '-r': {
          add(/^debug(?:\/|$)/.test(option.value) ? 'debugger' : `${source}-require`, `-r ${option.value}`);

          break;
        }

        case '-I': {
          add(`${source}-include`, `-I ${option.value}`);

          break;
        }

        case '-e': {
          add(`${source}-code`, option.value);

          break;
        }
      // No default
      }
    }
  };

  report('argv', scanOptions((cmdline || []).slice(1), {withValue: RUBY_WITH_VALUE, attachedOnly: RUBY_ATTACHED, combined: true}));
  // Bundler's own values are context: what they load is the bundler gem's
  // lib directory, which a verifier compares with the published gem.
  const bundler = bundlerSetup(environment);
  if (bundler) {
    add('bundler-setup', environment.RUBYOPT, 'info');
    add('bundler-rubylib', bundler.lib, 'info');
  } else if (standardBundlerSetup(environment, exe)) {
    add('bundler-setup', environment.RUBYOPT, 'info');
  } else {
    if (environment.RUBYOPT) {
      report('RUBYOPT', scanOptions(splitOptions(environment.RUBYOPT), {
        withValue: RUBY_WITH_VALUE, attachedOnly: RUBY_ATTACHED, combined: true, all: true,
      }));
    }

    if (environment.RUBYLIB) {
      add('RUBYLIB', environment.RUBYLIB);
    }
  }

  // A Gemfile is Ruby code; RubyGems loads the one this names at start-up.
  if (environment.RUBYGEMS_GEMDEPS) {
    add('RUBYGEMS_GEMDEPS', environment.RUBYGEMS_GEMDEPS);
  }

  // Where gems and the Gemfile are loaded from; checked gem directories
  // and the project's Gemfile are what the audit covers.
  for (const name of ['BUNDLE_GEMFILE', 'GEM_PATH', 'GEM_HOME', 'BUNDLE_PATH']) {
    if (environment[name]) {
      add(name, environment[name], 'info');
    }
  }

  if (environment.RUBY_DEBUG_OPEN !== undefined) {
    add('debugger', 'RUBY_DEBUG_OPEN');
    addPortFrom(ports, environment.RUBY_DEBUG_PORT || '');
  }

  return {findings, ports, extra: bundler ? {bundler} : {}};
}

// ─── .NET ──────────────────────────────────────────────────────────────

function inspectDotnet({environment}) {
  const findings = [];
  const add = (type, value, severity = 'critical') => findings.push({type, value, severity});
  const knob = name => environment[`DOTNET_${name}`] ?? environment[`COMPlus_${name}`];
  for (const name of ['DOTNET_STARTUP_HOOKS', 'DOTNET_ADDITIONAL_DEPS', 'DOTNET_SHARED_STORE']) {
    if (environment[name]) {
      add(name, environment[name]);
    }
  }

  const profiling = environment.CORECLR_ENABLE_PROFILING ?? environment.COR_ENABLE_PROFILING;
  if (profiling === '1') {
    const profiler = environment.CORECLR_PROFILER_PATH || environment.CORECLR_PROFILER_PATH_64 || environment.CORECLR_PROFILER || '';
    add('dotnet-profiler', profiler);
  }

  // A diagnostic port the runtime connects out to lets that tool control it.
  if (knob('DiagnosticPorts')) {
    add('dotnet-diagnostic-port', knob('DiagnosticPorts'));
  }

  return {findings, ports: [], extra: {diagnosticsDisabled: knob('EnableDiagnostics') === '0'}};
}

// ─── Erlang / Elixir (BEAM) ────────────────────────────────────────────

function inspectBeam({environment, cmdline}) {
  const findings = [];
  const add = (type, value, severity = 'critical') => findings.push({type, value, severity});
  for (const name of ['ERL_FLAGS', 'ERL_AFLAGS', 'ERL_ZFLAGS']) {
    const value = environment[name];
    if (value) {
      const args = splitOptions(value);
      for (const [index, argument] of args.entries()) {
        if (['-eval', '-s', '-run', '-pa', '-pz', '-boot', '-config'].includes(argument)) {
          add(`${name}${argument}`, `${argument} ${args[index + 1] || ''}`.trim());
        }
      }
    }
  }

  if (environment.ERL_LIBS) {
    add('ERL_LIBS', environment.ERL_LIBS);
  }

  const args = cmdline || [];
  const distributed = args.some((argument, index) => (argument === '-name' || argument === '-sname') && args[index + 1] && args[index + 1] !== 'undefined');
  if (distributed) {
    // Any node holding the cookie can run code in this one.
    add('beam-distribution', 'distributed Erlang is enabled; holders of the cookie can run code in this node', 'warning');
  }

  return {findings, ports: [], extra: {distributed}};
}

// ─── PHP ───────────────────────────────────────────────────────────────

const PHP_WITH_VALUE = new Set(['-d', '-c', '-r', '-f', '-z', '-B', '-R', '-F', '-E', '-t', '-S']);
const PHP_TERMINAL = new Set(['-r', '-f']);

function inspectPhp({environment, cmdline}) {
  const findings = [];
  const add = (type, value, severity = 'critical') => findings.push({type, value, severity});
  for (const name of ['PHP_INI_SCAN_DIR', 'PHPRC']) {
    if (environment[name] !== undefined && environment[name] !== '') {
      add(name, environment[name]);
    }
  }

  for (const option of scanOptions((cmdline || []).slice(1), {withValue: PHP_WITH_VALUE, terminal: PHP_TERMINAL, combined: true})) {
    if (option.flag === '-d' && /^\s*(?:auto_prepend_file|auto_append_file|extension|zend_extension|include_path|opcache\.preload)\s*=/.test(option.value)) {
      add('argv-ini', `-d ${option.value}`);
    } else {
      switch (option.flag) {
        case '-r':
        case '-B':
        case '-R':
        case '-E': {
          add('argv-code', `${option.flag} ${option.value}`);

          break;
        }

        case '-z': {
          add('argv-zend-extension', `-z ${option.value}`);

          break;
        }

        case '-c': {
          add('argv-ini-file', `-c ${option.value}`, 'warning');

          break;
        }
 // No default
      }
    }
  }

  return {findings, ports: [], extra: {}};
}

// ─── Perl ──────────────────────────────────────────────────────────────

const PERL_WITH_VALUE = new Set(['-e', '-E', '-I', '-M', '-m']);
const PERL_ATTACHED = new Set(['-d', '-D', '-i', '-l', '-0', '-C', '-x']);

function inspectPerl({environment, cmdline}) {
  const findings = [];
  const add = (type, value, severity = 'critical') => findings.push({type, value, severity});
  const report = (source, options) => {
    for (const option of options) {
      switch (option.flag) {
        case '-M':
        case '-m': {
          add(`${source}-module`, `${option.flag}${option.value}`);

          break;
        }

        case '-I': {
          add(`${source}-include`, `-I${option.value}`);

          break;
        }

        case '-e':
        case '-E': {
          add(`${source}-code`, option.value);

          break;
        }

        case '-d': {
          add('debugger', `-d${option.value}`);

          break;
        }
      // No default
      }
    }
  };

  report('argv', scanOptions((cmdline || []).slice(1), {withValue: PERL_WITH_VALUE, attachedOnly: PERL_ATTACHED, combined: true}));
  if (environment.PERL5OPT) {
    report('PERL5OPT', scanOptions(splitOptions(environment.PERL5OPT), {
      withValue: PERL_WITH_VALUE, attachedOnly: PERL_ATTACHED, combined: true, all: true,
    }));
  }

  for (const name of ['PERL5LIB', 'PERLLIB', 'PERL5DB']) {
    if (environment[name]) {
      add(name, environment[name]);
    }
  }

  return {findings, ports: [], extra: {}};
}

// ─── Deno and Bun ──────────────────────────────────────────────────────

function inspectDeno({cmdline}) {
  const findings = [];
  const ports = [];
  for (const argument of (cmdline || []).slice(1)) {
    if (/^--inspect(?:-brk|-wait)?(?:=|$)/.test(argument)) {
      findings.push({type: 'argv-inspector', value: argument, severity: 'critical'});
      addPortFrom(ports, argument.replace(/^[^=]*=?/, ''));
    }
  }

  return {findings, ports, extra: {}};
}

function inspectBun({environment, cmdline}) {
  const findings = [];
  const ports = [];
  const args = (cmdline || []).slice(1);
  for (const [index, argument] of args.entries()) {
    if (argument === '--preload' || argument === '-r' || argument === '--require') {
      findings.push({type: 'argv-preload', value: `${argument} ${args[index + 1] || ''}`.trim(), severity: 'critical'});
    } else if (argument.startsWith('--preload=')) {
      findings.push({type: 'argv-preload', value: argument, severity: 'critical'});
    } else if (/^--inspect(?:-brk|-wait)?(?:=|$)/.test(argument)) {
      findings.push({type: 'argv-inspector', value: argument, severity: 'critical'});
    }
  }

  if (environment.BUN_INSPECT) {
    findings.push({type: 'BUN_INSPECT', value: environment.BUN_INSPECT, severity: 'critical'});
  }

  if (environment.NODE_OPTIONS) {
    const flags = findNodeInjectionFlags(splitOptions(environment.NODE_OPTIONS), {hasScript: false});
    for (const preload of flags.preloads) {
      findings.push({type: 'NODE_OPTIONS-preload', value: preload, severity: 'critical'});
    }
  }

  return {findings, ports, extra: {}};
}

// ─── every process ─────────────────────────────────────────────────────

/**
 * Injection through the dynamic linker and C library, for any process.
 * @param {Object<string, string>} environment
 * @returns {Array<{type: string, value: string, severity: string}>}
 */
function inspectNative(environment) {
  const findings = [];
  for (const name of ['LD_PRELOAD', 'LD_AUDIT']) {
    if (environment[name] !== undefined) {
      findings.push({type: name, value: environment[name], severity: 'critical'});
    }
  }

  // Iconv loads conversion modules from here.
  if (environment.GCONV_PATH !== undefined) {
    findings.push({type: 'GCONV_PATH', value: environment.GCONV_PATH, severity: 'critical'});
  }

  // OpenSSL loads engines and providers named by its configuration.
  for (const name of ['OPENSSL_CONF', 'OPENSSL_ENGINES', 'OPENSSL_MODULES']) {
    if (environment[name] !== undefined) {
      findings.push({type: name, value: environment[name], severity: 'warning'});
    }
  }

  return findings;
}

// ─── profiles and detection ────────────────────────────────────────────

/**
 * Runtime profiles.  `executable` matches the executable's file name,
 * `library` a mapped shared library (for launchers and embedders with
 * other names), `version` extracts a version from a path when it has one.
 */
const PROFILES = {
  node: {
    name: 'node', label: 'Node.js', executable: /^(?:node|nodejs)$/, library: /\/libnode\.so[\d.]*$/, inspect: inspectNode, debugPorts: [9229],
  },
  python: {
    name: 'python', label: 'Python', executable: /^python(?:\d+(?:\.\d+)*)?[dmu]*$|^pypy\d*(?:\.\d+)?$|^uwsgi$/, library: /\/libpython(\d+\.\d+)[dmu]*\.so[\d.]*$/, version: /python(\d+\.\d+)/, inspect: inspectPython, debugPorts: [5678],
  },
  jvm: {
    name: 'jvm', label: 'JVM', executable: /^java$/, library: /\/libjvm\.so$/, version: /\/(?:jdk|java|temurin|zulu|openjdk)-?(\d+(?:\.\d+)*)/, inspect: inspectJvm, debugPorts: [],
  },
  ruby: {
    name: 'ruby', label: 'Ruby', executable: /^ruby(?:\d+(?:\.\d+)*)?$/, library: /\/libruby(?:-\d+(?:\.\d+)*)?\.so[\d.]*$/, version: /libruby[-.]?(?:so\.)?(\d+(?:\.\d+){1,2})/, inspect: inspectRuby, debugPorts: [],
  },
  dotnet: {
    name: 'dotnet', label: '.NET', executable: /^dotnet$/, library: /\/libcoreclr\.so$/, version: /Microsoft\.NETCore\.App\/(\d+\.\d+\.\d+)/, inspect: inspectDotnet, debugPorts: [],
    // W^X: CoreCLR maps JIT code twice (writable, and executable) from one memfd.
    memfds: {doublemapper: 'the .NET runtime\'s W^X double mapping of JIT code'},
  },
  beam: {
    name: 'beam', label: 'Erlang/Elixir (BEAM)', executable: /^beam(?:\.smp)?$/, library: null, version: /erts-(\d+(?:\.\d+)*)/, inspect: inspectBeam, debugPorts: [],
    // The JIT (asmjit) maps generated code twice from one memfd.
    memfds: {vmem: 'the BEAM JIT\'s dual mapping of generated code'},
  },
  php: {
    name: 'php', label: 'PHP', executable: /^php(?:-fpm|-cgi)?(?:\d+(?:\.\d+)*)?$/, library: /\/libphp\d*(?:\.\d+)?\.so$/, version: /php(?:-fpm)?(\d+\.\d+)/, inspect: inspectPhp, debugPorts: [],
  },
  perl: {
    name: 'perl', label: 'Perl', executable: /^perl(?:\d+(?:\.\d+)*)?$/, library: /\/libperl\.so[\d.]*$/, version: /libperl\.so\.(\d+(?:\.\d+){1,2})/, inspect: inspectPerl, debugPorts: [],
  },
  deno: {
    name: 'deno', label: 'Deno', executable: /^deno$/, library: null, inspect: inspectDeno, debugPorts: [9229],
  },
  bun: {
    name: 'bun', label: 'Bun', executable: /^bun$/, library: null, inspect: inspectBun, debugPorts: [6499],
  },
};

const NATIVE = {
  name: 'native', label: 'Native', executable: null, library: null, inspect: () => ({findings: [], ports: [], extra: {}}), debugPorts: [],
};

/**
 * Whether a memfd is one the runtime itself creates for its JIT: the
 * profile names it, and the process runs that runtime.  Other memfds, and
 * the same names in other processes, are not recognized.
 *
 * @param {string|null} runtime - profile name
 * @param {string} target - /memfd:<name>, as in /proc/<pid>/maps or fd/
 * @returns {string|null} what the memfd is, or null
 */
function runtimeMemfd(runtime, target) {
  const profile = Object.hasOwn(PROFILES, String(runtime)) ? PROFILES[runtime] : null;
  const match = String(target).match(/^\/memfd:(.+?)(?: \(deleted\))?$/);
  return profile && profile.memfds && match && Object.hasOwn(profile.memfds, match[1]) ? profile.memfds[match[1]] : null;
}

/**
 * Detect a process's runtime.
 *
 * @param {Object} input
 * @param {string|null} input.exe - executable path
 * @param {string[]} [input.libraries] - mapped files
 * @param {boolean} [input.nodeRelease] - the binary carries an official Node.js release URL
 * @returns {{name: string, label: string, version: string|null, by: string}}
 */
function detectRuntime({exe, libraries = [], nodeRelease = false}) {
  const base = exe ? path.basename(exe) : '';
  if (nodeRelease) {
    return {
      name: 'node', label: PROFILES.node.label, version: null, by: 'release',
    };
  }

  for (const profile of Object.values(PROFILES)) {
    if (profile.library) {
      const library = libraries.find(file => profile.library.test(file));
      if (library) {
        return {
          name: profile.name, label: profile.label, version: versionOf(profile, [library, exe || '']), by: 'library',
        };
      }
    }
  }

  for (const profile of Object.values(PROFILES)) {
    if (profile.executable.test(base)) {
      return {
        name: profile.name, label: profile.label, version: versionOf(profile, [exe, ...libraries]), by: 'executable',
      };
    }
  }

  return {
    name: 'native', label: NATIVE.label, version: null, by: 'default',
  };
}

function versionOf(profile, candidates) {
  if (!profile.version) {
    return null;
  }

  for (const candidate of candidates) {
    const match = String(candidate).match(profile.version);
    if (match) {
      return match[1];
    }
  }

  return null;
}

/**
 * Check a process's environment and command line for its runtime's
 * injection vectors, and for the dynamic linker's.
 *
 * @param {string} runtime - profile name ('native' for none)
 * @param {Object} input
 * @param {Object<string, string>} input.environment
 * @param {string[]} [input.duplicates] - environment names set more than once
 * @param {string[]|null} input.cmdline - null when unreadable
 * @param {string} [input.exe] - the executable's path, as the process sees it
 * @param {string} [input.raw] - /proc/<pid>/cmdline as read (for rewrite detection)
 * @param {() => boolean} [input.parentIsPm2]
 * @returns {{findings: Object[], ports: number[], extra: Object}}
 */
function inspectRuntime(runtime, input) {
  const profile = PROFILES[runtime] || NATIVE;
  const result = profile.inspect({
    environment: input.environment,
    cmdline: input.cmdline,
    exe: input.exe,
    raw: input.raw ?? '',
    parentIsPm2: input.parentIsPm2 || (() => false),
  });
  result.findings.unshift(...inspectNative(input.environment));
  if (input.duplicates && input.duplicates.length > 0) {
    result.findings.push({type: 'environment-duplicates', value: input.duplicates.join(' '), severity: 'warning'});
  }

  result.ports = [...new Set([...profile.debugPorts, ...result.ports])].sort((a, b) => a - b);
  return result;
}

/**
 * Parse /proc/<pid>/environ contents.  getenv() returns the first of
 * duplicate entries, which is the value kept; other readers (the dynamic
 * linker, a runtime's own parser) may take another, so names that occur
 * more than once are listed too.
 *
 * @param {string} text
 * @returns {{values: Object<string, string>, duplicates: string[]}}
 */
function parseEnviron(text) {
  const values = Object.create(null);
  const duplicates = new Set();
  for (const entry of text.split('\0')) {
    const equals = entry.indexOf('=');
    if (equals > 0) {
      const key = entry.slice(0, equals);
      if (key in values) {
        duplicates.add(key);
      } else {
        values[key] = entry.slice(equals + 1);
      }
    }
  }

  return {values, duplicates: [...duplicates].sort()};
}

module.exports = {
  PROFILES,
  NATIVE,
  detectRuntime,
  inspectRuntime,
  inspectNative,
  runtimeMemfd,
  bundlerSetup,
  standardBundlerSetup,
  parseEnviron,
  scanOptions,
  splitOptions,
  findNodeInjectionFlags,
  parsePm2Environment,
  parsePm2Fields,
  warningImports,
};
