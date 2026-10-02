'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const runtimes = require('../lib/runtimes');

test('Ruby: the Gemfile RubyGems loads, and where gems come from', () => {
  const environment = {
    RUBYGEMS_GEMDEPS: '/srv/app/Gemfile',
    BUNDLE_GEMFILE: '/srv/app/Gemfile',
    GEM_PATH: '/opt/gems:/usr/lib/ruby/gems',
    GEM_HOME: '/opt/gems',
    BUNDLE_PATH: '',
  };
  const {findings, ports} = runtimes.inspectRuntime('ruby', {environment, cmdline: ['ruby', 'app.rb']});
  assert.deepEqual(findings, [
    {type: 'RUBYGEMS_GEMDEPS', value: '/srv/app/Gemfile', severity: 'critical'},
    {type: 'BUNDLE_GEMFILE', value: '/srv/app/Gemfile', severity: 'info'},
    {type: 'GEM_PATH', value: '/opt/gems:/usr/lib/ruby/gems', severity: 'info'},
    {type: 'GEM_HOME', value: '/opt/gems', severity: 'info'},
  ]);
  assert.deepEqual(ports, []);

  // Nothing to report for a plain environment.
  assert.deepEqual(runtimes.inspectRuntime('ruby', {environment: {RUBYGEMS_GEMDEPS: ''}, cmdline: ['ruby', 'app.rb']}).findings, []);
});
