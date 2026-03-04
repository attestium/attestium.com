const {test} = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const Attestium = require('../lib/index');

test('continuous verification timer test', async () => {
  const attestium = new Attestium({
    projectRoot: path.join(__dirname, '..'),
    continuousVerification: false,
    verificationInterval: 60_000,
  });
  attestium.startContinuousVerification(60_000);
  assert.ok(attestium._verificationTimer);
  attestium.stopContinuousVerification();
  assert.strictEqual(attestium._verificationTimer, null);
});
