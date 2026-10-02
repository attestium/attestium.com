/**
 * Challenge-response over SSH: the verifier's key may run one command on
 * the server, the attester, and nothing else.  The server publishes no
 * endpoint: only the holder of the verifier's key can ask, and the server
 * is identified by its host key pinned in the verifier's known_hosts.
 *
 * On the server, in the attester user's ~/.ssh/authorized_keys (one line):
 *
 *   restrict,command="node /opt/attestium/examples/ssh-verification.js /srv/app /etc/attestium/signing-key.pem" ssh-ed25519 AAAA... verifier
 *
 * SSH passes the verifier's request ("attest <nonce>") in
 * SSH_ORIGINAL_COMMAND; the forced command answers it with an
 * Ed25519-signed statement of the tree digest of /srv/app.  The verifier
 * checks the signature with the public key it pinned, the nonce, the age
 * and the expected digest.
 *
 *   node examples/ssh-verification.js [projectRoot]   (both halves, no SSH)
 *
 * SSH decides who may ask and which machine answered.  It does not make
 * the answer true: root on the server can read the signing key and sign
 * any digest, or put another program in this one's place.  Only a TPM
 * quote with a pinned key and IMA, or a confidential VM, makes a forged
 * answer fail (docs/forged-answers.md).
 */

'use strict';

const fs = require('node:fs');
const {execFile} = require('node:child_process');
const Attestium = require('../lib/index.js');

/**
 * Attester: answer one request.
 *
 * @param {Object} input
 * @param {string} input.projectRoot
 * @param {string} input.privateKey - PEM
 * @param {string} input.request - SSH_ORIGINAL_COMMAND: "attest <nonce>"
 * @returns {Promise<string>} the signed statement, JSON
 */
async function answer({projectRoot, privateKey, request}) {
  const match = /^attest ([\da-f]+)$/.exec(String(request || ''));
  if (!match) {
    throw new Error('Expected "attest <nonce>"');
  }

  const attestium = new Attestium({projectRoot, signingKey: privateKey, logger: {log() {}}});
  return JSON.stringify(await attestium.generateVerificationResponse(match[1]));
}

/**
 * The ssh command line: the pinned host key only, the verifier's key only,
 * no agent, no forwarding, no prompt.
 *
 * @param {Object} input
 * @param {string} input.destination - user@host
 * @param {string} input.identity - the verifier's private key file
 * @param {string} input.knownHosts - the pinned host keys
 * @param {string} input.nonce
 * @returns {string[]}
 */
function sshArguments({destination, identity, knownHosts, nonce}) {
  const options = [
    'IdentitiesOnly=yes',
    'BatchMode=yes',
    'StrictHostKeyChecking=yes',
    `UserKnownHostsFile=${knownHosts}`,
    'GlobalKnownHostsFile=none',
    'ForwardAgent=no',
    'ClearAllForwardings=yes',
  ];
  return ['-F', 'none', '-i', identity, ...options.flatMap(option => ['-o', option]), '-T', '--', destination, `attest ${nonce}`];
}

/**
 * Verifier: check a statement.
 *
 * @param {Object} input
 * @param {string} input.statement - the attester's output
 * @param {string} input.nonce - the nonce this verifier sent
 * @param {string} input.publicKey - the attester's key, pinned
 * @param {string} [input.expectedDigest] - the tree digest of the reference
 * @returns {{valid: boolean, errors: string[]}}
 */
function check({statement, nonce, publicKey, expectedDigest}) {
  let envelope;
  try {
    envelope = JSON.parse(statement);
  } catch {
    return {valid: false, errors: ['The answer is not JSON']};
  }

  return Attestium.verifyVerificationResponse(envelope, {nonce, publicKey, digest: expectedDigest});
}

/**
 * Verifier: a fresh nonce, one SSH command, the checks.
 *
 * @param {Object} input - sshArguments() input without the nonce, check() input without statement and nonce
 * @param {string} [input.ssh='ssh']
 * @returns {Promise<{valid: boolean, errors: string[]}>}
 */
function verify({ssh = 'ssh', ...input}) {
  const nonce = Attestium.util.generateNonce();
  return new Promise(resolve => {
    execFile(ssh, sshArguments({...input, nonce}), {timeout: 600_000, maxBuffer: 16 * 1024 * 1024}, (error, stdout, stderr) => {
      resolve(error ? {valid: false, errors: [`ssh failed: ${String(stderr || error.message).trim()}`]} : check({...input, statement: stdout, nonce}));
    });
  });
}

/**
 * Both halves in one process, without SSH.
 */
async function main(projectRoot = process.cwd()) {
  const keys = Attestium.signing.generateKeyPair();
  const {digest} = await new Attestium({projectRoot, logger: {log() {}}}).generateVerificationReport();
  const nonce = Attestium.util.generateNonce();
  const statement = await answer({projectRoot, privateKey: keys.privateKey, request: `attest ${nonce}`});
  const result = check({
    statement, nonce, publicKey: keys.publicKey, expectedDigest: digest,
  });
  console.log(result.valid ? 'Server attestation verified.' : `Verification failed: ${result.errors.join('; ')}`);
  return result;
}

/**
 * Run as the forced command: answer SSH_ORIGINAL_COMMAND on stdout.
 */
async function forcedCommand(argv, environment) {
  const [projectRoot, keyFile] = argv;
  return answer({projectRoot, privateKey: fs.readFileSync(keyFile, 'utf8'), request: environment.SSH_ORIGINAL_COMMAND});
}

module.exports = {
  answer, sshArguments, check, verify, main, forcedCommand,
};

if (require.main === module) {
  // With a project root and a key file, this is the forced command: it
  // answers only a request in SSH_ORIGINAL_COMMAND.
  const run = process.argv.length < 4
    ? main(process.argv[2])
    : forcedCommand(process.argv.slice(2), process.env).then(statement => process.stdout.write(`${statement}\n`));
  run.catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
