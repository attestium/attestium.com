/**
 * Challenge-response over HTTP with node:http (no framework).
 *
 * The server answers a verifier's nonce with an Ed25519-signed statement
 * of its current tree digest.  The verifier checks the signature against
 * the public key it pinned, the nonce, the age, and the expected digest.
 *
 *   node examples/http-verification.js
 *
 * Note: a software signing key proves which key signed, not that the
 * machine is uncompromised; anyone with root on the server can read the
 * key.  Bind responses to a TPM quote (generateHardwareAttestation) when
 * that matters.
 */

'use strict';

const http = require('node:http');
const Attestium = require('../lib/index.js');

/**
 * Start a server that answers GET /attestation?nonce=<hex>.
 */
async function startServer({projectRoot, privateKey}) {
  const attestium = new Attestium({projectRoot, signingKey: privateKey, logger: {log() {}}});
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://localhost');
    if (request.method !== 'GET' || url.pathname !== '/attestation') {
      response.writeHead(404).end();
      return;
    }

    try {
      const body = await attestium.generateVerificationResponse(url.searchParams.get('nonce') || '');
      response.writeHead(200, {'content-type': 'application/json'}).end(JSON.stringify(body));
    } catch (error) {
      response.writeHead(400, {'content-type': 'application/json'}).end(JSON.stringify({error: error.message}));
    }
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  return server;
}

/**
 * Verifier side: fresh nonce, fetch, verify.
 */
async function verify({url, publicKey, expectedDigest}) {
  const nonce = Attestium.util.generateNonce();
  const response = await fetch(`${url}/attestation?nonce=${nonce}`);
  const envelope = await response.json();
  return Attestium.verifyVerificationResponse(envelope, {nonce, publicKey, digest: expectedDigest});
}

async function main(projectRoot = process.cwd()) {
  const keys = Attestium.signing.generateKeyPair();
  const server = await startServer({projectRoot, privateKey: keys.privateKey});
  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    const {digest} = await new Attestium({projectRoot, logger: {log() {}}}).generateVerificationReport();
    const result = await verify({url, publicKey: keys.publicKey, expectedDigest: digest});
    console.log(result.valid ? 'Server attestation verified.' : `Verification failed: ${result.errors.join('; ')}`);
    return result;
  } finally {
    server.close();
  }
}

module.exports = {startServer, verify, main};

if (require.main === module) {
  main(process.argv[2]).catch(error => {
    console.error(error);
    process.exitCode = 1;
  });
}
