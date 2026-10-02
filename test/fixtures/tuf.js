'use strict';

/* eslint-disable camelcase -- TUF metadata field names */

/**
 * A TUF repository for tests: root, timestamp, snapshot, targets and
 * delegated targets metadata signed with keys made here, served from a
 * route map (see startServer in ../helpers).
 *
 * Key forms: "ed25519" (hex public key), "ecdsa" (PEM, as current
 * Sigstore roots have) and "ecdsa-hex" (a hex-encoded uncompressed P-256
 * point, as the first Sigstore roots have).
 */

const crypto = require('node:crypto');
const {canonicalJson} = require('../../lib/tuf');

const FAR = '2100-01-01T00:00:00Z';

function makeKey(form = 'ed25519') {
  const pair = form === 'ed25519' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  const der = pair.publicKey.export({type: 'spki', format: 'der'});
  let key;
  if (form === 'ed25519') {
    key = {keytype: 'ed25519', scheme: 'ed25519', keyval: {public: der.subarray(-32).toString('hex')}};
  } else if (form === 'ecdsa') {
    key = {keytype: 'ecdsa', scheme: 'ecdsa-sha2-nistp256', keyval: {public: pair.publicKey.export({type: 'spki', format: 'pem'})}};
  } else {
    key = {
      keytype: 'ecdsa-sha2-nistp256', scheme: 'ecdsa-sha2-nistp256', keyid_hash_algorithms: ['sha256', 'sha512'], keyval: {public: der.subarray(-65).toString('hex')},
    };
  }

  return {
    form, key, keyid: crypto.createHash('sha256').update(canonicalJson(key)).digest('hex'), privateKey: pair.privateKey,
  };
}

/**
 * Sign metadata with keys (each from makeKey).
 */
function signMetadata(signed, keys) {
  const data = Buffer.from(canonicalJson(signed));
  return {
    signed,
    signatures: keys.map(key => ({keyid: key.keyid, sig: crypto.sign(key.form === 'ed25519' ? null : 'sha256', data, key.privateKey).toString('hex')})),
  };
}

const keyMap = keys => Object.fromEntries(keys.map(key => [key.keyid, key.key]));
const roleOf = (keys, threshold = 1) => ({keyids: keys.map(key => key.keyid), threshold});
const body = metadata => Buffer.from(JSON.stringify(metadata));
const fileMeta = (content, extra = {}) => ({
  length: content.length,
  hashes: {sha256: crypto.createHash('sha256').update(content).digest('hex'), sha512: crypto.createHash('sha512').update(content).digest('hex')},
  ...extra,
});

class TufRepository {
  /**
   * @param {Object} [options]
   * @param {string[]} [options.rootKeyForms] - one root key per form
   * @param {number} [options.threshold=2]
   * @param {string} [options.expires]
   */
  constructor({rootKeyForms = ['ed25519', 'ecdsa', 'ecdsa-hex'], threshold = 2, expires = FAR} = {}) {
    this.routes = {};
    this.expires = expires;
    this.rootKeys = rootKeyForms.map(form => makeKey(form));
    this.threshold = threshold;
    this.timestampKey = makeKey('ed25519');
    this.snapshotKey = makeKey('ecdsa');
    this.targetsKey = makeKey('ecdsa-hex');
    this.delegateKey = makeKey('ecdsa');
    this.root = null;
    this.initialRoot = this.addRoot();
  }

  /**
   * The root metadata naming the current role keys.
   */
  rootSigned({version, keys = this.rootKeys, threshold = this.threshold, expires = this.expires}) {
    const online = [this.timestampKey, this.snapshotKey, this.targetsKey];
    return {
      _type: 'root',
      spec_version: '1.0.31',
      version,
      expires,
      consistent_snapshot: true,
      keys: keyMap([...keys, ...online]),
      roles: {
        root: roleOf(keys, threshold),
        timestamp: roleOf([this.timestampKey]),
        snapshot: roleOf([this.snapshotKey]),
        targets: roleOf([this.targetsKey]),
      },
    };
  }

  /**
   * Publish the next root version, signed by the previous and new root
   * keys (or `signers`).  Returns the metadata.
   */
  addRoot({keys = this.rootKeys, threshold = this.threshold, expires = this.expires, signers, version, mutate} = {}) {
    const previous = this.root ? this.rootKeys : [];
    const next = version ?? (this.root ? this.root.signed.version + 1 : 1);
    const signed = this.rootSigned({
      version: next, keys, threshold, expires,
    });
    if (mutate) {
      mutate(signed);
    }

    const metadata = signMetadata(signed, signers || [...new Set([...previous, ...keys])]);
    this.routes[`/${this.root ? this.root.signed.version + 1 : 1}.root.json`] = {body: body(metadata)};
    this.root = metadata;
    this.rootKeys = keys;
    this.threshold = threshold;
    return metadata;
  }

  /**
   * Publish targets (name -> content), delegated roles
   * ({name: {paths, targets}}), and the snapshot and timestamp over them.
   *
   * @param {Object} [options]
   * @param {Object<string, Buffer>} [options.targets]
   * @param {Object<string, {paths: string[], targets: Object<string, Buffer>}>} [options.delegated]
   * @param {number} [options.version=1] - version of every file
   * @param {Object<string, Function>} [options.mutate] - change the signed part of timestamp/snapshot/targets/<role> before signing
   * @param {Object<string, Object[]>} [options.signers] - keys that sign each file instead of its role's
   * @param {Object<string, Object>} [options.expires] - expiry per file
   * @param {boolean} [options.snapshotHashes=false] - list lengths and hashes in the snapshot, as the timestamp does
   */
  publish({targets = {}, delegated = {}, version = 1, mutate = {}, signers = {}, expires = {}, snapshotHashes = false} = {}) {
    const finish = (name, signed, keys) => {
      signed.expires = expires[name] || signed.expires;
      if (mutate[name]) {
        mutate[name](signed);
      }

      return body(signMetadata(signed, signers[name] || keys));
    };

    const targetInfo = files => {
      const info = {};
      for (const [name, content] of Object.entries(files)) {
        info[name] = fileMeta(content);
        const slash = name.lastIndexOf('/');
        this.routes[`/targets/${name.slice(0, slash + 1)}${info[name].hashes.sha256}.${name.slice(slash + 1)}`] = {body: content};
      }

      return info;
    };

    const snapshotMeta = {};
    const roles = [];
    for (const [role, {paths, targets: files}] of Object.entries(delegated)) {
      const content = finish(role, {
        _type: 'targets', spec_version: '1.0.31', version, expires: this.expires, targets: targetInfo(files),
      }, [this.delegateKey]);
      this.routes[`/${version}.${encodeURIComponent(role)}.json`] = {body: content};
      snapshotMeta[`${role}.json`] = snapshotHashes ? fileMeta(content, {version}) : {version};
      roles.push({
        name: role, keyids: [this.delegateKey.keyid], threshold: 1, paths, terminating: true,
      });
    }

    const targetsSigned = {
      _type: 'targets', spec_version: '1.0.31', version, expires: this.expires, targets: targetInfo(targets),
    };
    if (roles.length > 0) {
      targetsSigned.delegations = {keys: keyMap([this.delegateKey]), roles};
    }

    const targetsContent = finish('targets', targetsSigned, [this.targetsKey]);
    this.routes[`/${version}.targets.json`] = {body: targetsContent};
    snapshotMeta['targets.json'] = snapshotHashes ? fileMeta(targetsContent, {version}) : {version};

    const snapshotContent = finish('snapshot', {
      _type: 'snapshot', spec_version: '1.0.31', version, expires: this.expires, meta: snapshotMeta,
    }, [this.snapshotKey]);
    this.routes[`/${version}.snapshot.json`] = {body: snapshotContent};

    this.routes['/timestamp.json'] = {
      body: finish('timestamp', {
        _type: 'timestamp', spec_version: '1.0.31', version, expires: this.expires, meta: {'snapshot.json': fileMeta(snapshotContent, {version})},
      }, [this.timestampKey]),
    };
  }
}

module.exports = {
  TufRepository, makeKey, signMetadata, keyMap, roleOf, fileMeta, FAR,
};

/* eslint-enable camelcase */
