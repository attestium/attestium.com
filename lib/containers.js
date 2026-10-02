/**
 * Attestium - containers (attester side)
 *
 * A process in a container runs from the container's root filesystem: the
 * image's layers, read-only, and a writable layer on top (overlayfs).  For
 * such a process this module finds:
 *
 *   - the container, from the process's cgroup (Docker, containerd,
 *     CRI-O, Podman, Kubernetes)
 *   - the image the runtime says it started from (Docker Engine API, or
 *     crictl for CRI runtimes)
 *   - its mounts: volumes and bind mounts are not part of the image, so code
 *     in them is reported separately
 *   - what changed in the writable layer (overlayfs upperdir), including
 *     deletions (whiteouts)
 *   - every file of the root filesystem, hashed through /proc/<pid>/root, so
 *     a verifier can compare them with the image's layers
 *
 * The runtime's claims about the image are not trusted by the verifier; the
 * files are compared with the image it names.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {execFile} = require('node:child_process');
const {
  walkTree, hashFile, openDirectory, openSubdirectory, closeDirectory,
} = require('./file-tree');
const {normalizePid, setOwn} = require('./util');

const ID = String.raw`[\da-f]{64}`;
const CGROUP_PATTERNS = [
  [new RegExp(`/docker/(${ID})(?:/|$)`), 'docker'],
  [new RegExp(`docker-(${ID})\\.scope`), 'docker'],
  [new RegExp(`cri-containerd-(${ID})\\.scope`), 'containerd'],
  [new RegExp(`crio-(${ID})\\.scope`), 'cri-o'],
  [new RegExp(`libpod-(${ID})\\.scope`), 'podman'],
  [new RegExp(`/libpod_parent/libpod-(${ID})`), 'podman'],
  [new RegExp(`/kubepods[^\\s]*/(${ID})(?:/|$)`), 'containerd'],
  [new RegExp(`/containerd/[\\w-]+/(${ID})(?:/|$)`), 'containerd'],
];

/**
 * The container a process belongs to, from /proc/<pid>/cgroup.
 * @param {string|number} pid
 * @param {string} [procRoot='/proc']
 * @returns {{id: string, runtime: string}|null}
 */
function containerOf(pid, procRoot = '/proc') {
  let text;
  try {
    text = fs.readFileSync(path.join(procRoot, normalizePid(pid), 'cgroup'), 'utf8');
  } catch {
    return null;
  }

  for (const line of text.split('\n')) {
    const cgroup = line.split(':').slice(2).join(':');
    for (const [pattern, runtime] of CGROUP_PATTERNS) {
      const match = cgroup.match(pattern);
      if (match) {
        return {id: match[1], runtime};
      }
    }
  }

  return null;
}

/**
 * Unescape a mountinfo field (\040 for a space, and so on).
 */
function unescapeMount(value) {
  return value.replaceAll(/\\([0-7]{3})/g, (_, octal) => String.fromCodePoint(Number.parseInt(octal, 8)));
}

/**
 * Parse /proc/<pid>/mountinfo.
 * @param {string} text
 * @returns {Array<{id: number, parent: number, root: string, mountPoint: string, options: string, fsType: string, source: string, superOptions: string}>}
 */
function parseMountinfo(text) {
  const mounts = [];
  for (const line of text.split('\n')) {
    const separator = line.indexOf(' - ');
    if (separator === -1) {
      continue;
    }

    const fields = line.slice(0, separator).split(' ');
    const after = line.slice(separator + 3).split(' ');
    mounts.push({
      id: Number(fields[0]),
      parent: Number(fields[1]),
      device: fields[2],
      root: unescapeMount(fields[3]),
      mountPoint: unescapeMount(fields[4]),
      options: fields[5],
      fsType: after[0],
      source: unescapeMount(after[1] || ''),
      superOptions: after.slice(2).join(' '),
    });
  }

  return mounts;
}

/**
 * The overlay directories of a process's root filesystem.
 * @param {Object[]} mounts - from parseMountinfo
 * @returns {{lower: string[], upper: string|null, work: string|null}|null}
 */
function rootOverlay(mounts) {
  const root = mounts.findLast(mount => mount.mountPoint === '/');
  if (!root || root.fsType !== 'overlay') {
    return null;
  }

  const options = {};
  // Option values may contain commas escaped as "\,".
  for (const part of root.superOptions.split(/(?<!\\),/)) {
    const equals = part.indexOf('=');
    if (equals > 0) {
      options[part.slice(0, equals)] = part.slice(equals + 1).replaceAll(String.raw`\,`, ',');
    }
  }

  return {
    lower: options.lowerdir ? options.lowerdir.split(/(?<!\\):/).map(item => item.replaceAll(String.raw`\:`, ':')) : [],
    upper: options.upperdir || null,
    work: options.workdir || null,
  };
}

/**
 * HTTP GET over a Unix socket (the Docker Engine API).
 * @returns {Promise<Object>} parsed JSON
 */
function unixGetJson(socketPath, urlPath, timeout = 10_000) {
  return new Promise((resolve, reject) => {
    const request = http.get({
      socketPath, path: urlPath, timeout, headers: {host: 'docker'},
    }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 64 * 1024 * 1024) {
          request.destroy(new Error('response too large'));
          return;
        }

        chunks.push(chunk);
      });
      response.on('end', () => {
        if (response.statusCode !== 200) {
          reject(new Error(`Docker API ${urlPath} answered ${response.statusCode}`));
          return;
        }

        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on('timeout', () => request.destroy(new Error(`Docker API ${urlPath} timed out`)));
    request.on('error', reject);
  });
}

/**
 * What Docker says about a container and its image.
 * @param {string} id
 * @param {string} [socketPath='/var/run/docker.sock']
 * @returns {Promise<Object>}
 */
async function inspectDocker(id, socketPath = '/var/run/docker.sock') {
  const container = await unixGetJson(socketPath, `/containers/${encodeURIComponent(id)}/json`);
  const image = await unixGetJson(socketPath, `/images/${encodeURIComponent(container.Image)}/json`).catch(() => ({}));
  const descriptor = container.ImageManifestDescriptor || null;
  return {
    name: String(container.Name || '').replace(/^\//, ''),
    image: {
      reference: container.Config && container.Config.Image ? String(container.Config.Image) : null,
      id: container.Image || null,
      manifestDigest: descriptor && descriptor.digest ? descriptor.digest : null,
      repoDigests: Array.isArray(image.RepoDigests) ? image.RepoDigests.map(String) : [],
    },
    platform: {os: image.Os || container.Platform || null, architecture: image.Architecture || (descriptor && descriptor.platform && descriptor.platform.architecture) || null},
    labels: (container.Config && container.Config.Labels) || {},
  };
}

/**
 * What a CRI runtime (containerd, CRI-O) says, through crictl.
 * @param {string} id
 * @param {Object} [options]
 * @param {string} [options.crictl='crictl']
 * @returns {Promise<Object>}
 */
function inspectCri(id, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(options.crictl || 'crictl', ['inspect', '-o', 'json', id], {timeout: 15_000, maxBuffer: 64 * 1024 * 1024}, (error, stdout) => {
      if (error) {
        reject(new Error(`crictl inspect failed: ${error.message.split('\n')[0]}`));
        return;
      }

      try {
        const json = JSON.parse(stdout);
        const status = json.status || {};
        const labels = status.labels || {};
        resolve({
          name: (status.metadata && status.metadata.name) || null,
          image: {
            reference: (status.image && status.image.image) || null,
            id: null,
            manifestDigest: null,
            repoDigests: status.imageRef ? [String(status.imageRef)] : [],
          },
          platform: {os: 'linux', architecture: null},
          labels,
          pod: labels['io.kubernetes.pod.name'] ? {name: labels['io.kubernetes.pod.name'], namespace: labels['io.kubernetes.pod.namespace'] || null} : null,
        });
      } catch (parseError) {
        reject(parseError);
      }
    });
  });
}

/**
 * Walk an overlayfs upper directory: files written in the container, and
 * whiteouts (character devices 0:0) for files deleted from the image.
 *
 * @param {string} upper
 * @returns {Promise<{files: Object<string, [string, string]>, deleted: string[], errors: Object[]}>}
 */
async function walkUpper(upper) {
  const files = {};
  const deleted = [];
  const errors = [];
  // The container writes this directory: each subdirectory is entered
  // through its parent's open descriptor, so one it replaces with a link
  // (to a directory of the host) during the walk is not followed.
  const visit = async (directory, relative) => {
    let entries;
    try {
      entries = await fs.promises.readdir(directory.path, {withFileTypes: true});
    } catch (error) {
      errors.push({path: relative || '.', error: error.code});
      return;
    }

    for (const entry of entries) {
      const child = relative ? `${relative}/${entry.name}` : entry.name;
      const full = `${directory.path}/${entry.name}`;
      try {
        if (entry.isDirectory()) {
          const subdirectory = await openSubdirectory(directory, entry.name);
          try {
            await visit(subdirectory, child);
          } finally {
            await closeDirectory(subdirectory);
          }
        } else if (entry.isCharacterDevice()) {
          const stats = await fs.promises.lstat(full);
          if (stats.rdev === 0) {
            deleted.push(child);
          } else {
            setOwn(files, child, ['device', 'device']);
          }
        } else if (entry.isSymbolicLink()) {
          setOwn(files, child, [`symlink:${await fs.promises.readlink(full)}`, '120000']);
        } else if (entry.isFile()) {
          const stats = await fs.promises.lstat(full);
          setOwn(files, child, [(await hashFile(full)).sha256, stats.mode & 0o111 ? '100755' : '100644']);
        } else if (!entry.isSocket()) {
          // A FIFO or block device: never opened, but reported.  A socket
          // has no content (a server's, such as PostgreSQL's in /run).
          errors.push({path: child, error: 'ENOTFILE'});
        }
      } catch (error) {
        errors.push({path: child, error: error.code || error.message});
      }
    }
  };

  let top;
  try {
    top = await openDirectory(upper);
  } catch (error) {
    return {files, deleted, errors: [{path: '.', error: error.code}]};
  }

  try {
    await visit(top, '');
  } finally {
    await closeDirectory(top);
  }

  return {files, deleted: deleted.sort(), errors};
}

/**
 * Every file of a process's root filesystem, through /proc/<pid>/root,
 * leaving out other mounts (volumes, /proc, /dev, ...).
 *
 * @param {string|number} pid
 * @param {Object} [options]
 * @param {string} [options.procRoot='/proc']
 * @param {number} [options.maxFiles=500000]
 * @returns {Promise<{files: Object<string, [string, string]>, fileCount: number, errors: Object[], truncated?: boolean, mounts: Object[]}>}
 */
async function walkRootfs(pid, options = {}) {
  const procRoot = options.procRoot || '/proc';
  pid = normalizePid(pid);
  const mounts = parseMountinfo(fs.readFileSync(path.join(procRoot, pid, 'mountinfo'), 'utf8'));
  const others = new Set(mounts.filter(mount => mount.mountPoint !== '/').map(mount => mount.mountPoint.replace(/^\//, '')));
  const root = path.join(procRoot, pid, 'root');
  const walk = await walkTree(root, {exclude: relative => others.has(relative)});
  const maxFiles = options.maxFiles || 500_000;
  const files = {};
  for (const entry of walk.entries.slice(0, maxFiles)) {
    setOwn(files, entry.path, [entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256, entry.mode]);
  }

  const result = {
    files, fileCount: walk.entries.length, errors: walk.errors, mounts,
  };
  if (walk.entries.length > maxFiles) {
    result.truncated = true;
  }

  return result;
}

/**
 * Mounts that bring files into a container from elsewhere (not the image).
 * @param {Object[]} mounts - from parseMountinfo
 * @returns {Array<{destination: string, source: string, root: string, fsType: string, readOnly: boolean}>}
 */
function externalMounts(mounts) {
  const virtual = new Set(['proc', 'sysfs', 'devpts', 'mqueue', 'cgroup', 'cgroup2', 'tmpfs', 'overlay', 'devtmpfs', 'securityfs', 'debugfs', 'tracefs', 'bpf', 'pstore', 'hugetlbfs', 'fusectl', 'configfs', 'binfmt_misc', 'nsfs']);
  return mounts
    .filter(mount => mount.mountPoint !== '/' && !virtual.has(mount.fsType))
    .map(mount => ({
      destination: mount.mountPoint, source: mount.source, root: mount.root, fsType: mount.fsType, readOnly: /(?:^|,)ro(?:,|$)/.test(mount.options),
    }));
}

module.exports = {
  containerOf,
  parseMountinfo,
  rootOverlay,
  inspectDocker,
  inspectCri,
  walkUpper,
  walkRootfs,
  externalMounts,
  unixGetJson,
};
