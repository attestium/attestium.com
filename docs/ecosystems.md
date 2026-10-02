# Ecosystems and references

For each kind of code a server runs, this page says what the attester reads on the machine, which reference the verifier obtains, and what makes a check fail or leaves it unverifiable. It covers installed packages (npm, PyPI, RubyGems, Hex, Composer, Maven, NuGet), Go and Rust binaries, native binaries and release manifests, the official Node.js release, containers and OCI images, and Debian and Ubuntu packages through their signed archives.

## How a package check works

Every installed-package ecosystem is a plugin with the same shape (`ecosystems.INSTALLED`):

| Side | Function | Does |
| --- | --- | --- |
| Attester | `detect(root)` | Finds where packages are installed under a project root |
| Attester | `scan(dir)` | Hashes what is installed there; reports facts only |
| Verifier | `readLock(repoDir)` | Reads the lockfile at the deployed commit, from the verifier's own checkout; throws `NoLockfileError` when there is none |
| Verifier | `compare({scan, lock, store, ...})` | Fetches the references the lockfile pins, checks their hashes, and compares |

`compare()` returns the same shape for every ecosystem:

*   `summary`: counts by status: `verified`, `bundled`, `patched`, `built`, `failed`, `unverifiable`, `error`.
*   `findings`: one per package that did not verify, with `status`, `package`, `path`, `reason`, and up to 50 `modified`, `missing` and `added` files.
*   `issues`: other observations with a severity `fail`, `warn` or `info`.
*   `passed`: true only when nothing `failed`, nothing is `unverifiable`, nothing is `error`, every issue has severity `warn` or `info`, and the scan read every file (`errors` in a scan fail: what is not read is not compared).

The three non-passing statuses mean different things:

| Status | Meaning |
| --- | --- |
| `failed` | The installed package contradicts its reference, or nothing pins it |
| `unverifiable` | No reference can exist for it (for example a package the lockfile pins without a hash) |
| `error` | The reference exists but could not be fetched; retry |

A reference whose content does not match the hash the lockfile pins is `failed`, not `error`: that is evidence of tampering somewhere.

The same loop works for every ecosystem:

```js
const {ecosystems, ReleaseVerification} = require('attestium');

(async () => {
  const store = new ecosystems.ReferenceStore({cacheDir: './cache'});
  const release = new ReleaseVerification({cacheDir: './cache'});

  for (const install of ecosystems.detectInstalls('./app')) {
    const plugin = ecosystems[install.ecosystem];

    // Attester: hash what is installed.
    const scan = await plugin.scan(install.dir, {root: './app'});

    // Verifier: the lockfile at the deployed commit, from its own checkout.
    let lock = null;
    try {
      lock = plugin.readLock('./reference');
    } catch (error) {
      if (!(error instanceof ecosystems.NoLockfileError)) {
        throw error;
      }
    }

    const result = await plugin.compare({scan, lock, store, release});
    console.log(install.ecosystem, result.passed, result.summary);
    console.log(result.findings, result.issues);
  }
})();
```

`ReferenceStore` downloads references and caches their manifests in `cacheDir`. Its `urls` option replaces registry base URLs (`pypi`, `pypiFiles`, `rubygems`, `hex`, `nuget`, `maven`, `packagist`, `crates`, `goproxy`), for example for a mirror. Content-addressed references are checked by hash whatever the mirror.

## npm (npm and pnpm)

| | |
| --- | --- |
| Attester reads | `node_modules`, in npm's nested or flat layout and pnpm's `.pnpm` store layout. Each package is hashed as a whole (a digest over its files); per-file hashes are sent only for packages the lockfile patches, allows to build, or pins to a GitHub commit, so a failure of another package does not name the changed file. Symbolic links are not followed; each is checked instead. |
| Reference | `pnpm-lock.yaml`, `npm-shrinkwrap.json` or `package-lock.json` at the commit (the first found, or the one `readLock(repoDir, {lockfile})` names). Each package is compared with the registry tarball whose SRI integrity the lockfile pins. A dependency pinned to a GitHub commit (`codeload.github.com` tarballs, `git+https://github.com/...#<commit>`) is compared with the archive GitHub generates for that commit. |
| Accounted for | Bundled dependencies, matched with the bundling package's tarball. pnpm patches (`pnpm.patchedDependencies`): the reference is the tarball with the patch applied, exactly. Packages allowed to run install scripts (`pnpm.onlyBuiltDependencies`) may add files but not change what they shipped. npm and pnpm rewriting a `#!...\r\n` first line of `bin` files to `\n`. |
| Fails | Files differ from the tarball; a package not in the lockfile or any bundle; an invalid `package.json`; a patch that does not apply; a link that does not resolve to an installed package; a link to a package other than the one the lockfile resolves its name to (see below); a non-bytecode file in a `__pycache__` directory; with `package-lock.json` or `npm-shrinkwrap.json`, a package other than the one the lockfile pins at its path (Node.js resolves a name by path); in pnpm's store, a package other than the one its directory is named for; a bundled dependency outside the package that bundles it. |
| Unverifiable | A package resolved from another git host, a directory or an unpinned tarball. |
| Warns | Files in `node_modules` that belong to no package (nothing verified loads them); Python bytecode caches written when a build tool such as node-gyp ran Python. |
| Note | pnpm links each name to a package in its store. The attester reports where each link points (`packageLinks`), and the verifier requires the package `pnpm-lock.yaml` resolves the name to: in the project's `node_modules`, the project's dependency (importer `.`); in `.pnpm/<key>/node_modules`, the dependency of the package installed there (any of its peer variants); elsewhere (hoisted links), any version the lockfile has for the name. An `npm:` alias names another package. A name the lockfile never declares must link to a package of that name. With `package-lock.json`, a link must name its package or an alias the lockfile declares. |

Global packages next to the Node.js runtime (npm, corepack, pnpm, pm2) have no lockfile. `ReleaseVerification#verifyGlobalPackage()` compares npm and corepack with the copies inside the official Node.js archive when the installed version is the one the release shipped, and anything else with the registry tarball named by registry metadata.

To verify a project on the machine itself, without the evidence format:

```js
const {ReleaseVerification} = require('attestium');

(async () => {
  const release = new ReleaseVerification({projectRoot: './app', cacheDir: './cache'});
  const result = await release.verifyModules();
  console.log(result.passed, result.details);
})();
```

## PyPI

| | |
| --- | --- |
| Attester reads | Each virtual environment (`.venv`, `venv`, `env`, `.virtualenv`, `virtualenv` with a `pyvenv.cfg`): every distribution's `.dist-info`, and every file its `RECORD` lists, hashed where it is installed (including console scripts in `bin/`). Files in `site-packages` that no `RECORD` claims are listed: Python runs `.pth` files and `sitecustomize.py` at start-up. |
| Reference | The first of `uv.lock`, `pylock.toml`, `poetry.lock`, `Pipfile.lock`, `requirements.lock`, `requirements.txt` (with `--hash`). The wheel whose tags match the installed `WHEEL` file is downloaded (from the lockfile's URL when it is on the `pypi` or `pypiFiles` host, otherwise found through the registry by its hash), checked against the pinned hash, and compared following the wheel install rules (`.data` directories, rewritten script interpreters, generated entry-point scripts). |
| Fails | Files differ from the pinned wheel; a package the lockfile does not pin; no pinned wheel matches the installed tags; missing `METADATA` or `RECORD`; a file in `site-packages` or the environment's `bin/` that no package created (a `RECORD` line naming a directory does not account for what is in it); anything at the top of `site-packages` that is not a file, directory or link (a FIFO `.pth` file is read at start-up); a changed `_virtualenv` start-up hook, or one that cannot be checked. |
| Unverifiable | The lockfile pins no hashes for the package; the package was built on the server from a source distribution. |
| Info | `pip`, `setuptools` and `wheel` installed by the environment tool and not in the lockfile, when they match their registry release, or, given the host's Debian or Ubuntu archive (`compare({distro: {archive, arch}})`), the distribution's patched wheel of that version (`python3-pip-whl`, which `python3 -m venv` installs). |
| Warns | Bytecode (`.pyc`), which cannot be compared with anything. Install without compiling (uv's default, `pip install --no-compile`) and run with `PYTHONDONTWRITEBYTECODE=1`. |

## RubyGems (Bundler)

| | |
| --- | --- |
| Attester reads | `vendor/bundle/ruby/<version>` or `.bundle/ruby/<version>`: every installed gem's files, its specification (a Ruby file RubyGems loads at start-up), compiled extensions, executable wrappers in `bin/`, RubyGems plugins. |
| Reference | `Gemfile.lock` (or `gems.locked`). Its `CHECKSUMS` section (Bundler 2.6 and later) pins each `.gem` file's SHA-256. The `.gem` is downloaded, checked, and its `data.tar.gz` compared with the installed directory. |
| Fails | Files differ from the gem; a gem not in the lockfile; a specification that is not a generated literal specification, or that differs from the gem's metadata; compiled extensions for a gem without extensions; Ruby source (`.rb` outside `ext/`) added to a gem with extensions; a `bin/` file that is not RubyGems' wrapper for a verified gem; any installed RubyGems plugin (loaded into every Ruby process). |
| Unverifiable | A gem installed from a git source. |
| Warns | A gem the lockfile has no checksum for, compared with the registry's checksum instead (run `bundle lock --add-checksums`); native extensions compiled on the server, whose output cannot be compared. |

`rubygems.compareGemDirectory({name, version, files, store})` compares one gem directory no lockfile pins, such as the bundler gem `bundle exec` puts on `RUBYLIB`, with the `.gem` the registry serves under the registry's published checksum.

## Hex (Erlang, Elixir)

| | |
| --- | --- |
| Attester reads | `deps/<name>` next to `mix.lock`, with the metadata files Mix writes (`.hex`, `.fetch`). |
| Reference | `mix.lock` pins each package's outer checksum, the SHA-256 of the tarball `repo.hex.pm` serves. The tarball is downloaded, checked, and its contents compared. |
| Fails | Files differ from the tarball; a dependency not in `mix.lock`; an entry in `deps/` that is a link or special file instead of a directory. |
| Unverifiable | A dependency fetched from git or a path; one from another Hex repository; a lock entry with only the inner checksum (update it with a current Mix). |
| Note | The code that runs is compiled from these sources (`_build`, or a release). Verify it by reproducing the build. |

## Composer (PHP)

| | |
| --- | --- |
| Attester reads | Every package directory under `vendor/` (`vendor/<vendor>/<name>`), with git blob ids, and the files Composer generates (the autoloader in `vendor/composer`, `vendor/autoload.php`, proxies in `vendor/bin`). |
| Reference | `composer.lock` pins each package to a commit of its source repository. The commit's tree, read from a blobless clone (`gitTrees.GitTrees`), is the reference: a dist install holds the tree minus `export-ignore` files, a source install the whole tree. |
| Fails | A file differs from the file at the commit, is added, or is missing; a package not in `composer.lock`; a file in `vendor/` that belongs to no package. |
| Unverifiable | `composer.lock` pins no source commit for the package. |
| Warns | The generated autoloader, which runs first in every request, is not compared. Reproduce the build with `vendor/composer/**` and `vendor/autoload.php` as build outputs, and pass them as `covered`. |

Git runs with hooks off, no prompts, no system or global configuration, and only `https` URLs.

## Maven (Java)

| | |
| --- | --- |
| Attester reads | Directories of jars a JVM application loads: `target/lib`, `target/dependency`, `lib`, `libs`, Gradle's `build/install/<app>/lib`, and `WEB-INF/lib` of unpacked wars. Each jar is hashed, and its Maven coordinates read from `META-INF/maven/.../pom.properties`. |
| Reference | Jars are copied unchanged from the repository, so each jar's SHA-256 must be one the build pinned: `gradle/verification-metadata.xml` (Gradle dependency verification) or `lockfile.json` (maven-lockfile). |
| Fails | A jar that differs from the one the build pinned; a jar the build does not pin that names no coordinates; a jar that differs from Maven Central's for its coordinates; links or other entries named like jars. |
| Error | Maven Central could not be reached for an unpinned jar. |
| Warns | Jars the build does not pin, compared with Maven Central instead (this trusts the registry, not the repository); other files next to the jars. |
| Note | The application's own jar is build output: verify it by reproducing the build, and pass it as `covered`. |

## NuGet (.NET)

| | |
| --- | --- |
| Attester reads | A published .NET application: the directory holding `<app>.deps.json` and `<app>.runtimeconfig.json` (a `publish` or `out` directory), hashed file by file. |
| Reference | `packages.lock.json` (`RestorePackagesWithLockFile`) pins each package's content hash, the SHA-512 of the `.nupkg`. Every locked package is downloaded and checked, and each assembly or native library in the published directory must be a file one of them ships, unchanged. |
| Fails | A file that differs from the file of the same name in the locked packages (assemblies and native libraries are recognized whatever the case of their extension); a file no locked package ships and no build reproduces; no `packages.lock.json`; a locked package that could not be downloaded or checked. |
| Warns | Build output that decides what the runtime loads (`deps.json`, `runtimeconfig.json`), and the application's own assembly and apphost, are verified only by reproducing the build. |

## Go binaries

A Go binary (Go 1.18 and later) records the module it was built from, every dependency with its `go.sum` hash, and build settings. `elf.goBuildInfo()` reads that record from the file; `ecosystems.go.compareBuildInfo()` checks it against `go.sum` at the deployed commit.

```js
const fs = require('node:fs');
const {execFileSync} = require('node:child_process');
const {elf, ecosystems} = require('attestium');

// Attester: the build information inside the running binary.
const info = elf.goBuildInfo(fs.readFileSync('./hello'));

// Verifier: go.mod, go.sum and the commit, from its own checkout.
const lock = ecosystems.go.readLock('./goref');
const commit = execFileSync('git', ['-C', './goref', 'rev-parse', 'HEAD'], {encoding: 'utf8'}).trim();

const result = ecosystems.go.compareBuildInfo({info, lock, commit, label: 'hello'});
console.log(info.goVersion, info.main, info.settings['vcs.revision']);
console.log(result.passed, result.summary, result.issues);
```

| Result | When |
| --- | --- |
| Fails | A dependency (after replacements) not in `go.sum`, or with another hash; built from another module; built from another commit (`vcs.revision`); built from a modified tree (`vcs.modified=true`) |
| Unverifiable | A dependency replaced by a local directory |
| Info | No commit recorded (`-buildvcs=false`); built without `-trimpath`, so it will not reproduce byte for byte |
| Warns | Go 1.17 or earlier, which stores no inline build information |

The record is written by the build, so a binary could claim anything. The binary's own hash proves what it is: a reproduced build, an attested artifact, or a signed checksum. This check shows that the binary was built with the pinned dependencies, and flags a build from another commit or a modified tree.

## Rust binaries

A binary built with [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) records every crate compiled into it in a `.dep-v0` section. `elf.cargoAuditable()` reads it; `ecosystems.cargo.compareAuditable()` checks it against `Cargo.lock` at the commit.

```js
const fs = require('node:fs');
const {elf, ecosystems} = require('attestium');

// Attester: the crate list inside the binary (null when it has none).
const packages = elf.cargoAuditable(fs.readFileSync('./rustapp/target/debug/rustapp'));

// Verifier: Cargo.lock at the commit.
const lock = ecosystems.cargo.readLock('./rustapp');
const result = ecosystems.cargo.compareAuditable({packages, lock});
console.log(result.passed, result.summary, result.findings);
```

A crate fails when it is not in `Cargo.lock`, or comes from another source than the lockfile says. A registry crate whose lockfile entry has no checksum, or a git crate pinned to no commit, is unverifiable. As with Go, the binary's own hash is what proves it.

## Native binaries

A native binary (a database server, a proxy, a tool from a release page) is explained by one of:

*   its owning distribution package (see [Debian and Ubuntu packages](#debian-and-ubuntu-packages));
*   an entry in the project's published checksum list, preferably signed (`checksums.fetchChecksums()`, see [Signatures](signatures.md#signed-checksum-lists));
*   a GitHub artifact attestation for its SHA-256 (`attestations.verifyGithubAttestation()`);
*   a pinned SHA-256 in the verifier's configuration;
*   a reproduced build.

For your own releases deployed without git, publish a release manifest from CI and attest it. See [Release manifests](signatures.md#release-manifests) and [SPEC.md](../SPEC.md#release-manifests).

## Language runtimes

The attester detects each process's runtime from its executable name and mapped libraries (`libjvm.so` is the JVM, whatever the launcher is called): Node.js, Python, JVM, Ruby, .NET, BEAM, PHP, Perl, Deno, Bun, or native. For each, `ProcessIntegrity` reports that runtime's code injection vectors: environment variables that load code (`NODE_OPTIONS`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`, `RUBYOPT`, `DOTNET_STARTUP_HOOKS`, `ERL_FLAGS`, `PHP_INI_SCAN_DIR`, `PERL5OPT`, and the dynamic linker's `LD_PRELOAD` and `LD_AUDIT`), command-line options that do the same, debugger and management ports, and attach mechanisms.

The runtime binary itself is explained like any executable. Node.js has an official release reference:

```js
const {ReleaseVerification} = require('attestium');

(async () => {
  const release = new ReleaseVerification({cacheDir: './cache'});
  // In a verifier, pass the executable's sha256 and the version from the evidence.
  const result = await release.verifyNodeRelease();
  console.log(result.passed, result.details);
})();
```

`verifyNodeRelease()` downloads `SHASUMS256.txt` for the version, the official `.tar.gz` for the platform, checks the archive against the list, and compares `bin/node` inside it with the binary (on Windows, `node.exe` is listed directly). Set `nodeKeyring` to a keyring of the [Node.js release keys](https://github.com/nodejs/release-keys) to require a valid signature on `SHASUMS256.txt` (checked with `gpgv`). A binary repackaged by a distribution differs from the official one; explain it by its distribution package instead.

Other runtimes are explained by their distribution package, their project's signed checksums, or a pinned hash.

## Containers and OCI images

For a process in a container, the attester reports:

*   the container, from the process's cgroup (`containers.containerOf()`: Docker, containerd, CRI-O, Podman, Kubernetes);
*   the image the runtime says it started from (`containers.inspectDocker()`, or `containers.inspectCri()` through `crictl`);
*   mounts that bring in files from outside the image;
*   the overlay's writable layer: files written and files deleted (`containers.walkUpper()`);
*   every file of the root filesystem, hashed through `/proc/<pid>/root`, other mounts left out (`containers.walkRootfs()`).

The verifier does not trust the runtime's claims. It fetches the image by digest from the registry, checks every manifest and layer against the digest that names it, applies the layers in order (whiteouts included), and compares the files:

```js
const {containers, oci} = require('attestium');

(async () => {
  const pid = process.argv[2]; // a process inside the container

  // Attester: the container, the image the runtime names, the files it runs from.
  const {id} = containers.containerOf(pid);
  const inspected = await containers.inspectDocker(id);
  const rootfs = await containers.walkRootfs(pid);
  const repoDigest = inspected.image.repoDigests[0]; // registry/repository@sha256:...

  // Verifier: the image, fetched by digest; the platform manifest; every layer applied.
  const registry = new oci.Registry();
  const reference = oci.parseReference(repoDigest);
  const {manifest} = await registry.platformManifest(reference, inspected.platform);
  const expected = await oci.imageFiles(registry, reference, manifest);

  // Files the runtime writes into every container are not image files.
  const runtimeFiles = new Set(['.dockerenv', 'etc/hostname', 'etc/hosts', 'etc/resolv.conf']);
  const result = oci.compareRootfs(rootfs.files, expected, {ignore: file => runtimeFiles.has(file)});
  console.log(result); // {modified, missing, added, modeChanged}
})();
```

Pass `credentials` to `oci.Registry` for private registries (`{token}` or `{username, password}` per registry name), and `endpoints` to map a registry name to a mirror. A registry with no configured endpoint is a name taken from evidence: it, and the token service it names, is never reached at a private address (loopback, RFC 1918, link-local, cloud metadata) unless `httpOptions.denyPrivateAddresses` is `false`. Code in a volume or bind mount is not part of the image; explain it as a directory service or report it.

## Debian and Ubuntu packages

The runtime and the shared libraries a process maps usually come from the distribution. The reference is the distribution's signed archive:

*   The attester finds the owning package of each file in the dpkg database (`distro.DpkgDatabase#ownerOf()`), with its version, architecture, the path it is listed as (merged-`/usr` aliases included), and when it was installed.
*   The verifier checks the archive's `InRelease` signature with the distribution's keyring (`gpgv`, reading its status lines from a descriptor of their own, so a signature by a revoked or expired key, which `gpgv` accepts with exit status 0, is refused), follows the SHA-256 chain to the `Packages` index and to the `.deb`, extracts it with `dpkg-deb`, and compares the file.

```js
const fs = require('node:fs');
const {distro, ecosystems, util} = require('attestium');

(async () => {
  const file = '/usr/lib/x86_64-linux-gnu/libc.so.6';

  // Attester: the owning package, from the dpkg database, and the file's hash.
  const owner = new distro.DpkgDatabase().ownerOf(file);
  const sha256 = util.sha256(fs.readFileSync(file));

  // Verifier: the same file inside that package, from the signed archive.
  const release = distro.osRelease();
  const archives = distro.defaultArchives(release, owner.arch);
  const store = new ecosystems.ReferenceStore({cacheDir: './cache'});
  const reference = new distro.ArchiveReference({archives, store});
  const files = await reference.files(owner.name, owner.version, owner.arch, owner.installedAt);

  const expected = files[owner.listedAs] ?? files[file];
  console.log(owner, expected === sha256 ? 'matches the archive' : 'differs from the archive');
})();
```

The dpkg database is the server's claim. The package it names must hold the file with the same contents, so a false claim fails. A file owned by no package is reported as unexplained.

`defaultArchives()` returns the release's main, updates and security suites, with the keyrings in `/usr/share/keyrings` (install `debian-archive-keyring` or `ubuntu-keyring` on the verifier). Archive indexes may be fetched over plain HTTP: their contents are authenticated by the signature and the hash chain, not by the transport.

A version that has since been superseded is no longer in the archive. `ArchiveReference#files()` then looks it up in the archive's snapshot service (`snapshot.debian.org`, `snapshot.ubuntu.com`) at the hour the package was installed, and a day later. When neither has it, it throws with code `ENOTINARCHIVE`: upgrade the package, or configure an archive snapshot that has it.
