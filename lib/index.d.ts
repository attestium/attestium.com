/* eslint-disable @typescript-eslint/no-restricted-types, @typescript-eslint/naming-convention, @typescript-eslint/member-ordering, unicorn/prefer-event-target -- the declarations mirror the CommonJS runtime, which returns null and Buffer, exposes constant statics, and extends EventEmitter */
/**
 * Attestium type definitions.
 */

import {EventEmitter} from 'node:events';
import type {KeyObject, X509Certificate} from 'node:crypto';
import type {ChildProcess} from 'node:child_process';

declare class Attestium extends EventEmitter {
  static readonly VERSION: string;
  static readonly DEFAULT_INCLUDE: string[];
  static readonly DEFAULT_EXCLUDE: string[];
  static digestOf(value: unknown): string;
  static verifyVerificationResponse(
    response: Attestium.SignedEnvelope<Attestium.VerificationResponsePayload>,
    expected: {nonce: string; publicKey: Attestium.KeyLike; digest?: string; maxAgeMs?: number},
  ): {valid: boolean; errors: string[]};

  static verifyHardwareAttestation(
    attestation: Attestium.HardwareAttestation,
    expected: {nonce: string; publicKey: string; expectedPcrs?: Record<string, Record<string, string>>},
  ): {valid: boolean; errors: string[]};

  readonly version: string;
  readonly projectRoot: string;
  gitCommit: string | null;
  deployTime: string | null;
  includePatterns: string[];
  excludePatterns: string[];
  tpm: Attestium.Tpm;

  constructor(options?: Attestium.AttestiumOptions);
  log(message: string, level?: string): void;
  matchesPattern(relativePath: string, pattern: string): boolean;
  shouldInclude(relativePath: string): boolean;
  shouldExclude(relativePath: string): boolean;
  categorizeFile(relativePath: string): string;
  parseGitignorePatterns(content: string): string[];
  loadGitignorePatterns(): void;
  scanProjectFiles(): Promise<string[]>;
  calculateFileChecksum(filePath: string): Promise<string>;
  generateFileChecksum(filePath: string): Promise<string>;
  verifyFileIntegrity(filePath: string): Promise<{checksum: string | null; verified: boolean; timestamp: string; category?: string; size?: number; error?: string}>;
  generateVerificationReport(): Promise<Attestium.VerificationReport>;
  exportVerificationData(): Promise<Attestium.Baseline>;
  compareWithBaseline(baseline: Attestium.Baseline, options?: {publicKey?: Attestium.KeyLike}): Promise<Attestium.BaselineComparison>;
  verifyImportedData(baseline: Attestium.Baseline, options?: {publicKey?: Attestium.KeyLike}): Promise<boolean>;
  generateChallenge(ttlMs?: number): Attestium.Challenge;
  validateChallenge(challenge: {expiresAt: string} | null | undefined): boolean;
  verifyChallenge(challenge: Attestium.Challenge | string, nonce: string): Promise<boolean>;
  generateVerificationResponse(nonce: string): Promise<Attestium.SignedEnvelope<Attestium.VerificationResponsePayload> | {payload: Attestium.VerificationResponsePayload; signature: null}>;
  setupRuntimeHooks(): void;
  getRuntimeVerificationStatus(): Promise<{enabled: boolean; totalModules: number; changedOnDisk: number; modules: Attestium.RuntimeModule[]}>;
  startContinuousVerification(interval?: number | 'random'): void;
  stopContinuousVerification(): void;
  runVerificationCycle(): Promise<Array<Omit<Attestium.IntegrityViolation, 'timestamp'>>>;
  isTpmAvailable(): Promise<boolean>;
  initializeTpm(): Promise<Attestium.AttestationKey>;
  generateHardwareAttestation(nonce: string, options?: {pcrList?: number[]}): Promise<Attestium.HardwareAttestation>;
  generateHardwareRandom(length?: number): Promise<{bytes: Buffer; source: 'tpm' | 'os'}>;
  getTpmInstallationInstructions(): string;
  getSecurityStatus(): Promise<Record<string, unknown>>;
  cleanup(): Promise<void>;

  on(event: 'integrityViolation', listener: (violation: Attestium.IntegrityViolation) => void): this;
  on(event: 'fileChanged', listener: (file: string, previousChecksum: string, newChecksum: string) => void): this;
  on(event: 'moduleLoaded', listener: (record: {filename: string; sha256: string; loadedAt: string}) => void): this;
  on(event: 'verificationError', listener: (error: Error) => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
}

declare namespace Attestium {
  export type KeyLike = string | Buffer | KeyObject;

  export type AttestiumOptions = {
    projectRoot?: string;
    includePatterns?: string[];
    excludePatterns?: string[];
    enableGitignoreInheritance?: boolean;
    enableRuntimeHooks?: boolean;
    signingKey?: KeyLike;
    continuousVerification?: boolean;
    verificationInterval?: number | 'random';
    customCategories?: Record<string, RegExp>;
    gitCommit?: string;
    deployTime?: string;
    enableTpm?: boolean;
    tpm?: TpmOptions;
    logger?: {log(message: string): void};
    developmentMode?: boolean;
    productionMode?: boolean;
  };

  export type FileRecord = {
    relativePath: string;
    checksum: string;
    gitBlobId: string;
    mode: '100644' | '100755' | '120000';
    size: number;
    category: string;
    verified: true;
  };

  export type WalkError = {path: string; error: string};

  export type VerificationReport = {
    timestamp: string;
    attestiumVersion: string;
    projectRoot: string;
    gitCommit: string | null;
    deployTime: string | null;
    files: FileRecord[];
    errors: WalkError[];
    digest: string;
    summary: {totalFiles: number; verifiedFiles: number; failedFiles: number; categories: Record<string, number>};
  };

  export type Baseline = {
    metadata: {attestiumVersion: string; timestamp: string; gitCommit: string | null; deployTime: string | null};
    files: Record<string, {checksum: string; category: string; size: number}>;
    summary: VerificationReport['summary'];
    digest: string;
    signature?: {alg: 'ed25519'; keyId: string; publicKey: string; value: string};
  };

  export type BaselineComparison = {
    valid: boolean;
    signature: SignatureCheck | null;
    added: string[];
    removed: string[];
    modified: string[];
    errors: Array<WalkError | {error: string}>;
  };

  export type Challenge = {nonce: string; timestamp: string; expiresAt: string};

  export type VerificationResponsePayload = {
    type: 'attestium-verification-response';
    nonce: string;
    timestamp: string;
    attestiumVersion: string;
    gitCommit: string | null;
    digest: string;
    summary: VerificationReport['summary'];
  };

  export type RuntimeModule = {filename: string; sha256: string; loadedAt: string; diskSha256: string | null; changedOnDisk: boolean};

  export type HardwareAttestation = {
    type: 'hardware-backed';
    nonce: string;
    reportDigest: string;
    softwareVerification: VerificationReport;
    hardwareAttestation: Quote;
    timestamp: string;
  };

  export type IntegrityViolation =
    | {type: 'fileChanged'; file: string; previousChecksum: string; newChecksum: string; timestamp: string}
    | {type: 'fileAdded'; file: string; newChecksum: string; timestamp: string}
    | {type: 'fileRemoved'; file: string; previousChecksum: string; timestamp: string};

  // ─── signing ──────────────────────────────────────────────────────────

  export type SignedEnvelope<T = unknown> = {alg: 'ed25519'; keyId: string; publicKey: string; payload: T; signature: string};
  export type SignatureCheck = {valid: boolean; trusted: boolean; keyId: string | null; error?: string};

  // ─── TPM ──────────────────────────────────────────────────────────────

  export type TpmOptions = {
    tcti?: string;
    akHandle?: string;
    timeout?: number;
    devices?: string[];
    run?: (file: string, args: string[], options: {env: NodeJS.ProcessEnv; timeout: number; cwd?: string}) => Promise<string>;
  };

  export type AttestationKey = {handle: string; publicKey: string; keyId: string};

  export type Quote = {
    keyId: string;
    handle: string;
    hashAlg: string;
    message: string;
    signature: string;
    pcrs: Record<string, Record<string, string>>;
  };

  export class Tpm {
    static verifyQuote(input: {quote: Quote; publicKey: string; nonce: string; expectedPcrs?: Record<string, Record<string, string>>}): {valid: boolean; errors: string[]; attest?: Record<string, unknown>; pcrs?: Quote['pcrs']};
    static parseAttest(buffer: Buffer): Record<string, unknown>;
    static parsePcrYaml(text: string): Record<string, Record<string, string>>;
    static readonly HASH_SIZES: Record<string, number>;
    constructor(options?: TpmOptions);
    checkAvailability(): Promise<{available: boolean; reason?: string; family?: string | null}>;
    isAvailable(): Promise<boolean>;
    getAttestationKey(handle?: string): Promise<AttestationKey>;
    createAttestationKey(options?: {handle?: string; algorithm?: 'rsa' | 'ecc'; replace?: boolean}): Promise<AttestationKey>;
    /** The AK's TPM2B_PUBLIC, base64. */
    getAttestationKeyPublicArea(handle?: string): Promise<string>;
    /** The EK's public area and, when the manufacturer stored one, its certificate (base64 DER). */
    getEndorsement(options?: {algorithm?: 'rsa' | 'ecc'}): Promise<{algorithm: 'rsa' | 'ecc'; publicArea: string; certificate: string | null}>;
    /** Recover the secret a verifier encrypted to this TPM's EK for the AK (base64 in and out). */
    activateCredential(options: {credential: string; algorithm?: 'rsa' | 'ecc'; handle?: string}): Promise<string>;
    quote(options: {nonce: string; pcrs?: number[]; bank?: string; handle?: string}): Promise<Quote>;
    readPcrs(pcrs?: number[], bank?: string): Promise<Record<string, string>>;
    extendPcr(pcr: number, bank: string, digest: string): Promise<void>;
    getRandom(length?: number): Promise<Buffer>;
  }

  // ─── process integrity ────────────────────────────────────────────────

  export type Finding = {check: string; type: string; severity: 'critical' | 'warning' | 'info'; detail: unknown};

  export type ProcessReport = {
    pid: string;
    platform: string;
    timestamp: string;
    /** The language runtime (Linux only; null elsewhere). */
    runtime: runtimes.Runtime | null;
    memoryMaps: Record<string, any>;
    executablePages: {supported: boolean; matched: boolean | null; regions: Array<Record<string, any>>; mismatched: Array<Record<string, any>>; skipped: Array<Record<string, any>>; error?: string};
    linkerIntegrity: {
      supported: boolean;
      clean: boolean | null;
      findings?: Array<{type: string; value: string; severity?: Finding['severity']}>;
      /** The PM2 application the process belongs to, from pm2_env (cluster mode) or its separate variables (fork mode). */
      pm2?: Pm2Settings;
      /** Set when the process overwrote its command line (process.title); the hidden bytes are padding. */
      cmdlineRewritten?: {hiddenBytes: number; originalBytes: number};
      /** Inspector ports named by the process's options. */
      inspectorPorts?: number[];
      [key: string]: unknown;
    };
    tracer: {supported: boolean; traced: boolean | null; tracerPid?: number | null; [key: string]: unknown};
    fileDescriptors: {supported: boolean; totalFds: number; suspicious: Array<Record<string, any>>; [key: string]: unknown};
    listeningSockets: {supported: boolean; listening: Array<{address: string; port: number}>; error?: string};
    inspectorPorts: number[];
    findings: Finding[];
    passed: boolean;
    /** Checks that could not run, e.g. for lack of permission. */
    incomplete: Array<{check: string; error: string}>;
  };

  export type Pm2Settings = {name: string | null; script: string | null; nodeArgs: string[]; interpreterArgs: string[]};

  export type ProcessInfo = {
    pid: string;
    supported: boolean;
    name?: string;
    ppid?: number;
    uid?: number;
    startTimeMs?: number;
    cmdline?: string[];
    exe?: string | null;
    exeDeleted?: boolean;
    cwd?: string | null;
  };

  export class ProcessIntegrity {
    static findNodeInjectionFlags(args: string[], options?: {hasScript?: boolean}): {preloads: string[]; inspector: string[]; ports: number[]};
    static parsePm2Environment(value: string | null): Pm2Settings | null;
    static parsePm2Fields(fields: Record<string, string>): Pm2Settings | null;

    constructor(options?: {
      expectedLibs?: string[];
      maxAnonExecRegions?: number;
      timeout?: number;
      platform?: string;
      run?: (file: string, args: string[], options: {timeout: number}) => string;
      procRoot?: string;
      ldPreloadPath?: string;
      inspectorPorts?: number[];
      nodeExecutables?: string[];
    });

    getProcessInfo(pid: string | number): ProcessInfo;
    listProcesses(filter?: {uid?: number; cwdPrefix?: string; exe?: string}): ProcessInfo[];
    checkMemoryMaps(pid: string | number): ProcessReport['memoryMaps'];
    checkExecutablePages(pid: string | number): ProcessReport['executablePages'];
    checkLinkerIntegrity(pid: string | number, options?: {isNode?: boolean; runtime?: string}): ProcessReport['linkerIntegrity'];
    checkTracerPid(pid: string | number): ProcessReport['tracer'];
    checkFileDescriptors(pid: string | number): ProcessReport['fileDescriptors'];
    checkListeningSockets(pid: string | number): ProcessReport['listeningSockets'];
    detectRuntime(pid: string | number, options?: {libraries?: string[]; nodeRelease?: boolean}): runtimes.Runtime;
    checkAll(pid: string | number, options?: {isNode?: boolean; runtime?: string; nodeRelease?: boolean}): ProcessReport;
  }

  // ─── release verification ─────────────────────────────────────────────

  export type InstalledPackage = {name: string; version: string | null; path: string; digest: string; fileCount: number; files?: Record<string, string>; invalid?: true};
  /** A link in node_modules and the installed package (its path) it points to. */
  export type PackageLink = {path: string; target: string};
  /** What each link name may resolve to: in the project's node_modules, in a package's (by name@version), anywhere. */
  export type LockfileLinks = {
    importer: Record<string, Array<{name: string; version: string | null}>>;
    owners: Record<string, Record<string, Array<{name: string; version: string | null}>>>;
    declared: Record<string, Array<{name: string; version: string | null}>>;
  };
  export type PackageReference = {name: string; version: string; integrity: string | null; tarball: string | null; source: string; github?: GithubCommit; path?: string};
  export type GithubCommit = {owner: string; repo: string; commit: string};
  export type PackageManifest = {files: Record<string, string>; digest: string; fileCount: number; bundled: Array<{name: string; version: string | null; digest: string; fileCount: number}>; binFixes?: Record<string, string>; fixedDigest?: string};
  /** `patched`: pnpm patches by spec, with the files each touches and its text; null when the patch file cannot be read. */
  export type PackagePolicy = {patched: Record<string, {files: string[]; text: string} | null>; built: string[]};
  export type CheckResult = {name: string; passed: boolean; details: Record<string, any>};

  export class ReleaseVerification {
    static parseLockfile(text: string, format: 'pnpm' | 'npm'): {format: string; lockfileVersion: unknown; packages: PackageReference[]; links: LockfileLinks};
    /** Package links pointing to a package other than the one the lockfile resolves the name to. */
    static retargetedLinks(packageLinks: PackageLink[], packages: InstalledPackage[], links?: LockfileLinks): string[];
    static parseShasums(text: string): Map<string, string>;
    static githubCommitOf(source: string): GithubCommit | null;
    static filesNeeded(lock: {packages: PackageReference[]}, policy: PackagePolicy): Set<string>;
    static foreignCacheFiles(caches?: Array<{path: string; files: string[]}>): string[];
    static verifyIntegrity(data: Buffer, integrity: string): boolean;
    static filesTouchedByPatch(patch: string): string[];
    static packageManifestFromFiles(files: Map<string, Buffer | string>): PackageManifest;
    static nodeReleaseTarget(platform: string, arch: string): {platform: string; arch: string};
    static isValidPackageName(name: string): boolean;
    static globalModulesDir(execPath?: string, platform?: string): string;

    constructor(options?: {
      projectRoot?: string;
      nodeDistUrl?: string;
      registryUrl?: string;
      githubArchiveUrl?: string;
      cacheDir?: string;
      nodeKeyring?: string;
      timeout?: number;
      concurrency?: number;
      maxRetries?: number;
      retryDelay?: number;
    });

    getNodeShasums(version: string): Promise<Map<string, string>>;
    getOfficialNodeBinary(target: {version: string; platform: string; arch: string}): Promise<{sha256: string; source: string; archive: string; archiveSha256: string}>;
    getOfficialNodeArchive(target: {version: string; platform: string; arch: string}, shasums?: Map<string, string>): Promise<{archive: string; archiveSha256: string; files: Record<string, string>; versions: Record<string, string>}>;
    verifyNodeRelease(options?: {execPath?: string; version?: string; platform?: string; arch?: string; sha256?: string}): Promise<CheckResult>;
    scanInstalledPackages(nodeModulesDir?: string, options?: {includeFiles?: boolean | ((item: InstalledPackage) => boolean)}): Promise<{packages: InstalledPackage[]; unaccounted: string[]; links: Array<{path: string; target: string | null; problem: string}>; packageLinks: PackageLink[]; caches: Array<{path: string; files: string[]}>; errors: WalkError[]}>;
    getRegistryReference(name: string, version: string): Promise<{integrity: string; tarball: string}>;
    getPackageManifest(reference: {name: string; version: string; integrity?: string | null; github?: GithubCommit}): Promise<PackageManifest>;
    getPackageFiles(reference: {name: string; version: string; integrity?: string | null; github?: GithubCommit}, paths: string[]): Promise<Map<string, Buffer>>;
    readLockfile(root?: string): {format: string; lockfileVersion: unknown; packages: PackageReference[]};
    readPackagePolicy(root?: string): PackagePolicy;
    comparePackages(input: {
      installed: InstalledPackage[];
      references?: PackageReference[];
      policy?: Partial<PackagePolicy>;
      manifestProvider?: (item: InstalledPackage) => Promise<PackageManifest | null>;
      resolveFiles?: (item: InstalledPackage) => Promise<Record<string, string> | null>;
    }): Promise<{passed: boolean; summary: Record<string, number>; findings: Array<Record<string, any>>; files: Map<string, Record<string, string>>}>;
    verifyModules(): Promise<CheckResult>;
    verifyGlobalPackage(packageDir: string, options?: {node?: {version: string; platform: string; arch: string}}): Promise<CheckResult>;
    verifyAll(options?: {checkNode?: boolean; node?: {execPath?: string; version?: string; platform?: string; arch?: string}; globalDir?: string; globalPackages?: string[]; modules?: boolean}): Promise<{timestamp: string; platform: string; arch: string; nodeVersion: string; checks: Record<string, CheckResult>; passed: boolean; summary: string}>;
  }

  export namespace signing {
    export const ALGORITHM: 'ed25519';
    export function generateKeyPair(): {publicKey: string; privateKey: string};
    export function fingerprint(key: KeyLike): string;
    export function sign<T>(payload: T, privateKey: KeyLike): SignedEnvelope<T>;
    export function verify(envelope: unknown, trustedPublicKey?: KeyLike): SignatureCheck;
    export function toPublicKey(key: KeyLike): KeyObject;
    export function toPrivateKey(key: KeyLike): KeyObject;
  }

  export namespace ima {
    export const DEFAULT_LOG: string;
    export type Entry = {pcr: number; templateName: string; templateDigest: string; templateData: Buffer; violation: boolean; fileHashAlgorithm?: string; fileHash?: string; path?: string};
    export function parseBinaryLog(buffer: Buffer, options?: {littleEndian?: boolean}): Entry[];
    export function replay(entries: Entry[], bank?: string, pcr?: number): string;
    export function backedEntries(entries: Entry[], quoted: string, bank?: string, pcr?: number): Entry[] | null;
    /** File measurements of one PCR (default 10); violations and ima-buf (buffer) entries are left out. */
    export function measurementsByPath(entries: Entry[], options?: {pcr?: number}): Map<string, {algorithm: string; hash: string; count: number; hashes: string[]}>;
    export function readLog(file?: string): Buffer;
  }

  export namespace fileTree {
    export type Entry = {path: string; type: 'file' | 'symlink'; mode: string; size: number; sha256: string; gitBlobId: string; ctimeMs: number; mtimeMs: number; target?: string};
    export function gitBlobId(content: Buffer | string): string;
    export function hashFile(filePath: string, options?: {root?: string; rootOwnedLinks?: boolean; inode?: number}): Promise<{sha256: string; gitBlobId: string; size: number}>;
    export function openInRoot(root: string, file: string, options?: {flags?: number; rootOwnedLinks?: boolean}): number;
    export function globToRegExp(pattern: string): RegExp;
    export function createMatcher(patterns?: string[]): (relativePath: string) => boolean;
    export function toPosixRelative(root: string, fullPath: string): string;
    export type WalkOptions = {exclude?: (relativePath: string, isDirectory: boolean) => boolean; concurrency?: number; root?: string; rootOwnedLinks?: boolean};
    /** Each directory listed, '.' for the top: adding, removing or renaming an entry changes both times. */
    export type Directory = {path: string; ctimeMs: number; mtimeMs: number};
    /** With hash: false, each entry is only stat'ed: its path, type and times. */
    export type StatEntry = Pick<Entry, 'path' | 'type' | 'ctimeMs' | 'mtimeMs'>;
    export function walkTree(root: string, options: WalkOptions & {hash: false}): Promise<{entries: StatEntry[]; directories: Directory[]; errors: WalkError[]}>;
    export function walkTree(root: string, options?: WalkOptions & {hash?: true}): Promise<{entries: Entry[]; directories: Directory[]; errors: WalkError[]}>;
    export function manifestDigest(entries: Array<{path: string; sha256: string; type?: 'file' | 'symlink'}>): string;
  }

  export namespace http {
    /** The signature of dns.lookup. */
    export type Lookup = (hostname: string, options: {all?: boolean; family?: number}, callback: (error: NodeJS.ErrnoException | null, address: string | Array<{address: string; family: number}>, family?: number) => void) => void;
    /** With denyPrivateAddresses, refuse (EPRIVATEADDRESS) to connect to a private address (isPrivateAddress), checked when connecting and on every redirect. */
    export type GetOptions = {headers?: Record<string, string>; timeout?: number; deadline?: number; maxBytes?: number; maxRedirects?: number; maxRetries?: number; retryDelay?: number; ca?: string | Buffer; allowHttp?: boolean; denyPrivateAddresses?: boolean; lookup?: Lookup};
    export function httpGet(url: string, options?: GetOptions): Promise<Buffer>;
    export function httpGetJson(url: string, options?: GetOptions): Promise<any>;
    export function assertAllowedUrl(url: URL, options?: {allowHttp?: boolean; denyPrivateAddresses?: boolean}): void;
    /** Loopback, private, carrier-grade NAT, link-local, unspecified, unique-local, multicast or reserved (also inside IPv6 forms); true for anything not an IP address. */
    export function isPrivateAddress(address: string): boolean;
    /** A lookup that fails (EPRIVATEADDRESS) for a name resolving to any private address. */
    export function privateAddressLookup(resolve?: Lookup): Lookup;
    /** The lookup and agent options of http.request that enforce denyPrivateAddresses. */
    export function connectOptions(options?: {denyPrivateAddresses?: boolean; lookup?: Lookup}): {lookup?: Lookup; agent?: false};
  }

  export namespace util {
    /** Existence by stat(), which honors file capabilities (unlike access()). */
    export function exists(file: string): boolean;
    export function canonicalize(value: unknown): string;
    export function isPlainObject(value: unknown): boolean;
    export function sha256(data: string | Buffer | Uint8Array): string;
    export function digestOf(value: unknown): string;
    export function safeEqual(a: unknown, b: unknown): boolean;
    export function normalizePid(pid: string | number): string;
    export function normalizeNonce(nonce: string): string;
    export function generateNonce(bytes?: number): string;
    export function parallelMap<T>(tasks: Array<() => Promise<T>>, concurrency: number): Promise<T[]>;
    /** Set an own property, even one named __proto__. */
    export function setOwn(object: object, key: string, value: unknown): void;
  }

  /** A comparison of installed packages with their references. */
  export type Comparison = {
    passed: boolean;
    summary: Record<string, number>;
    findings: Array<{status: 'failed' | 'unverifiable' | 'error'; package: string; path: string; reason?: string; modified?: string[]; missing?: string[]; added?: string[]}>;
    issues: Array<{severity: 'fail' | 'warn' | 'info'; message: string; items?: string[]}>;
  };

  export type Scan = {packages: Array<{name: string | null; version: string | null; path: string; files?: Record<string, string>; invalid?: boolean; meta?: Record<string, any>}>; unaccounted: string[]; links: Array<{path: string; problem: string}>; caches: Array<{path: string; files: string[]}>; errors: WalkError[]; meta?: Record<string, any>};

  export type EcosystemPlugin = {
    detect(root: string): string[];
    installRoot(dir: string): string;
    scan(dir: string, options?: {root?: string}): Promise<Scan>;
    readLock(repoDir: string, options?: {lockfile?: string}): any;
    compare(input: {scan: Scan; lock: any; store: ecosystems.ReferenceStore; release?: ReleaseVerification; gitTrees?: gitTrees.GitTrees; covered?: (file: string) => boolean; distro?: {archive: distro.ArchiveReference; arch: string}}): Promise<Comparison>;
  };

  export namespace ecosystems {
    export const INSTALLED: Record<'npm' | 'pypi' | 'rubygems' | 'hex' | 'composer' | 'maven' | 'nuget', EcosystemPlugin>;
    export const COMPILED: Record<'go' | 'cargo', any>;
    export class NoLockfileError extends Error {}
    export class ReferenceStore {
      constructor(options?: {cacheDir?: string | null; httpOptions?: http.GetOptions; concurrency?: number; urls?: Partial<Record<'pypi' | 'pypiFiles' | 'rubygems' | 'hex' | 'nuget' | 'maven' | 'packagist' | 'crates' | 'goproxy' | 'uvSource', string>>});
      urls: Record<string, string>;
      memo<T>(key: string, compute: () => Promise<T>, options?: {persist?: boolean}): Promise<T>;
      get(url: string, options?: http.GetOptions): Promise<Buffer>;
      getJson(url: string, options?: http.GetOptions): Promise<any>;
    }
    export function detectInstalls(root: string, names?: string[]): Array<{ecosystem: string; dir: string; installRoot: string}>;
    /** Compare two `path -> sha256` maps. */
    export function compareFiles(installed: Record<string, string>, expected: Record<string, string>, options?: {allowExtra?: (file: string, hash: string) => boolean; allowMissing?: (file: string) => boolean; equivalent?: (file: string, installed: string, expected: string) => boolean}): {modified: string[]; missing: string[]; added: string[]};
    /** The common comparison shape from per-package results. */
    export function collect(results: any[], issues?: Comparison['issues']): Comparison;
    /** CSV as Python's csv module writes it (a wheel's RECORD). */
    export function parseCsv(text: string): string[][];
    export const npm: EcosystemPlugin;
    export const pypi: EcosystemPlugin;
    export const rubygems: EcosystemPlugin;
    export const hex: EcosystemPlugin;
    export const composer: EcosystemPlugin;
    export const maven: EcosystemPlugin;
    export const nuget: EcosystemPlugin;
    export namespace go {
      export function readLock(repoDir: string, options?: {dir?: string}): {format: 'go.sum'; module: string | null; sums: Map<string, string>};
      export function compareBuildInfo(input: {info: any; lock: any; commit?: string; label?: string}): Comparison;
    }
    export namespace cargo {
      export function readLock(repoDir: string, options?: {lockfile?: string}): {format: 'cargo'; file: string; packages: Map<string, {name: string; version: string; source: string | null; checksum: string | null}>};
      export function compareAuditable(input: {packages: any[]; lock: any}): Comparison;
    }
  }

  export namespace runtimes {
    export type Runtime = {name: string; label: string; version: string | null; by: string | null};
    export type Finding = {type: string; severity: 'critical' | 'warning' | 'info'; value?: string; detail?: unknown};
    export const PROFILES: Record<string, any>;
    /** The profile of a process of no known runtime. */
    export const NATIVE: {name: 'native'; label: string; executable: null; library: null; inspect: (...args: any[]) => {findings: Finding[]; ports: number[]; extra: Record<string, unknown>}; debugPorts: number[]};
    /** What a memfd (`/memfd:<name>`) is when the runtime's profile names it, or null. */
    export function runtimeMemfd(runtime: string | null | undefined, target: string): string | null;
    /** Exactly the RUBYOPT and RUBYLIB `bundle exec` sets, or null. */
    export function bundlerSetup(environment: Record<string, string>): {lib: string; version: string} | null;
    /** `bundle exec` with the Bundler in the interpreter's standard library (Debian, Ubuntu). */
    export function standardBundlerSetup(environment: Record<string, string>, exe?: string): {setup: string} | null;
    export function inspectRuntime(runtime: Runtime | string, input: {environment: Record<string, string>; cmdline: string[]; exe?: string; duplicates?: string[]; raw?: string; parentIsPm2?: boolean}): {findings: Finding[]; ports: number[]; extra: Record<string, unknown>};
    /** Split an options string as NODE_OPTIONS is split. */
    export function splitOptions(text: string): string[];
    export const findNodeInjectionFlags: typeof ProcessIntegrity.findNodeInjectionFlags;
    export const parsePm2Environment: typeof ProcessIntegrity.parsePm2Environment;
    export const parsePm2Fields: typeof ProcessIntegrity.parsePm2Fields;
    export function detectRuntime(input: {exe: string | null; libraries?: string[]; nodeRelease?: boolean}): Runtime;
    export function parseEnviron(text: string): {values: Record<string, string>; duplicates: string[]};
  }

  export namespace elf {
    export function parseElf(buffer: Buffer): any;
    export function sectionData(buffer: Buffer, elf: any, name: string): Buffer | null;
    export function goBuildInfo(buffer: Buffer): {goVersion: string; path: string | null; main: {path: string; version: string; sum?: string} | null; deps: Array<{path: string; version: string; sum?: string; replace?: {path: string; version?: string; sum?: string}}>; settings: Record<string, string>; unsupported?: string} | null;
    export function cargoAuditable(buffer: Buffer): Array<{name: string; version: string; source: string; kind: 'runtime' | 'build'; root: boolean}> | null;
  }

  export namespace zip {
    export function listZip(buffer: Buffer): Array<{name: string; method: number; compressedSize: number; size: number; crc32: number; offset: number}>;
    export function readZipFiles(buffer: Buffer, options?: {stripFirstComponent?: boolean; maxUncompressedBytes?: number; filter?: (name: string) => boolean}): Map<string, Buffer>;
  }

  export namespace toml {
    export class TomlError extends Error {}
    export function parseToml(text: string): Record<string, any>;
  }

  export namespace sigstore {
    export class SigstoreError extends Error {}
    /** Fulcio certificate extension OIDs, by claim name. */
    export const FULCIO_OIDS: Record<string, string>;
    /** Parse a trusted_root.json. */
    export function loadTrustedRoot(json: any): {authorities: any[]; logs: any[]; [key: string]: any};
    /** The Fulcio identity claims of a certificate. */
    export function certificateClaims(certificate: X509Certificate): Record<string, string | null>;
    /** DSSE pre-authentication encoding. */
    export function pae(payloadType: string, payload: Buffer): Buffer;
    export function rootFromInclusionProof(index: number | bigint, size: number | bigint, leafHash: Buffer, proof: Buffer[]): Buffer;
    export function verifyCheckpoint(envelope: string, log: any): any;
    export function verifyTimestamp(der: Buffer, signature: Buffer, trustedRoot: any): Date;
    export function verifyBundle(bundle: any, options: {trustedRoot: any; publicKeys?: Record<string, string>; identity?: Record<string, string | RegExp>; subject?: {algorithm: string; digest: string}; payloadType?: string; artifact?: Buffer}): {statement: any; claims: Record<string, string | null> | null; signedAt: Date; keyHint: string | null};
  }

  export namespace tuf {
    export class TufClient {
      constructor(options: {metadataUrl: string; targetsUrl?: string; initialRoot: any; cacheDir?: string | null; httpOptions?: http.GetOptions; now?: () => Date});
      target(name: string): Promise<Buffer>;
      /** Run the update workflow once and cache the result. */
      refresh(): Promise<any>;
    }
    export class TufError extends Error {}
    /** The OLPC canonical JSON TUF signs. */
    export function canonicalJson(value: unknown): string;
    export function verifyThreshold(metadata: any, keys: any, role: any, name: string): void;
    export function checkHashes(content: Buffer, meta: any, name: string): void;
    export function matchPath(pattern: string, name: string): boolean;
  }

  export namespace attestations {
    export const GITHUB_ISSUER: 'https://token.actions.githubusercontent.com';
    export function snappyDecompress(buffer: Buffer): Buffer;
    export class SigstoreTrust {
      constructor(options?: {cacheDir?: string; httpOptions?: http.GetOptions; tufUrl?: string; initialRoot?: any; trustedRoot?: any; npmKeys?: any});
      trustedRoot(): Promise<any>;
      npmKeys(): Promise<Record<string, {pem: string; validUntil: number}>>;
    }
    /** `repository`: the repository the workflow ran for; `workflowRepository`: where the (reusable) workflow file lives, default `repository`. */
    export type Signer = {repository: string; workflow?: string; ref?: string; workflowRepository?: string};
    export function githubIdentity(signer: Signer): Record<string, string | RegExp>;
    export function githubAttestations(input: {repository: string; digest: string; httpOptions?: http.GetOptions; apiUrl?: string}): Promise<any[]>;
    export function verifyGithubAttestation(input: {bundles: any[]; digest: string; signer: Signer; trust: SigstoreTrust; predicateType?: string}): Promise<{statement: any; claims: Record<string, string | null>; signedAt: Date}>;
    export function npmProvenance(input: {name: string; version: string; integrity: string; trust: SigstoreTrust; registryUrl?: string; httpOptions?: http.GetOptions}): Promise<{provenance: boolean; reason?: string; repository?: string | null; commit?: string | null; workflow?: string; signedAt?: string; published?: boolean}>;
  }

  export namespace checksums {
    export type Source = {url: string; signature?: {type: 'gpg' | 'minisign' | 'sigstore'; url?: string; keyring?: string; publicKey?: string; identity?: Record<string, string>}};
    export function parseChecksums(text: string): Map<string, string>;
    export function fetchChecksums(source: Source, context: {store: ecosystems.ReferenceStore; trustedRoot?: () => Promise<any>}): Promise<{checksums: Map<string, string>; signed: boolean}>;
    /** Why gpgv status output (--status-fd) does not show only good signatures by keys that are neither revoked nor expired, or null. */
    export function gpgStatusProblem(status: string): string | null;
    export function verifyMinisign(data: Buffer, signatureText: string, publicKey: string): boolean;
    /** Turn `/.../` strings into regular expressions. */
    export function toIdentity(identity?: Record<string, string>): Record<string, string | RegExp>;
  }

  export namespace distro {
    export type Owner = {name: string; version: string; arch: string; source: string | null; listedAs: string; installedAt: string | null};
    export class DpkgDatabase {
      constructor(options?: {root?: string});
      available(): boolean;
      ownerOf(file: string): Owner | null;
    }
    export type Archive = {url: string; suites: string[]; components: string[]; keyring: string; snapshot?: string};
    export class ArchiveReference {
      constructor(options: {archives: Archive[]; store: ecosystems.ReferenceStore; gpgv?: string; dpkgDeb?: string});
      files(name: string, version: string, arch: string, installedAt?: string | null): Promise<Record<string, string>>;
      locate(name: string, version: string, arch: string, installedAt?: string | null): Promise<{url: string; filename: string; sha256: string} | null>;
      /** The versions of a package the archives publish for an architecture. */
      versions(name: string, arch: string): Promise<string[]>;
      /** The contents of a published package's regular files that `wanted` selects (paths absolute). */
      contents(name: string, version: string, arch: string, wanted: (file: string) => boolean): Promise<Map<string, Buffer>>;
      /** Names the archives, for cache keys. */
      cacheKey(): string;
    }
    export function parseStanzas(text: string): Array<Record<string, string>>;
    /** The paths a file may be listed under (merged /usr). */
    export function aliases(file: string): string[];
    export function osRelease(root?: string): {id: string | null; versionId: string | null; codename: string | null} | null;
    export function defaultArchives(release: {id: string | null; codename: string | null}, arch: string): Archive[];
  }

  export namespace containers {
    export function containerOf(pid: string | number, procRoot?: string): {id: string; runtime: string} | null;
    export function inspectDocker(id: string, socketPath?: string): Promise<any>;
    export function inspectCri(id: string, options?: {crictl?: string}): Promise<any>;
    export function walkUpper(upper: string): Promise<{files: Record<string, [string, string]>; deleted: string[]; errors: WalkError[]}>;
    export function walkRootfs(pid: string | number, options?: {procRoot?: string; maxFiles?: number}): Promise<{files: Record<string, [string, string]>; fileCount: number; errors: WalkError[]; truncated?: boolean; mounts: any[]}>;
    export type Mount = {destination: string; source: string | null; root: string | null; fsType: string | null; readOnly: boolean};
    export function parseMountinfo(text: string): any[];
    /** Mounts that bring in files from outside the image. */
    export function externalMounts(mounts: any[]): Mount[];
    export function rootOverlay(mounts: any[]): any;
  }

  export namespace oci {
    export type Reference = {registry: string; repository: string; tag: string | null; digest: string | null};
    export function parseReference(reference: string): Reference;
    export class Registry {
      constructor(options?: {httpOptions?: http.GetOptions; endpoints?: Record<string, string>; credentials?: Record<string, {token: string} | {username: string; password: string}>});
      manifest(reference: Reference, digest?: string): Promise<any>;
      blob(reference: Reference, digest: string, maxBytes?: number): Promise<Buffer>;
      platformManifest(reference: Reference, platform: {os: string; architecture: string; variant?: string}): Promise<{digest: string; manifest: any; index: string | null}>;
      referrerBundles(reference: Reference, digest: string): Promise<any[]>;
    }
    /** Refuses images whose layers together expand beyond `maxBytes` (default 4 GiB). */
    export function imageFiles(registry: Registry, reference: Reference, manifest: any, options?: {maxBytes?: number}): Promise<Map<string, [string, string]>>;
    export function decompressLayer(blob: Buffer, mediaType: string, maxBytes?: number): Buffer;
    export function applyLayers(tars: Buffer[]): Map<string, [string, string]>;
    export function compareRootfs(actual: Record<string, [string, string]>, expected: Map<string, [string, string]>, options?: {ignore?: (file: string) => boolean}): {modified: string[]; missing: string[]; added: string[]; modeChanged: string[]};
  }

  export namespace confidential {
    export const TSM_ROOT: string;
    export function collectReport(reportData: Buffer, options?: {entry?: string | null; root?: string}): {provider: string; report: Buffer; auxblob: Buffer | null};
    export function reportData(nonce: string, digest: string): Buffer;
    export function verifyConfidential(evidence: {provider: string; report: string; auxblob?: string | null}, expected: Buffer, options?: {vcek?: Buffer; roots?: any; allowMigrationAgent?: boolean; root?: any; qeIdentity?: QeIdentity}): {type: 'sev-snp' | 'tdx'; measurement: string; [key: string]: any};
    /** Intel's TDX quoting enclave identity, required of the QE report by default. */
    export type QeIdentity = {mrsigner: string; isvprodid: number; attributes: string; attributesMask: string; miscselect: string; miscselectMask: string};
    export const TD_QE_IDENTITY: QeIdentity;
    export function verifySnpReport(input: {report: Buffer; reportData: Buffer; vcek?: Buffer; certificates?: any; roots?: any; allowMigrationAgent?: boolean}): {type: 'sev-snp'; measurement: string; [key: string]: any};
    export function verifyTdxQuote(input: {quote: Buffer; reportData: Buffer; root?: any; qeIdentity?: QeIdentity}): {type: 'tdx'; measurement: string; [key: string]: any};
    export function parseSnpReport(buffer: Buffer): Record<string, any>;
    export function snpProduct(parsed: Record<string, any>): string;
    export function tcbParts(tcb: bigint | Buffer, product: string): Record<string, number>;
    export function parseCertificateTable(auxblob: Buffer): Map<string, Buffer>;
    export function vcekClaims(certificate: X509Certificate): Record<string, any>;
    export function vcekUrl(parsed: Record<string, any>, product: string, base?: string): string;
    export function parseTdxQuote(buffer: Buffer): Record<string, any>;
    export function amdRoots(): any;
  }

  export namespace tpmIdentity {
    export function parseTpmPublic(buffer: Buffer): {type: 'rsa' | 'ecc'; nameAlg: number; attributes: number; key: KeyObject; name: Buffer};
    export function attestationKeyProblems(parsed: {attributes: number}): string[];
    export function makeCredential(input: {ek: any; akName: Buffer; secret: Buffer}): Buffer;
    export function verifyEkCertificate(input: {certificate: Buffer; ekKey: KeyObject; roots: any[]; intermediates?: any[]}): {subject: string; issuer: string; chain: string[]};
    /** Whether the certificate may issue certificates: basicConstraints cA, and keyCertSign when it has a keyUsage extension. */
    export function isCertificateAuthority(certificate: X509Certificate): boolean;
    /** TPM object attribute bits. */
    export const ATTRIBUTE: Record<'fixedTPM' | 'fixedParent' | 'sensitiveDataOrigin' | 'userWithAuth' | 'restricted' | 'decrypt' | 'sign', number>;
    /** TPM 2.0 KDFa (SP800-108 counter mode, HMAC). */
    export function kdfa(key: Buffer, label: string, contextU: Buffer, contextV: Buffer, bits: number): Buffer;
    /** TPM 2.0 KDFe (SP800-56A concatenation). */
    export function kdfe(z: Buffer, label: string, partyU: Buffer, partyV: Buffer, bits: number): Buffer;
  }

  export namespace monitor {
    export function readLog(file: string, options?: {since?: number; limit?: number; maxBytes?: number}): {since: string | null; until: string | null; execs: any[]; maps: any[]; truncated: boolean; malformed: number};
    export function run(options: {log: string; maxBytes?: number; bpftrace?: string; mmap?: boolean; maxStrlen?: number; onLine?: (line: string) => void}): {child: ChildProcess; done: Promise<number>};
    export function summarize(lines: Iterable<string>, options?: {since?: number; limit?: number}): {since: string | null; until: string | null; execs: any[]; maps: any[]; truncated: boolean; malformed: number};
    export function parseLine(line: string): any;
    export function escapePath(path: string, cut?: boolean): string;
    export function eventReader(onEvent: (event: any) => void, token: string): (line: string) => void;
    /** The bpftrace program. */
    export function script(options?: {mmap?: boolean; token?: string}): string;
  }

  export namespace schema {
    export function compile(schema: any, options?: {maxErrors?: number}): (value: unknown) => {valid: boolean; errors: string[]};
  }

  export namespace gitTrees {
    export class GitTrees {
      constructor(options: {cacheDir: string; git?: string; timeout?: number; allowFileUrls?: boolean});
      tree(url: string, commit: string): Promise<Map<string, {mode: string; blob: string}>>;
      file(url: string, commit: string, path: string): Promise<Buffer | null>;
    }
    /** Match the files a .gitattributes marks export-ignore. */
    export function exportIgnore(gitattributesText: string): (path: string) => boolean;
  }

  export namespace asn1 {
    export type Element = {tagClass: number; constructed: boolean; tag: number; start: number; contentStart: number; end: number; children: Element[] | null; buffer: Buffer};
    export class Asn1Error extends Error {}
    export function parse(der: Buffer): Element;
    export function parseElement(buffer: Buffer, offset?: number, limit?: number): Element;
    export function certificateExtensions(der: Buffer): Map<string, {critical: boolean; value: Buffer}>;
    export function oid(element: Element): string;
    export function text(element: Element): string;
    export function integer(element: Element): bigint;
    export function time(element: Element): Date;
    export function content(element: Element): Buffer;
    export function raw(element: Element): Buffer;
  }

  export namespace evidence {
    export const TYPE: 'attestium-evidence';
    export const VERSION: 2;
    export const MANIFEST_TYPE: 'attestium-manifest';
    export const MANIFEST_NAME: '.attestium-manifest.json';
    export function validateEvidence(evidence: unknown): {valid: boolean; errors: string[]};
    export function evidenceDigest(evidence: Record<string, unknown>): string;
    export function createManifest(directory: string, options: {repository: string; commit: string; exclude?: string[]}): Promise<{type: 'attestium-manifest'; version: 1; repository: string; commit: string; files: Record<string, [string, string]>}>;
    export function parseManifest(text: string | Buffer): any;
  }
}

export = Attestium;
