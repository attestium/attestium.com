/**
 * Bacopa - Runtime Code Verification and Integrity Monitoring
 * TypeScript definitions
 */

export type BacopaOptions = {
  /** Root directory of the project to monitor */
  projectRoot?: string;
  /** File patterns to include in verification */
  includePatterns?: string[];
  /** File patterns to exclude from verification */
  excludePatterns?: string[];
  /** Enable runtime module loading hooks */
  enableRuntimeHooks?: boolean;
  /** Automatically load .gitignore patterns */
  enableGitignoreInheritance?: boolean;
  /** Git commit hash for verification */
  gitCommit?: string;
  /** Deployment timestamp */
  deployTime?: string;
  /** Custom logger instance */
  logger?: Logger;
};

export type Logger = {
  log(message: string): void;
};

export type FileChecksum = {
  checksum: string;
  size: number;
  modified: string;
};

export type ComprehensiveChecksums = {
  source_code: Record<string, FileChecksum>;
  dependencies: Record<string, FileChecksum>;
  static_assets: Record<string, FileChecksum>;
  configuration: Record<string, FileChecksum>;
  documentation: Record<string, FileChecksum>;
  metadata: {
    git_commit: string | undefined;
    deploy_time: string;
    generation_time: string;
    total_files: number;
    verification_version: string;
  };
};

export type LoadedModule = {
  filename: string;
  module_id: string;
  load_time: string;
  checksum: string | undefined;
  category: string;
};

export type VerificationStatus = {
  project_root: string;
  git_commit: string | undefined;
  deploy_time: string;
  runtime_hooks_enabled: boolean;
  loaded_modules_count: number;
  tracked_files_count: number;
  last_verification: VerificationResults | undefined;
  status: string;
};

export type Discrepancy = {
  type: 'missing_file' | 'checksum_mismatch' | 'unexpected_file';
  category: string;
  file: string;
  expected_checksum: string | undefined;
  actual_checksum: string | undefined;
  severity: 'critical' | 'warning' | 'info';
  description: string;
};

export type CategorySummary = {
  checked: number;
  failed: number;
};

export type VerificationResults = {
  status: 'success' | 'warning' | 'failed';
  timestamp: string;
  git_commit: string | undefined;
  total_files_checked: number;
  discrepancies: Discrepancy[];
  summary: {
    source_code: CategorySummary;
    dependencies: CategorySummary;
    static_assets: CategorySummary;
    configuration: CategorySummary;
    documentation: CategorySummary;
  };
};

/**
 * Main Bacopa class for runtime code verification
 */
export default class Bacopa {
  constructor(options?: BacopaOptions);

  /** Project root directory */
  readonly projectRoot: string;

  /** Git commit hash */
  readonly gitCommit: string | undefined;

  /** Deployment timestamp */
  readonly deployTime: string;

  /** File patterns to include */
  readonly includePatterns: string[];

  /** File patterns to exclude */
  readonly excludePatterns: string[];

  /** Whether runtime hooks are enabled */
  readonly enableRuntimeHooks: boolean;

  /**
   * Load and parse .gitignore patterns
   */
  loadGitignorePatterns(): void;

  /**
   * Parse .gitignore file content into exclude patterns
   */
  parseGitignorePatterns(content: string): string[];

  /**
   * Check if a file should be included in verification
   */
  shouldIncludeFile(filePath: string): boolean;

  /**
   * Setup runtime hooks to track module loading
   */
  setupRuntimeHooks(): void;

  /**
   * Track a loaded module
   */
  trackLoadedModule(filename: string, moduleId: string): void;

  /**
   * Generate comprehensive checksums for all files
   */
  generateComprehensiveChecksums(): Promise<ComprehensiveChecksums>;

  /**
   * Categorize a file based on its path and type
   */
  categorizeFile(relativePath: string): string;

  /**
   * Calculate checksum for a file
   */
  calculateFileChecksum(filePath: string): Promise<string | undefined>;

  /**
   * Walk directory recursively
   */
  walkDirectory(dir: string, callback: (filePath: string) => Promise<void>): Promise<void>;

  /**
   * Get current verification status
   */
  getVerificationStatus(): VerificationStatus;

  /**
   * Get list of loaded modules
   */
  getLoadedModules(): LoadedModule[];

  /**
   * Verify integrity against expected checksums
   */
  verifyIntegrity(expectedChecksums: ComprehensiveChecksums): Promise<VerificationResults>;

  /**
   * Generate a human-friendly verification report
   */
  generateHumanReport(verificationResults: VerificationResults): string;

  /**
   * Log a message with timestamp and level
   */
  log(message: string, level?: 'INFO' | 'WARN' | 'ERROR'): void;
}

export = Bacopa;

