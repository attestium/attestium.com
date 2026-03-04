/**
 * TPM 2.0 Integration for Attestium
 * Provides hardware-backed verification using Trusted Platform Module
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {execSync} = require('node:child_process');
const TPM2 = require('trusted-platform-module-2');

/**
 * TPM Integration class for hardware-backed attestation
 */
class TpmIntegration {
  constructor(options = {}) {
    this.tpm2 = new TPM2();
    this.tpmAvailable = null;
    this.keyContext = options.keyContext || 'attestium-key.ctx';
    this.sealedDataPath = options.sealedDataPath || 'attestium-sealed.dat';
    this.options = options;
  }

  /**
   * Check if TPM 2.0 and tpm2-tools are available on the system
   * @returns {Promise<boolean>} True if TPM is available
   */
  async checkTpmAvailability() {
    if (this.tpmAvailable !== null) {
      return this.tpmAvailable;
    }

    try {
      // First check if tpm2-tools are installed
      const tpm2ToolsAvailable = await this.checkTpm2Tools();
      if (!tpm2ToolsAvailable) {
        console.warn('[ATTESTIUM] tpm2-tools not found. Please install tpm2-tools for TPM functionality.');
        this.tpmAvailable = false;
        return false;
      }

      // Check if TPM device is available
      const tpmDeviceAvailable = fs.existsSync('/dev/tpm0') || fs.existsSync('/dev/tpmrm0');
      if (!tpmDeviceAvailable) {
        console.warn('[ATTESTIUM] TPM device not found. Hardware TPM may not be available.');
        this.tpmAvailable = false;
        return false;
      }

      // Try to get TPM capabilities
      execSync('tpm2_getcap properties-fixed', {stdio: 'pipe'});

      this.tpmAvailable = true;
      console.log('[ATTESTIUM] TPM 2.0 hardware and tools detected');
      return true;
    } catch (error) {
      console.warn('[ATTESTIUM] TPM not available:', error.message);
      this.tpmAvailable = false;
      return false;
    }
  }

  /**
   * Check if tpm2-tools are installed
   * @returns {Promise<boolean>} True if tpm2-tools are available
   */
  async checkTpm2Tools() {
    try {
      execSync('which tpm2_getcap', {stdio: 'pipe'});
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Generate installation instructions for missing dependencies
   * @returns {string} Installation instructions
   */
  getInstallationInstructions() {
    return `
TPM 2.0 Setup Instructions

To use hardware-backed verification, you need to install tpm2-tools:

**Ubuntu/Debian:**
\`\`\`bash
sudo apt-get update
sudo apt-get install tpm2-tools libtss2-dev
\`\`\`

**CentOS/RHEL/Fedora:**
\`\`\`bash
sudo yum install tpm2-tools tpm2-tss-devel
# or for newer versions:
sudo dnf install tpm2-tools tpm2-tss-devel
\`\`\`

**From Source (like Keylime):**
\`\`\`bash
# Install tpm2-tools from source
git clone https://github.com/tpm2-software/tpm2-tools.git tpm2-tools
pushd tpm2-tools
./bootstrap
./configure --prefix=/usr/local
make
sudo make install
popd
\`\`\`

**Verify Installation:**
\`\`\`bash
tpm2_getcap properties-fixed
\`\`\`

If you see TPM properties, your setup is working correctly!
`;
  }

  /**
   * Initialize TPM for Attestium use
   * @returns {Promise<boolean>} True if initialization successful
   */
  async initializeTpm() {
    const available = await this.checkTpmAvailability();
    if (!available) {
      throw new Error('TPM not available. ' + this.getInstallationInstructions());
    }

    try {
      // Create primary key if it doesn't exist
      if (!fs.existsSync(this.keyContext)) {
        await this.createPrimaryKey();
      }

      console.log('[ATTESTIUM] TPM initialized successfully');
      return true;
    } catch (error) {
      console.error('[ATTESTIUM] TPM initialization failed:', error.message);
      throw error;
    }
  }

  /**
   * Create a primary key in TPM
   * @returns {Promise<void>}
   */
  async createPrimaryKey() {
    try {
      this.tpm2.createPrimary({
        hierarchy: 'owner',
        keyAlgorithm: 'rsa2048',
        output: this.keyContext,
      });
      console.log('[ATTESTIUM] TPM primary key created');
    } catch (error) {
      throw new Error(`Failed to create TPM primary key: ${error.message}`);
    }
  }

  /**
   * Seal data to TPM (encrypt data that can only be unsealed in current system state)
   * @param {string} data - Data to seal
   * @param {Array<number>} pcrList - PCR values to seal against
   * @returns {Promise<string>} Path to sealed data file
   */
  async sealData(data, pcrList = [0, 1, 2, 3]) {
    await this.initializeTpm();

    try {
      // Create a temporary file with the data
      const temporaryDataFile = path.join(os.tmpdir(), `attestium-data-${Date.now()}.tmp`);
      fs.writeFileSync(temporaryDataFile, data);

      // Seal the data using TPM
      this.tpm2.create({
        parentContext: this.keyContext,
        publicKey: `${this.sealedDataPath}.pub`,
        privateKey: `${this.sealedDataPath}.priv`,
        input: temporaryDataFile,
        pcrList: pcrList.join(','),
      });

      // Clean up temporary file
      fs.unlinkSync(temporaryDataFile);

      console.log('[ATTESTIUM] Data sealed to TPM successfully');
      return this.sealedDataPath;
    } catch (error) {
      throw new Error(`Failed to seal data to TPM: ${error.message}`);
    }
  }

  /**
   * Unseal data from TPM (decrypt data sealed to current system state)
   * @returns {Promise<string>} Unsealed data
   */
  async unsealData() {
    await this.initializeTpm();

    try {
      const temporaryOutputFile = path.join(os.tmpdir(), `attestium-unsealed-${Date.now()}.tmp`);

      // Load the sealed object
      this.tpm2.load({
        parentContext: this.keyContext,
        publicKey: `${this.sealedDataPath}.pub`,
        privateKey: `${this.sealedDataPath}.priv`,
        output: `${this.sealedDataPath}.ctx`,
      });

      // Unseal the data
      this.tpm2.unseal({
        itemContext: `${this.sealedDataPath}.ctx`,
        output: temporaryOutputFile,
      });

      // Read the unsealed data
      const unsealedData = fs.readFileSync(temporaryOutputFile, 'utf8');

      // Clean up
      fs.unlinkSync(temporaryOutputFile);

      console.log('[ATTESTIUM] Data unsealed from TPM successfully');
      return unsealedData;
    } catch (error) {
      throw new Error(`Failed to unseal data from TPM: ${error.message}`);
    }
  }

  /**
   * Generate hardware random bytes using TPM
   * @param {number} length - Number of random bytes to generate
   * @returns {Promise<Buffer>} Random bytes
   */
  async generateHardwareRandom(length = 32) {
    await this.initializeTpm();

    try {
      const randomData = this.tpm2.getRandom(length);
      console.log('[ATTESTIUM] Hardware random generated');
      return Buffer.from(randomData, 'hex');
    } catch (error) {
      throw new Error(`Failed to generate hardware random: ${error.message}`);
    }
  }

  /**
   * Create TPM-backed attestation quote
   * @param {string} nonce - Challenge nonce
   * @param {Array<number>} pcrList - PCR values to include in quote
   * @returns {Promise<Object>} Attestation quote with signature
   */
  async createAttestationQuote(nonce, pcrList = [0, 1, 2, 3, 4, 5, 6, 7]) {
    await this.initializeTpm();

    try {
      const quoteFile = path.join(os.tmpdir(), `attestium-quote-${Date.now()}.quote`);
      const sigFile = path.join(os.tmpdir(), `attestium-sig-${Date.now()}.sig`);

      // Create attestation quote
      this.tpm2.quote({
        keyContext: this.keyContext,
        pcrList: pcrList.join(','),
        message: nonce,
        signature: sigFile,
        message: quoteFile,
      });

      // Read quote and signature
      const quote = fs.readFileSync(quoteFile);
      const signature = fs.readFileSync(sigFile);

      // Clean up temporary files
      fs.unlinkSync(quoteFile);
      fs.unlinkSync(sigFile);

      const attestation = {
        quote: quote.toString('base64'),
        signature: signature.toString('base64'),
        nonce,
        pcrList,
        timestamp: new Date().toISOString(),
        tpmVersion: await this.getTmpVersion(),
      };

      console.log('[ATTESTIUM] TPM attestation quote created');
      return attestation;
    } catch (error) {
      throw new Error(`Failed to create attestation quote: ${error.message}`);
    }
  }

  /**
   * Get TPM version information
   * @returns {Promise<Object>} TPM version details
   */
  async getTmpVersion() {
    try {
      const output = execSync('tpm2_getcap properties-fixed', {encoding: 'utf8'});
      return {
        version: '2.0',
        details: output.trim(),
      };
    } catch (error) {
      return {
        version: 'unknown',
        error: error.message,
      };
    }
  }

  /**
   * Verify system integrity using TPM measurements
   * @param {Object} expectedMeasurements - Expected PCR values
   * @returns {Promise<Object>} Verification result
   */
  async verifySystemIntegrity(expectedMeasurements = {}) {
    await this.initializeTpm();

    try {
      // Read current PCR values
      const pcrOutput = execSync('tpm2_pcrread', {encoding: 'utf8'});
      const currentMeasurements = this.parsePcrOutput(pcrOutput);

      const result = {
        verified: true,
        measurements: currentMeasurements,
        expectedMeasurements,
        differences: [],
        timestamp: new Date().toISOString(),
      };

      // Compare with expected values if provided
      if (Object.keys(expectedMeasurements).length > 0) {
        for (const [pcr, expectedValue] of Object.entries(expectedMeasurements)) {
          const currentValue = currentMeasurements[pcr];
          if (currentValue !== expectedValue) {
            result.verified = false;
            result.differences.push({
              pcr,
              expected: expectedValue,
              actual: currentValue,
            });
          }
        }
      }

      console.log(`[ATTESTIUM] System integrity verification ${result.verified ? 'passed' : 'failed'}`);
      return result;
    } catch (error) {
      throw new Error(`Failed to verify system integrity: ${error.message}`);
    }
  }

  /**
   * Parse PCR output from tpm2_pcrread
   * @param {string} output - Raw PCR output
   * @returns {Object} Parsed PCR values
   */
  parsePcrOutput(output) {
    const measurements = {};
    const lines = output.split('\n');

    for (const line of lines) {
      const match = line.match(/(\d+)\s*:\s*0x([A-Fa-f\d]+)/);
      if (match) {
        measurements[match[1]] = match[2].toLowerCase();
      }
    }

    return measurements;
  }

  /**
   * Clean up TPM resources
   * @returns {Promise<void>}
   */
  async cleanup() {
    try {
      // Remove temporary files
      const filesToClean = [
        this.keyContext,
        `${this.sealedDataPath}.pub`,
        `${this.sealedDataPath}.priv`,
        `${this.sealedDataPath}.ctx`,
      ];

      for (const file of filesToClean) {
        if (fs.existsSync(file)) {
          fs.unlinkSync(file);
        }
      }

      console.log('[ATTESTIUM] TPM resources cleaned up');
    } catch (error) {
      console.warn('[ATTESTIUM] TPM cleanup warning:', error.message);
    }
  }
}

module.exports = TpmIntegration;

