const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const Attestium = require('../lib/index');

const app = express();
const port = process.env.PORT || 3000;

// Initialize Attestium
const attestium = new Attestium({
  projectRoot: process.cwd(),
  enableRuntimeHooks: true,
});

// Middleware
app.use(express.json());
app.use(express.static('public'));

// In-memory store for nonces (use Redis in production)
const nonceStore = new Map();
const NONCE_EXPIRY = 5 * 60 * 1000; // 5 minutes

/**
 * Generate a cryptographically secure nonce
 * @returns {string} Base64 encoded nonce
 */
function generateNonce() {
  return crypto.randomBytes(32).toString('base64');
}

/**
 * Store nonce with expiration
 * @param {string} nonce - The nonce to store
 * @param {Object} metadata - Additional metadata
 */
function storeNonce(nonce, metadata = {}) {
  nonceStore.set(nonce, {
    ...metadata,
    timestamp: Date.now(),
    used: false,
  });

  // Clean up expired nonces
  setTimeout(() => {
    nonceStore.delete(nonce);
  }, NONCE_EXPIRY);
}

/**
 * Validate and consume nonce
 * @param {string} nonce - The nonce to validate
 * @returns {boolean} True if nonce is valid and unused
 */
function validateNonce(nonce) {
  const stored = nonceStore.get(nonce);

  if (!stored) {
    return false; // Nonce not found
  }

  if (stored.used) {
    return false; // Nonce already used
  }

  if (Date.now() - stored.timestamp > NONCE_EXPIRY) {
    nonceStore.delete(nonce);
    return false; // Nonce expired
  }

  // Mark as used
  stored.used = true;
  return true;
}

/**
 * Generate verification challenge for client
 */
app.get('/api/verification/challenge', async (request, res) => {
  try {
    const nonce = generateNonce();
    const timestamp = new Date().toISOString();

    // Generate current verification report
    const report = await attestium.generateVerificationReport();

    // Create challenge data
    const challengeData = {
      nonce,
      timestamp,
      serverChecksum: crypto.createHash('sha256')
        .update(JSON.stringify(report.summary))
        .digest('hex'),
      totalFiles: report.summary.totalFiles,
      verifiedFiles: report.summary.verifiedFiles,
    };

    // Store nonce with challenge metadata
    storeNonce(nonce, {
      challengeData,
      serverReport: report,
    });

    res.json({
      success: true,
      challenge: challengeData,
      message: 'Verification challenge generated',
    });
  } catch (error) {
    console.error('Error generating challenge:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate verification challenge',
    });
  }
});

/**
 * Verify client response to challenge
 */
app.post('/api/verification/verify', async (request, res) => {
  try {
    const {nonce, clientSignature, expectedChecksum} = request.body;

    if (!nonce || !clientSignature || !expectedChecksum) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: nonce, clientSignature, expectedChecksum',
      });
    }

    // Validate nonce
    if (!validateNonce(nonce)) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired nonce',
      });
    }

    // Get stored challenge data
    const stored = nonceStore.get(nonce);
    const {challengeData, serverReport} = stored;

    // Verify client signature
    const expectedSignature = crypto.createHash('sha256')
      .update(nonce + challengeData.serverChecksum + expectedChecksum)
      .digest('hex');

    if (clientSignature !== expectedSignature) {
      return res.status(401).json({
        success: false,
        error: 'Invalid client signature',
      });
    }

    // Verify server state hasn't changed
    const currentReport = await attestium.generateVerificationReport();
    const currentChecksum = crypto.createHash('sha256')
      .update(JSON.stringify(currentReport.summary))
      .digest('hex');

    if (currentChecksum !== challengeData.serverChecksum) {
      return res.status(409).json({
        success: false,
        error: 'Server state changed during verification',
        details: {
          originalChecksum: challengeData.serverChecksum,
          currentChecksum,
        },
      });
    }

    // Verification successful
    res.json({
      success: true,
      verification: {
        timestamp: new Date().toISOString(),
        nonce,
        serverChecksum: currentChecksum,
        clientExpected: expectedChecksum,
        match: currentChecksum === expectedChecksum,
        report: {
          totalFiles: currentReport.summary.totalFiles,
          verifiedFiles: currentReport.summary.verifiedFiles,
          categories: currentReport.summary.categories,
        },
      },
      message: 'Verification completed successfully',
    });

    // Clean up used nonce
    nonceStore.delete(nonce);
  } catch (error) {
    console.error('Error during verification:', error);
    res.status(500).json({
      success: false,
      error: 'Verification failed due to server error',
    });
  }
});

/**
 * Get current server verification status
 */
app.get('/api/verification/status', async (request, res) => {
  try {
    const report = await attestium.generateVerificationReport();
    const runtimeStatus = attestium.getRuntimeVerificationStatus();

    res.json({
      success: true,
      status: {
        timestamp: new Date().toISOString(),
        projectRoot: attestium.projectRoot,
        gitCommit: attestium.gitCommit,
        deployTime: attestium.deployTime,
        files: {
          total: report.summary.totalFiles,
          verified: report.summary.verifiedFiles,
          failed: report.summary.failedFiles,
          categories: report.summary.categories,
        },
        runtime: {
          hooksEnabled: attestium.enableRuntimeHooks,
          loadedModules: runtimeStatus.totalModules,
        },
        integrity: {
          checksum: crypto.createHash('sha256')
            .update(JSON.stringify(report.summary))
            .digest('hex'),
        },
      },
    });
  } catch (error) {
    console.error('Error getting status:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get verification status',
    });
  }
});

/**
 * Export verification data for external auditing
 */
app.get('/api/verification/export', async (request, res) => {
  try {
    const exportData = await attestium.exportVerificationData();

    res.json({
      success: true,
      export: exportData,
      message: 'Verification data exported successfully',
    });
  } catch (error) {
    console.error('Error exporting data:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to export verification data',
    });
  }
});

/**
 * Serve client-side verification page
 */
app.get('/', (request, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attestium Verification Demo</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .status {
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover { background: #0056b3; }
        button:disabled { background: #6c757d; cursor: not-allowed; }
        .code {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧪 Attestium Verification Demo</h1>
        <p><strong>Element of Attestation</strong> - Real-time code integrity verification</p>

        <div id="status"></div>

        <h3>Actions</h3>
        <button onclick="getStatus()">Get Server Status</button>
        <button onclick="startVerification()">Start Verification</button>
        <button onclick="exportData()">Export Verification Data</button>

        <div id="results"></div>
    </div>

    <script>
        let currentChallenge = null;

        function showStatus(message, type = 'info') {
            const statusDiv = document.getElementById('status');
            statusDiv.innerHTML = \`<div class="\${type}">\${message}</div>\`;
        }

        function showResults(data) {
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = \`
                <h3>Results</h3>
                <div class="code">\${JSON.stringify(data, null, 2)}</div>
            \`;
        }

        async function getStatus() {
            try {
                showStatus('Fetching server status...', 'info');
                const response = await fetch('/api/verification/status');
                const data = await response.json();

                if (data.success) {
                    showStatus('Server status retrieved successfully', 'success');
                    showResults(data.status);
                } else {
                    showStatus(\`Error: \${data.error}\`, 'error');
                }
            } catch (error) {
                showStatus(\`Network error: \${error.message}\`, 'error');
            }
        }

        async function startVerification() {
            try {
                showStatus('Starting verification process...', 'info');

                // Step 1: Get challenge from server
                const challengeResponse = await fetch('/api/verification/challenge');
                const challengeData = await challengeResponse.json();

                if (!challengeData.success) {
                    showStatus(\`Challenge failed: \${challengeData.error}\`, 'error');
                    return;
                }

                currentChallenge = challengeData.challenge;
                showStatus('Challenge received, generating client response...', 'info');

                // Step 2: Generate client signature
                const expectedChecksum = currentChallenge.serverChecksum; // In real scenario, client would have its own expected value
                const clientSignature = await generateClientSignature(
                    currentChallenge.nonce,
                    currentChallenge.serverChecksum,
                    expectedChecksum
                );

                // Step 3: Send verification response
                const verifyResponse = await fetch('/api/verification/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        nonce: currentChallenge.nonce,
                        clientSignature,
                        expectedChecksum
                    })
                });

                const verifyData = await verifyResponse.json();

                if (verifyData.success) {
                    showStatus('Verification completed successfully!', 'success');
                    showResults(verifyData.verification);
                } else {
                    showStatus(\`Verification failed: \${verifyData.error}\`, 'error');
                    if (verifyData.details) {
                        showResults(verifyData.details);
                    }
                }

            } catch (error) {
                showStatus(\`Verification error: \${error.message}\`, 'error');
            }
        }

        async function generateClientSignature(nonce, serverChecksum, expectedChecksum) {
            // In a real implementation, this would use WebCrypto API
            // For demo purposes, we'll simulate the signature generation
            const data = nonce + serverChecksum + expectedChecksum;

            // Simple hash simulation (in production, use proper crypto)
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);
            const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async function exportData() {
            try {
                showStatus('Exporting verification data...', 'info');
                const response = await fetch('/api/verification/export');
                const data = await response.json();

                if (data.success) {
                    showStatus('Verification data exported successfully', 'success');
                    showResults(data.export);
                } else {
                    showStatus(\`Export failed: \${data.error}\`, 'error');
                }
            } catch (error) {
                showStatus(\`Export error: \${error.message}\`, 'error');
            }
        }

        // Auto-load status on page load
        window.addEventListener('load', getStatus);
    </script>
</body>
</html>
  `);
});

// Error handling middleware
app.use((error, request, res, next) => {
  console.error('Express error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

// Start server
app.listen(port, () => {
  console.log(`🧪 Attestium Express Demo running on http://localhost:${port}`);
  console.log('📊 Visit the URL to see the interactive verification demo');
  console.log('🔍 API endpoints:');
  console.log('  GET  /api/verification/status    - Get current verification status');
  console.log('  GET  /api/verification/challenge - Get verification challenge');
  console.log('  POST /api/verification/verify    - Verify challenge response');
  console.log('  GET  /api/verification/export    - Export verification data');
});

module.exports = app;

