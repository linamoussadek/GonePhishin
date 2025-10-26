#!/usr/bin/env node

/**
 * Simple Notary Stub Server for Testing
 * 
 * This is a minimal notary server that returns certificate fingerprints
 * for testing the TLS & Certificate Verification feature.
 * 
 * Usage: node notary-stub.js
 * 
 * The server will run on http://localhost:3000 and provide endpoints:
 * - GET /observe?host=example.com - Returns certificate fingerprint for the host
 * 
 * For testing, you can configure the extension to use:
 * - http://localhost:3000/observe
 * - http://localhost:3001/observe  
 * - http://localhost:3002/observe
 */

const express = require('express');
const https = require('https');
const crypto = require('crypto');
const { promisify } = require('util');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS for Chrome extensions
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Mock certificate database for testing
const mockCertificates = {
  'example.com': {
    fingerprint: 'sha256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
    issuer: 'CN=Example CA, O=Example Corp',
    timestamp: new Date().toISOString()
  },
  'github.com': {
    fingerprint: 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    issuer: 'CN=DigiCert SHA2 Extended Validation Server CA',
    timestamp: new Date().toISOString()
  },
  'bank.example': {
    fingerprint: 'sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
    issuer: 'CN=Bank CA, O=Bank Corp',
    timestamp: new Date().toISOString()
  }
};

// Function to get real certificate fingerprint (for production use)
async function getRealCertificateFingerprint(hostname) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: hostname,
      port: 443,
      path: '/',
      method: 'GET',
      rejectUnauthorized: false // For testing purposes
    };

    const req = https.request(options, (res) => {
      const cert = res.socket.getPeerCertificate(true);
      if (cert && cert.raw) {
        const fingerprint = crypto.createHash('sha256').update(cert.raw).digest('hex');
        resolve({
          fingerprint: `sha256:${fingerprint}`,
          issuer: cert.issuer ? cert.issuer.CN || 'Unknown' : 'Unknown',
          timestamp: new Date().toISOString()
        });
      } else {
        reject(new Error('No certificate found'));
      }
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.end();
  });
}

// Main observe endpoint
app.get('/observe', async (req, res) => {
  const hostname = req.query.host;
  
  if (!hostname) {
    return res.status(400).json({
      error: 'Missing host parameter',
      usage: 'GET /observe?host=example.com'
    });
  }

  try {
    let certData;
    
    // Check if we have mock data for this hostname
    if (mockCertificates[hostname]) {
      certData = mockCertificates[hostname];
      console.log(`📋 Using mock certificate for ${hostname}`);
    } else {
      // Try to get real certificate
      try {
        certData = await getRealCertificateFingerprint(hostname);
        console.log(`🔍 Retrieved real certificate for ${hostname}`);
      } catch (error) {
        console.log(`⚠️  Failed to get real certificate for ${hostname}: ${error.message}`);
        // Fallback to mock data
        certData = mockCertificates['example.com'];
        console.log(`📋 Using fallback mock certificate for ${hostname}`);
      }
    }

    // Return notary response
    const response = {
      host: hostname,
      fingerprint_sha256: certData.fingerprint,
      ts: certData.timestamp
    };

    console.log(`✅ Notary response for ${hostname}:`, response);
    res.json(response);

  } catch (error) {
    console.error(`❌ Error processing request for ${hostname}:`, error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Root endpoint with usage info
app.get('/', (req, res) => {
  res.json({
    name: 'Notary Stub Server',
    version: '1.0.0',
    endpoints: {
      observe: 'GET /observe?host=example.com',
      health: 'GET /health'
    },
    usage: 'This is a test notary server for the Gone Phishin\' extension'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Notary Stub Server running on http://localhost:${PORT}`);
  console.log(`📡 Endpoints:`);
  console.log(`   GET /observe?host=example.com`);
  console.log(`   GET /health`);
  console.log(`   GET /`);
  console.log(`\n🔧 For testing, configure extension notaries to use:`);
  console.log(`   http://localhost:${PORT}/observe`);
  console.log(`   http://localhost:${PORT + 1}/observe`);
  console.log(`   http://localhost:${PORT + 2}/observe`);
  console.log(`\n📋 Mock certificates available for: ${Object.keys(mockCertificates).join(', ')}`);
});

module.exports = app;
