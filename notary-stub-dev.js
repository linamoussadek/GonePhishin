#!/usr/bin/env node

/**
 * Development Notary Stub Server
 * 
 * A robust local notary server for testing the Gone Phishin' extension.
 * Performs real TLS handshakes to target hosts and returns certificate fingerprints.
 * 
 * Usage: node notary-stub-dev.js
 * Endpoint: http://localhost:9001/observe?host=example.com
 * 
 * Optional: ?force=fingerprint to simulate different notary votes for testing
 */

const express = require('express');
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const { promisify } = require('util');

const app = express();
const PORT = 9001;

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

// Parse JSON bodies
app.use(express.json());

// Real TLS certificate fetching
async function getRealCertificateFingerprint(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const options = {
      host: hostname,
      port: port,
      rejectUnauthorized: false, // For testing purposes
      timeout: 5000
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate(true);
      if (cert && cert.raw) {
        const fingerprint = crypto.createHash('sha256').update(cert.raw).digest('hex');
        socket.end();
        resolve({
          fingerprint: `sha256:${fingerprint}`,
          issuer: cert.issuer ? cert.issuer.CN || 'Unknown' : 'Unknown',
          subject: cert.subject ? cert.subject.CN || 'Unknown' : 'Unknown',
          notBefore: cert.validFrom,
          notAfter: cert.validTo
        });
      } else {
        socket.end();
        reject(new Error('No certificate found'));
      }
    });

    socket.on('error', (err) => {
      socket.end();
      reject(err);
    });

    socket.setTimeout(5000, () => {
      socket.end();
      reject(new Error('TLS handshake timeout'));
    });
  });
}

// Main observe endpoint
app.get('/observe', async (req, res) => {
  const hostname = req.query.host;
  const forceFingerprint = req.query.force;
  
  if (!hostname) {
    return res.status(400).json({
      error: 'Missing host parameter',
      usage: 'GET /observe?host=example.com'
    });
  }

  try {
    let certData;
    
    if (forceFingerprint) {
      // For testing: simulate different notary votes
      console.log(`🧪 Using forced fingerprint for ${hostname}: ${forceFingerprint}`);
      certData = {
        fingerprint: forceFingerprint,
        issuer: 'CN=Test CA',
        subject: `CN=${hostname}`,
        notBefore: new Date().toISOString(),
        notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
      };
    } else {
      // Get real certificate
      console.log(`🔍 Fetching real certificate for ${hostname}`);
      certData = await getRealCertificateFingerprint(hostname);
    }

    const response = {
      host: hostname,
      fingerprint_sha256: certData.fingerprint,
      issuer: certData.issuer,
      subject: certData.subject,
      not_before: certData.notBefore,
      not_after: certData.notAfter,
      ts: new Date().toISOString()
    };

    console.log(`✅ Notary response for ${hostname}:`, response);
    res.json(response);

  } catch (error) {
    console.error(`❌ Error fetching certificate for ${hostname}:`, error.message);
    res.status(500).json({
      error: 'Certificate fetch failed',
      message: error.message,
      host: hostname
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0-dev',
    endpoints: {
      observe: 'GET /observe?host=example.com',
      health: 'GET /health'
    }
  });
});

// Root endpoint with usage info
app.get('/', (req, res) => {
  res.json({
    name: 'Gone Phishin\' Notary Stub (Dev)',
    version: '1.0.0-dev',
    endpoints: {
      observe: 'GET /observe?host=example.com',
      health: 'GET /health'
    },
    usage: 'Development notary server for TLS certificate verification testing',
    testing: {
      normal: 'GET /observe?host=github.com',
      simulate_mitm: 'GET /observe?host=github.com&force=sha256:different_fingerprint',
      simulate_consensus: 'GET /observe?host=github.com&force=sha256:same_fingerprint'
    }
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
  console.log(`🚀 Development Notary Stub running on http://localhost:${PORT}`);
  console.log(`📡 Endpoints:`);
  console.log(`   GET /observe?host=example.com`);
  console.log(`   GET /health`);
  console.log(`   GET /`);
  console.log(`\n🧪 Testing endpoints:`);
  console.log(`   Normal: http://localhost:${PORT}/observe?host=github.com`);
  console.log(`   Simulate MITM: http://localhost:${PORT}/observe?host=github.com&force=sha256:different_fingerprint`);
  console.log(`   Simulate Consensus: http://localhost:${PORT}/observe?host=github.com&force=sha256:same_fingerprint`);
  console.log(`\n🔧 Configure extension notaries to use:`);
  console.log(`   http://localhost:${PORT}/observe`);
});

module.exports = app;
