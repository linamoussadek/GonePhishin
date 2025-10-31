const express = require('express');
const https = require('https');
const crypto = require('crypto');
const router = express.Router();

// CORS middleware
router.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  
  next();
});

router.get('/observe', async (req, res) => {
  const host = req.query.host;
  const force = req.query.force;
  
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  
  // Validate input
  if (!host) {
    return res.status(400).json({ error: 'missing_host' });
  }
  
  // Testing mode: force specific fingerprint
  if (force && force.startsWith('sha256:')) {
    console.log(`🧪 Testing mode: forcing fingerprint for ${host}`);
    return res.json({ 
      host, 
      fingerprint_sha256: force, 
      ts: new Date().toISOString() 
    });
  }
  
  // Production: get real certificate
  try {
    console.log(`🔍 Fetching certificate for: ${host}`);
    
    const cert = await getCertificateFromHost(host);
    
    if (!cert || !cert.raw) {
      throw new Error('No certificate received');
    }
    
    // Generate SHA-256 fingerprint
    const fingerprint = generateSha256Fingerprint(cert.raw);
    
    console.log(`✅ Got fingerprint for ${host}: ${fingerprint.substring(0, 32)}...`);
    
    return res.json({ 
      host, 
      fingerprint_sha256: fingerprint, 
      ts: new Date().toISOString() 
    });
    
  } catch (error) {
    console.error(`❌ Failed to get certificate for ${host}:`, error.message);
    return res.status(502).json({ 
      error: 'probe_failed', 
      reason: error.message 
    });
  }
});

// Helper: Get certificate from host
function getCertificateFromHost(hostname) {
  return new Promise((resolve, reject) => {
    const options = {
      host: hostname,
      port: 443,
      method: 'GET',
      path: '/',
      agent: false,
      rejectUnauthorized: false, // Allow self-signed for notary purposes
      timeout: 5000
    };
    
    const req = https.request(options, (res) => {
      try {
        const cert = res.socket.getPeerCertificate(true);
        res.resume(); // Consume response
        res.destroy();
        resolve(cert);
      } catch (err) {
        reject(err);
      }
    });
    
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('timeout'));
    });
    
    req.end();
  });
}

// Helper: Generate SHA-256 fingerprint
function generateSha256Fingerprint(certDer) {
  const hash = crypto.createHash('sha256')
    .update(certDer)
    .digest('hex');
  return `sha256:${hash.toLowerCase()}`;
}

module.exports = router;

