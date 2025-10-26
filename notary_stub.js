// notary_stub.js
// Dev notary stub with strict CORS for Chrome extension development.
// Usage:
//   npm init -y
//   npm install express
//   node notary_stub.js
//
// Before running: set environment variable EXT_ORIGIN to your extension origin:
//   export EXT_ORIGIN="chrome-extension://REPLACE_WITH_YOUR_EXTENSION_ID"
//
// Example:
//   EXT_ORIGIN="chrome-extension://jgkbihacnefedkhmgfclmanfoaajignk" node notary_stub.js

const express = require('express');
const https = require('https');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const EXT_ORIGIN = process.env.EXT_ORIGIN || `chrome-extension://REPLACE_WITH_YOUR_EXTENSION_ID`;
const ALLOW_ORIGINS = new Set([EXT_ORIGIN, 'http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:9001', 'http://127.0.0.1:9001', 'http://localhost:3000', '*']);

const app = express();

// Custom CORS middleware that echoes allowed origin (safe) and supports OPTIONS preflight
app.use((req, res, next) => {
  const origin = req.headers.origin;
  // allow if origin is in allowlist OR allow all with '*'
  if (ALLOW_ORIGINS.has('*') || (origin && ALLOW_ORIGINS.has(origin))) {
    // Echo back the exact Origin (preferred over wildcard when extension origin is present)
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

// Utility: compute sha256 fingerprint from DER Buffer
function sha256FingerprintFromDER(derBuffer) {
  // Return fingerprint in canonical lower-case hex prefixed with "sha256:"
  const hash = crypto.createHash('sha256').update(derBuffer).digest('hex');
  return 'sha256:' + hash.toLowerCase();
}

// Probe hostname: connect to host:443, get peer cert raw DER (leaf)
function fetchLeafCertDER(hostname, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const opts = {
      host: hostname,
      port: 443,
      method: 'GET',
      path: '/',
      agent: false,
      rejectUnauthorized: false, // allow dev to retrieve cert even if untrusted
      timeout: timeoutMs
    };

    const req = https.request(opts, (res) => {
      try {
        const peer = res.socket.getPeerCertificate(true);
        if (!peer || !peer.raw) {
          reject(new Error('no_peer_cert'));
          return;
        }
        resolve(peer.raw);
      } catch (err) {
        reject(err);
      } finally {
        // consume response
        res.resume();
      }
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy(new Error('timeout'));
    });
    req.end();
  });
}

app.get('/observe', async (req, res) => {
  const host = req.query.host;
  const force = req.query.force;

  // Always respond JSON; do not return HTML.
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (!host) {
    return res.status(400).json({ error: 'missing_host' });
  }

  if (force && typeof force === 'string' && force.startsWith('sha256:')) {
    return res.json({ host, fingerprint_sha256: force, ts: new Date().toISOString() });
  }

  try {
    const der = await fetchLeafCertDER(host);
    const fingerprint = sha256FingerprintFromDER(der);
    return res.json({ host, fingerprint_sha256: fingerprint, ts: new Date().toISOString() });
  } catch (err) {
    // Always return JSON on failures (502) so extension never gets HTML
    const reason = err && err.message ? err.message : 'unknown';
    return res.status(502).json({ error: 'probe_failed', reason });
  }
});

app.listen(PORT, () => {
  console.log(`Notary stub listening on http://localhost:${PORT}`);
  console.log(`Allowed extension origin: ${EXT_ORIGIN}`);
  console.log(`Example: http://localhost:${PORT}/observe?host=github.com`);
});