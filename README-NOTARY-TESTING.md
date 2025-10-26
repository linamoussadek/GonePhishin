# Gone Phishin' - Notary System Testing Guide

This guide explains how to test the TLS & Certificate Verification + Multi-Vantage Notary Checks feature.

## 🚀 Quick Start

### 1. Start the Development Notary Server

```bash
# Install dependencies (if not already done)
npm install express

# Start the notary server
node notary-stub-dev.js
```

The server will run on `http://localhost:9001` and provide:
- Real TLS certificate fetching
- CORS-enabled endpoints for Chrome extensions
- Testing endpoints for different scenarios

### 2. Configure the Extension

The extension is already configured to use the local notary endpoints:
- `http://localhost:9001/observe`
- `http://localhost:9001/observe?force=sha256:consensus_fingerprint`
- `http://localhost:9001/observe?force=sha256:consensus_fingerprint`

### 3. Test the Extension

1. **Reload the extension** in `chrome://extensions/`
2. **Navigate to `https://github.com`**
3. **Click the extension icon**
4. **Click "🧪 Test TLS Check"**
5. **Watch the console** for detailed logs

## 🧪 Test Scenarios

### Scenario 1: Normal Operation
- **Expected**: All notaries return same fingerprint
- **Result**: Consensus = `consistent`, Severity = `low`
- **Console**: `✅ Notary consensus: secure`

### Scenario 2: MITM Simulation
- **Setup**: Use `?force=sha256:different_fingerprint` in notary endpoints
- **Expected**: Notaries return different fingerprint than local
- **Result**: Consensus = `mitm_detected`, Severity = `critical`
- **Console**: `🚨 CRITICAL: Notary disagreement detected`

### Scenario 3: Notary Unavailability
- **Setup**: Stop the notary server
- **Expected**: All notary queries fail
- **Result**: Consensus = `no_data`, Severity = `medium`
- **Console**: `⚠️ WARNING: Notary consensus issue`
- **Popup**: `⚠️ Notary servers unreachable`

### Scenario 4: Mixed Responses
- **Setup**: Some notaries return different fingerprints
- **Expected**: Partial agreement between notaries
- **Result**: Consensus = `mixed`, Severity = `medium`
- **Console**: `⚠️ WARNING: Notary consensus issue`

## 🔧 Configuration Flags

### TEST_SIMULATE_TLS Flag
The extension uses a `TEST_SIMULATE_TLS=true` flag to prevent false session flips during testing:

```javascript
const TEST_SIMULATE_TLS = true; // Flag to prevent session flips in simulation mode
```

When enabled:
- Session consistency checks are suspended
- Console shows: `🧪 SIMULATION MODE: not a real TLS fingerprint — session checks suspended for origin X`
- No false session flip detections

## 📊 Expected Console Logs

### Successful Notary Query
```
🌐 Querying notary services for hostname: github.com
📡 Notary endpoints: ['http://localhost:9001/observe', ...]
🔍 Querying notary: http://localhost:9001/observe
✅ Notary response from http://localhost:9001/observe: {host: 'github.com', fingerprint_sha256: 'sha256:abc123...', ...}
📊 Notary query results: {total: 3, successful: 3, failed: 0, votes: ['sha256:abc123...', 'sha256:abc123...', 'sha256:abc123...'], errors: []}
🤝 Consensus evaluation: {consensus: 'consistent', severity: 'low', message: 'Notaries agree with local view'}
✅ Notary consensus: secure
```

### Notary Unavailability
```
🌐 Querying notary services for hostname: github.com
🔍 Querying notary: http://localhost:9001/observe
❌ Notary query failed for http://localhost:9001/observe: Network error (CORS/connectivity)
📊 Notary query results: {total: 3, successful: 0, failed: 3, votes: [], errors: ['Network error (CORS/connectivity)', 'Timeout after 3000ms', 'Failed to fetch']}
🤝 Consensus evaluation: {consensus: 'no_data', severity: 'medium', message: 'Notary servers unreachable — unable to corroborate certificate'}
⚠️ WARNING: Notary consensus issue
```

### MITM Detection
```
🌐 Querying notary services for hostname: github.com
📊 Notary query results: {total: 3, successful: 3, failed: 0, votes: ['sha256:different...', 'sha256:different...', 'sha256:different...'], errors: []}
🤝 Consensus evaluation: {consensus: 'mitm_detected', severity: 'critical', message: 'Potential MITM detected - notaries disagree'}
🚨 CRITICAL: Notary disagreement detected
```

## 🛠️ Manual Testing Script

Run the automated test script:

```bash
node test-notary-system.js
```

This will test:
- Notary server availability
- Basic notary queries
- Different consensus scenarios
- Error handling

## 🔍 Debugging Tips

### 1. Check Notary Server Status
```bash
curl http://localhost:9001/health
```

### 2. Test Notary Query Manually
```bash
curl "http://localhost:9001/observe?host=github.com"
```

### 3. Simulate MITM
```bash
curl "http://localhost:9001/observe?host=github.com&force=sha256:different_fingerprint"
```

### 4. Check Extension Console
- Open `chrome://extensions/`
- Find "Gone Phishin'" extension
- Click "Inspect views: service worker"
- Check console logs

## 📋 Production Deployment

For production use, replace the local notary endpoints with real notary services:

```javascript
const NOTARY_ENDPOINTS = [
  'https://your-notary-service.com/observe',
  'https://another-notary-service.com/observe',
  'https://third-notary-service.com/observe'
];
```

**Note**: The current implementation uses localhost for development. In production, you would run real notary servers that perform actual TLS handshakes to target hosts.

## 🚨 Error Handling

The system handles various error scenarios:

1. **Network Errors**: CORS, connectivity issues
2. **Timeout Errors**: Requests taking too long
3. **Invalid Responses**: Non-JSON responses
4. **Backend Errors**: HTML error pages instead of JSON
5. **Rate Limiting**: Too many requests to same hostname

All errors are logged with sanitized information and don't crash the extension flow.

## 📈 Performance

- **Timeout**: 3 seconds per notary query
- **Cache TTL**: 10 minutes
- **Rate Limit**: 1 query per hostname per 30 seconds
- **Concurrent**: All notary queries run in parallel

This ensures the extension remains responsive while providing robust certificate verification.
