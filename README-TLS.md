# Gone Phishin' - TLS & Certificate Verification Feature

This document describes the TLS & Certificate Verification + Multi-Vantage Notary Checks feature added to the Gone Phishin' Chrome extension.

## 🎯 Overview

The TLS & Certificate Verification feature provides comprehensive protection against man-in-the-middle (MITM) attacks by:

- **Local Certificate Intelligence**: Detecting issuer drift, session consistency issues, and weak TLS configurations
- **Multi-Vantage Notary Checks**: Querying multiple trusted notary endpoints to verify certificate fingerprints
- **Real-time Protection**: Showing interstitials for high-severity events and warnings for medium-severity issues

## 🏗️ Architecture

### Core Components

1. **Background Service Worker** (`background/background.js`)
   - TLS security verification on completed requests
   - Certificate fingerprint generation and storage
   - Notary client for multi-vantage verification
   - Session consistency and issuer drift detection

2. **Interstitial Page** (`interstitial.html`, `interstitial.js`)
   - Full-page blocking interface for high-severity events
   - Evidence display with certificate details
   - User override options (Proceed Anyway, Pin for 24h)

3. **Popup Interface** (`popup/popup.html`, `popup/popup.js`, `popup/popup.css`)
   - TLS status display for current site
   - Notary consensus information
   - Security alerts and warnings

4. **Notary Stub Server** (`notary-stub.js`)
   - Test notary server for development and testing
   - Mock certificate database
   - Real certificate fingerprint retrieval

## 🚀 Installation & Setup

### Prerequisites

- Node.js 16+ (for notary stub server)
- Chrome browser with developer mode enabled
- Git (for cloning the repository)

### 1. Install Extension

```bash
# Clone the repository
git clone <repository-url>
cd GonePhishin

# Load the extension in Chrome:
# 1. Open Chrome and go to chrome://extensions/
# 2. Enable "Developer mode"
# 3. Click "Load unpacked" and select the project directory
```

### 2. Setup Notary Stub Server (for testing)

```bash
# Install dependencies
npm install

# Start the notary stub server
npm start

# Or run multiple instances for testing
node notary-stub.js &
PORT=3001 node notary-stub.js &
PORT=3002 node notary-stub.js &
```

### 3. Configure Extension Notaries

Update the notary endpoints in `background/background.js`:

```javascript
const NOTARY_ENDPOINTS = [
  'http://localhost:3000/observe',
  'http://localhost:3001/observe', 
  'http://localhost:3002/observe'
];
```

## 🧪 Testing

### Automated Test Scenarios

Run the MITM test scenarios:

```bash
# Run all test scenarios
node test-mitm-scenarios.js

# Individual test scenarios:
# - Baseline behavior (normal HTTPS sites)
# - Self-signed certificate MITM
# - CA-signed forged certificate MITM  
# - Mid-session certificate flip
# - Weak TLS protocols and ciphers
```

### Manual Testing

1. **Baseline Test**: Navigate to normal HTTPS sites (github.com, google.com) - should show green badge
2. **MITM Test**: Use mitmproxy to simulate attacks and verify detection
3. **Notary Test**: Verify notary consensus evaluation works correctly

### Test Tools Setup

```bash
# Install mitmproxy for MITM simulation
pip install mitmproxy

# Install sslsplit for advanced MITM testing
# (Platform-specific installation instructions)
```

## ⚙️ Configuration

### TLS Security Policies

Configure security policies in `background/background.js`:

```javascript
const TLS_POLICIES = {
  minVersion: 'TLSv1.2',           // Minimum TLS version
  minRsaKeySize: 2048,            // Minimum RSA key size
  forbiddenCiphers: ['RC4', '3DES'], // Forbidden cipher suites
  forbiddenSignatures: ['sha1']   // Forbidden signature algorithms
};
```

### Notary Configuration

```javascript
const NOTARY_ENDPOINTS = [
  'https://notary1.example.com/observe',
  'https://notary2.example.com/observe', 
  'https://notary3.example.com/observe'
];
```

### Consensus Rules

```javascript
// Default consensus rule: require >50% agreement
const majority = Math.floor(notaryResults.length / 2) + 1;
```

## 🔧 API Reference

### Notary API Contract

**Request**: `GET /observe?host=example.com`

**Response**:
```json
{
  "host": "example.com",
  "fingerprint_sha256": "sha256:AAAAAAAA...",
  "ts": "2025-10-23T12:34:56Z"
}
```

### Storage Schema

The extension uses `chrome.storage.local` with the following key patterns:

- `audit_*`: Audit logs for security events
- `issuerDrift_*`: Issuer drift detection events  
- `notary_*`: Cached notary responses
- `override_*`: User overrides for blocked sites
- `pin_*`: Pinned certificates for 24h

## 🛡️ Security Features

### 1. Issuer Drift Detection
- **TOFU (Trust On First Use)**: Records issuer on first visit
- **Drift Detection**: Alerts when issuer changes unexpectedly
- **Notary Verification**: Queries notaries to verify legitimacy

### 2. Session Consistency
- **Session Tracking**: Monitors certificate fingerprints per tab
- **Flip Detection**: Alerts when certificate changes mid-session
- **High Severity**: Session flips are treated as critical events

### 3. Weak TLS Detection
- **Protocol Version**: Flags TLS < 1.2 as weak
- **Cipher Suites**: Detects RC4, 3DES, and other weak ciphers
- **Key Sizes**: Validates RSA key sizes >= 2048 bits

### 4. Multi-Vantage Notary Checks
- **Parallel Queries**: Queries multiple notaries simultaneously
- **Consensus Evaluation**: Requires majority agreement
- **MITM Detection**: Flags when notaries disagree with local view

## 🎨 User Interface

### Badge Colors
- 🟢 **Green (✓)**: Secure connection, no issues
- 🟡 **Amber (⚠)**: Warning - weak TLS or mixed notary responses  
- 🔴 **Red (🚨)**: Critical - potential MITM detected

### Interstitial Page
- **Evidence Display**: Shows certificate details, notary results
- **User Actions**: Go Back, Proceed Anyway, Pin for 24h
- **Audit Logging**: Records all user decisions

### Popup Interface
- **Current Site Status**: TLS version, certificate issuer, consensus
- **Security Alerts**: Displays active warnings and critical issues
- **Notary Information**: Shows consensus results and notary responses

## 🚨 Limitations & Considerations

### Manifest V3 Constraints
- **No Synchronous Blocking**: Cannot block requests before they complete
- **Interstitial Approach**: Uses navigation to extension page for blocking
- **Enterprise Deployment**: Full blocking requires enterprise force-install

### Privacy Considerations
- **No Persistent IDs**: Notary queries don't include client identifiers
- **Local Storage Only**: All data stored locally in chrome.storage.local
- **Optional Relay**: Users can configure proxy for notary queries

### Performance Impact
- **Top-Level Only**: Only inspects main frame navigations
- **Caching**: Notary results cached for 10 minutes
- **Rate Limiting**: Limited to 1 query per origin per 30 seconds

## 🔮 Future Enhancements

### Planned Features
- **Certificate Transparency**: Integration with CT logs for additional verification
- **Settings Page**: UI for configuring notaries and security policies
- **Learn Mode**: Automatic trusted issuer learning from first N visits
- **Enterprise Features**: Enhanced blocking capabilities for enterprise deployments

### Advanced Notary Features
- **Notary Health Monitoring**: Track notary availability and response times
- **Dynamic Notary Selection**: Choose notaries based on geographic location
- **Notary Reputation**: Weight notary responses based on historical accuracy

## 📊 Monitoring & Analytics

### Audit Logging
All security events are logged locally with:
- Timestamp and hostname
- Certificate fingerprints and issuers
- Notary consensus results
- User override decisions

### Performance Metrics
- Notary query response times
- Certificate verification latency
- False positive/negative rates

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

### Testing Requirements
- All new features must include test scenarios
- MITM test coverage for security features
- Performance testing for notary queries

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the test scenarios for expected behavior
2. Review the audit logs in chrome.storage.local
3. Verify notary endpoints are accessible
4. Check browser console for error messages

---

**Note**: This feature is designed for security-conscious users and organizations. The notary system provides defense-in-depth against sophisticated MITM attacks that traditional certificate validation cannot detect.
