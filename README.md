# Gone Phishin' - Browser Extension

A browser extension for phishing protection and security analysis, available for both **Chrome (MV3)** and **Firefox (MV2)**.

## Features

### Chrome Version
- **HTTPS Enforcement**: Automatically upgrades HTTP to HTTPS connections
- **Heuristic Analysis**: Pattern-based content analysis to detect phishing attempts
- **URLScan.io Integration**: Real-time URL scanning for malicious content
- **Real-time Monitoring**: Active tab monitoring with anomaly scoring
- **Whitelist Management**: User-controlled site whitelisting

### Firefox Version
- **Certificate Analysis**: Advanced TLS certificate inspection and anomaly scoring
- **Certificate History**: Tracks certificate changes for MITM detection
- **Security Scoring**: 0-100 anomaly score with confidence levels
- **Certificate Details**: Full certificate information display (subject, issuer, expiration, TLS version, cipher suite)

## Quick Start

### Chrome Installation

1. **Build the extension:**
   ```bash
   node build.js
   ```

2. **Load in Chrome:**
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select `build/chrome/` folder

### Firefox Installation

1. **Build the extension:**
   ```bash
   node build.js
   ```

2. **Load in Firefox:**
   - Open `about:debugging`
   - Click "This Firefox"
   - Click "Load Temporary Add-on"
   - Select `build/firefox/manifest.json`

## Project Structure

```
GonePhishin/
├── background/              # Background scripts
│   ├── background.js       # Chrome service worker
│   ├── background-firefox.js  # Firefox background script
│   ├── firefox-certificate.js # Firefox certificate analysis
│   └── scoring-system.js   # Unified scoring system
├── popup/                  # Extension popup UI
│   ├── popup.html/js/css   # Chrome popup
│   └── popup-firefox.*     # Firefox popup
├── heuristics/             # Heuristic analysis engine
├── manifest.json           # Chrome MV3 manifest
├── manifest-firefox.json   # Firefox MV2 manifest
├── build.js                # Build script for packaging
└── FIREFOX_BUILD.md        # Firefox build documentation
```

## Development

### Building

```bash
node build.js
```

This creates:
- `build/chrome/` - Chrome MV3 version
- `build/firefox/` - Firefox MV2 version

### Testing

See `TESTING_GUIDE.md` for testing instructions with the phishing test site.

## Backend (Optional)

The extension integrates with a backend for URLScan.io scanning. See `backend/` directory for setup.

## Documentation

- **FIREFOX_BUILD.md** - Firefox-specific build and feature documentation
- **TESTING_GUIDE.md** - Testing instructions and test site setup

## License

MIT
