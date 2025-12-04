# Firefox Build Guide

This extension supports both **Chrome (MV3)** and **Firefox (MV2)** versions. The Firefox version includes advanced certificate analysis capabilities that are not available in Chrome MV3.

## Differences Between Versions

### Chrome MV3
- Uses Manifest V3 (service worker)
- Limited certificate access (only HTTPS protocol check)
- Uses `declarativeNetRequest` for HTTPS upgrades
- Uses `chrome.action` API

### Firefox MV2
- Uses Manifest V2 (background page)
- **Full certificate analysis** via `browser.webRequest.onHeadersReceived`
- Uses `webRequestBlocking` for HTTPS upgrades
- Uses `browser.browserAction` API
- Certificate features:
  - Certificate fingerprint tracking
  - Issuer drift detection
  - Certificate expiration monitoring
  - Session certificate consistency checks
  - TLS version and cipher suite analysis

## Building for Firefox

### Option 1: Using the Build Script (Recommended)

```bash
node build.js
```

This will create:
- `build/chrome/` - Chrome MV3 version
- `build/firefox/` - Firefox MV2 version

### Option 2: Manual Build

1. **Copy shared files** to a new directory:
   - `popup/`
   - `heuristics/`
   - `content-script.js`
   - `content-script-bridge.js`
   - `icons/`
   - `rules/`
   - `warning.html`, `warning.css`, `warning.js`
   - `interstitial.html`, `interstitial.css`, `interstitial.js`
   - `login/`

2. **Copy Firefox-specific files**:
   - Copy `manifest-firefox.json` and rename to `manifest.json`
   - Copy `background/firefox-certificate.js`
   - Copy `background/background-firefox.js`

3. **Ensure script order** in `manifest.json`:
   ```json
   "background": {
     "scripts": [
       "background/firefox-certificate.js",
       "background/background-firefox.js"
     ],
     "persistent": true
   }
   ```

## Installing Firefox Version

1. Open Firefox
2. Navigate to `about:debugging`
3. Click "This Firefox"
4. Click "Load Temporary Add-on..."
5. Select the `manifest.json` file from `build/firefox/`

## Testing Certificate Features

The Firefox version provides advanced certificate analysis. To test:

1. Visit an HTTPS website
2. Open the extension popup
3. Check the "Connection Security" section
4. Certificate details will be displayed if issues are detected:
   - Expired certificates
   - Certificates expiring soon
   - Issuer changes (potential MITM)
   - Session certificate flips (potential MITM attack)
   - Weak TLS versions

## File Structure

```
GonePhishin/
├── manifest.json              # Chrome MV3 manifest
├── manifest-firefox.json      # Firefox MV2 manifest
├── background/
│   ├── background.js         # Chrome background (service worker)
│   ├── background-firefox.js # Firefox background (MV2)
│   ├── firefox-certificate.js # Firefox certificate analysis
│   └── scoring-system.js     # Shared scoring (Chrome only, inline in Firefox)
├── build.js                   # Build script
└── ... (shared files)
```

## Notes

- The Firefox version uses `browser.*` APIs (though `chrome.*` also works for compatibility)
- Certificate analysis is **Firefox-only** due to MV2's `securityInfo` access
- Both versions share the same UI, heuristics engine, and URLScan integration
- The unified scoring system works identically in both versions

## Troubleshooting

### Certificate analysis not working
- Ensure `firefox-certificate.js` is loaded before `background-firefox.js`
- Check browser console for errors
- Verify `webRequest` and `webRequestBlocking` permissions in manifest

### HTTPS upgrades not working
- Firefox MV2 supports `webRequestBlocking` - ensure it's in permissions
- Check that localhost domains are excluded (for testing)

### Build script errors
- Ensure Node.js is installed
- Check file paths are correct
- Verify all required files exist

