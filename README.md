# Gone Phishin' - Chrome Extension

A Chrome extension for phishing protection and detection.

## Installation

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right
4. Click "Load unpacked" and select this directory
5. The extension should now appear in your Chrome toolbar

## Current Features

- Basic popup interface
- Extension framework ready for phishing detection features
- Modern, responsive UI design

## Planned Features

- Real-time phishing detection
- URL analysis and validation
- Warning system for suspicious websites
- Settings and preferences panel
- Scan current page functionality

## File Structure

```
GonePhishin/
├── manifest.json          # Extension configuration
├── popup.html            # Main popup interface
├── popup.css             # Styling for popup
├── popup.js              # Popup functionality
├── icons/                # Extension icons
│   └── README.md         # Icon requirements
└── README.md             # This file
```

## Development

This is the base structure for the Chrome extension. Future development will add:

- Content scripts for page analysis
- Background scripts for monitoring
- Phishing detection algorithms
- User settings and preferences
- Notification system

## Version

1.0.0 - Initial setup and base structure
