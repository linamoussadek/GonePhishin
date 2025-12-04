// ============================================
// Build Script for Chrome and Firefox Versions
// ============================================
// 
// This script packages the extension for both Chrome (MV3) and Firefox (MV2)
// by copying the appropriate manifest and background scripts.

const fs = require('fs');
const path = require('path');

const BUILD_DIR = path.join(__dirname, 'build');
const CHROME_DIR = path.join(BUILD_DIR, 'chrome');
const FIREFOX_DIR = path.join(BUILD_DIR, 'firefox');

// Files to copy to both builds
const SHARED_FILES = [
  'popup',
  'heuristics',
  'content-script.js',
  'content-script-bridge.js',
  'icons',
  'rules',
  'warning.html',
  'warning.css',
  'warning.js',
  'interstitial.html',
  'interstitial.css',
  'interstitial.js',
  'login'
];

// Additional files for Firefox (certificate-focused popup)
const FIREFOX_ADDITIONAL_FILES = [
  'popup/popup-firefox.html',
  'popup/popup-firefox.js'
];

// Files specific to Chrome
const CHROME_FILES = [
  'manifest.json',
  'background/background.js',
  'background/scoring-system.js'
];

// Files specific to Firefox
const FIREFOX_FILES = [
  'manifest-firefox.json',
  'background/background-firefox.js',
  'background/firefox-certificate.js'
];

function copyRecursive(src, dest) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    if (!fs.existsSync(dest)) {
      fs.mkdirSync(dest, { recursive: true });
    }
    const entries = fs.readdirSync(src);
    for (const entry of entries) {
      const srcPath = path.join(src, entry);
      const destPath = path.join(dest, entry);
      copyRecursive(srcPath, destPath);
    }
  } else {
    fs.copyFileSync(src, dest);
  }
}

function copyFile(src, dest) {
  const destDir = path.dirname(dest);
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }
  fs.copyFileSync(src, dest);
}

function cleanBuildDir() {
  if (fs.existsSync(BUILD_DIR)) {
    fs.rmSync(BUILD_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(BUILD_DIR, { recursive: true });
}

function buildChrome() {
  console.log('📦 Building Chrome version...');
  
  // Copy shared files
  for (const file of SHARED_FILES) {
    const src = path.join(__dirname, file);
    const dest = path.join(CHROME_DIR, file);
    if (fs.existsSync(src)) {
      copyRecursive(src, dest);
      console.log(`  ✓ Copied ${file}`);
    }
  }
  
  // Copy Chrome-specific files
  copyFile(
    path.join(__dirname, 'manifest.json'),
    path.join(CHROME_DIR, 'manifest.json')
  );
  
  // Copy background scripts
  const chromeBgDir = path.join(CHROME_DIR, 'background');
  fs.mkdirSync(chromeBgDir, { recursive: true });
  copyFile(
    path.join(__dirname, 'background/background.js'),
    path.join(chromeBgDir, 'background.js')
  );
  
  // Copy scoring system (if exists as separate file)
  if (fs.existsSync(path.join(__dirname, 'background/scoring-system.js'))) {
    copyFile(
      path.join(__dirname, 'background/scoring-system.js'),
      path.join(chromeBgDir, 'scoring-system.js')
    );
  }
  
  console.log('✅ Chrome build complete!');
  console.log(`   Location: ${CHROME_DIR}`);
}

function buildFirefox() {
  console.log('🦊 Building Firefox version...');
  
  // Copy shared files
  for (const file of SHARED_FILES) {
    const src = path.join(__dirname, file);
    const dest = path.join(FIREFOX_DIR, file);
    if (fs.existsSync(src)) {
      copyRecursive(src, dest);
      console.log(`  ✓ Copied ${file}`);
    }
  }
  
  // Copy Firefox manifest (rename to manifest.json)
  copyFile(
    path.join(__dirname, 'manifest-firefox.json'),
    path.join(FIREFOX_DIR, 'manifest.json')
  );
  
  // Copy Firefox-specific popup files
  const firefoxPopupDir = path.join(FIREFOX_DIR, 'popup');
  if (!fs.existsSync(firefoxPopupDir)) {
    fs.mkdirSync(firefoxPopupDir, { recursive: true });
  }
  copyFile(
    path.join(__dirname, 'popup/popup-firefox.html'),
    path.join(firefoxPopupDir, 'popup-firefox.html')
  );
  copyFile(
    path.join(__dirname, 'popup/popup-firefox.js'),
    path.join(firefoxPopupDir, 'popup-firefox.js')
  );
  console.log('  ✓ Copied Firefox-specific popup files');
  
  // Copy Firefox background scripts
  const firefoxBgDir = path.join(FIREFOX_DIR, 'background');
  fs.mkdirSync(firefoxBgDir, { recursive: true });
  copyFile(
    path.join(__dirname, 'background/firefox-certificate.js'),
    path.join(firefoxBgDir, 'firefox-certificate.js')
  );
  copyFile(
    path.join(__dirname, 'background/background-firefox.js'),
    path.join(firefoxBgDir, 'background-firefox.js')
  );
  
  console.log('✅ Firefox build complete!');
  console.log(`   Location: ${FIREFOX_DIR}`);
}

function build() {
  console.log('🚀 Starting build process...\n');
  
  cleanBuildDir();
  buildChrome();
  console.log('');
  buildFirefox();
  
  console.log('\n✨ Build complete!');
  console.log('\nNext steps:');
  console.log('  Chrome: Load unpacked extension from build/chrome/');
  console.log('  Firefox: Load temporary extension from build/firefox/');
}

// Run build
build();

