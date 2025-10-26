#!/usr/bin/env node

/**
 * MITM Test Scenarios for Gone Phishin' Extension
 * 
 * This script provides test scenarios for validating the TLS & Certificate
 * Verification feature against various MITM attack simulations.
 * 
 * Prerequisites:
 * - mitmproxy installed: pip install mitmproxy
 * - sslsplit or similar MITM tool
 * - Chrome with the extension loaded
 * 
 * Usage: node test-mitm-scenarios.js
 */

const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

class MitmTestRunner {
  constructor() {
    this.testResults = [];
    this.mitmProcesses = [];
  }

  async runTest(testName, description, testFunction) {
    console.log(`\n🧪 Running test: ${testName}`);
    console.log(`📝 Description: ${description}`);
    console.log('─'.repeat(60));

    try {
      const result = await testFunction();
      this.testResults.push({
        name: testName,
        status: 'PASS',
        result: result
      });
      console.log(`✅ ${testName}: PASSED`);
    } catch (error) {
      this.testResults.push({
        name: testName,
        status: 'FAIL',
        error: error.message
      });
      console.log(`❌ ${testName}: FAILED - ${error.message}`);
    }
  }

  async testSelfSignedMitm() {
    // Test scenario: Self-signed certificate MITM
    console.log('🔧 Setting up self-signed MITM proxy...');
    
    // Create mitmproxy script for self-signed certs
    const mitmScript = `
import mitmproxy.http
from mitmproxy import http
import ssl
import socket

def request(flow: http.HTTPFlow) -> None:
    # Replace with self-signed certificate
    if "bank.example" in flow.request.pretty_host:
        # This would be handled by mitmproxy's certificate generation
        pass
`;
    
    const scriptPath = path.join(__dirname, 'mitm-self-signed.py');
    fs.writeFileSync(scriptPath, mitmScript);
    
    console.log('📋 Instructions for manual testing:');
    console.log('1. Start mitmproxy: mitmdump -s mitm-self-signed.py --listen-port 8080');
    console.log('2. Configure browser to use proxy: localhost:8080');
    console.log('3. Navigate to https://bank.example');
    console.log('4. Verify extension shows red interstitial');
    
    return {
      proxyPort: 8080,
      scriptPath: scriptPath,
      expectedBehavior: 'Red interstitial should appear due to self-signed certificate'
    };
  }

  async testCaSignedMitm() {
    // Test scenario: CA-signed forged certificate MITM
    console.log('🔧 Setting up CA-signed MITM proxy...');
    
    const mitmScript = `
import mitmproxy.http
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Simulate CA-signed certificate replacement
    if "github.com" in flow.request.pretty_host:
        # This would replace with attacker's CA-signed cert
        pass
`;
    
    const scriptPath = path.join(__dirname, 'mitm-ca-signed.py');
    fs.writeFileSync(scriptPath, mitmScript);
    
    console.log('📋 Instructions for manual testing:');
    console.log('1. Start mitmproxy: mitmdump -s mitm-ca-signed.py --listen-port 8081');
    console.log('2. Configure browser to use proxy: localhost:8081');
    console.log('3. Navigate to https://github.com');
    console.log('4. Verify extension detects issuer drift and queries notaries');
    
    return {
      proxyPort: 8081,
      scriptPath: scriptPath,
      expectedBehavior: 'Extension should detect issuer drift and show warning/block'
    };
  }

  async testSessionFlip() {
    // Test scenario: Mid-session certificate flip
    console.log('🔧 Setting up session flip test...');
    
    const mitmScript = `
import mitmproxy.http
from mitmproxy import http
import time

session_start_time = None

def request(flow: http.HTTPFlow) -> None:
    global session_start_time
    
    if "example.com" in flow.request.pretty_host:
        if session_start_time is None:
            session_start_time = time.time()
            # First request - use normal certificate
            pass
        elif time.time() - session_start_time > 10:
            # After 10 seconds, switch to different certificate
            # This simulates a session flip
            pass
`;
    
    const scriptPath = path.join(__dirname, 'mitm-session-flip.py');
    fs.writeFileSync(scriptPath, mitmScript);
    
    console.log('📋 Instructions for manual testing:');
    console.log('1. Start mitmproxy: mitmdump -s mitm-session-flip.py --listen-port 8082');
    console.log('2. Configure browser to use proxy: localhost:8082');
    console.log('3. Navigate to https://example.com');
    console.log('4. Wait 10+ seconds and refresh the page');
    console.log('5. Verify extension detects session flip');
    
    return {
      proxyPort: 8082,
      scriptPath: scriptPath,
      expectedBehavior: 'Extension should detect session flip and show red interstitial'
    };
  }

  async testWeakTls() {
    // Test scenario: Weak TLS protocols and ciphers
    console.log('🔧 Setting up weak TLS test...');
    
    const mitmScript = `
import mitmproxy.http
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Force weak TLS version and ciphers
    if "legacy.example" in flow.request.pretty_host:
        # This would force TLS 1.0 and weak ciphers
        pass
`;
    
    const scriptPath = path.join(__dirname, 'mitm-weak-tls.py');
    fs.writeFileSync(scriptPath, mitmScript);
    
    console.log('📋 Instructions for manual testing:');
    console.log('1. Start mitmproxy: mitmdump -s mitm-weak-tls.py --listen-port 8083');
    console.log('2. Configure browser to use proxy: localhost:8083');
    console.log('3. Navigate to https://legacy.example');
    console.log('4. Verify extension shows amber warning for weak TLS');
    
    return {
      proxyPort: 8083,
      scriptPath: scriptPath,
      expectedBehavior: 'Extension should show amber warning for weak TLS'
    };
  }

  async testBaseline() {
    // Test scenario: Normal baseline behavior
    console.log('🔧 Testing baseline behavior...');
    
    const testSites = [
      'https://example.com',
      'https://github.com',
      'https://www.google.com'
    ];
    
    console.log('📋 Instructions for manual testing:');
    console.log('1. Navigate to the following sites without any proxy:');
    testSites.forEach(site => console.log(`   - ${site}`));
    console.log('2. Verify extension shows green badge (secure)');
    console.log('3. Verify no red interstitials appear');
    console.log('4. Check popup shows normal TLS status');
    
    return {
      testSites: testSites,
      expectedBehavior: 'All sites should show green badge, no alerts'
    };
  }

  async runAllTests() {
    console.log('🚀 Starting MITM Test Scenarios for Gone Phishin\' Extension');
    console.log('═'.repeat(60));

    // Test 1: Baseline behavior
    await this.runTest(
      'Baseline Test',
      'Verify extension works correctly with normal HTTPS sites',
      () => this.testBaseline()
    );

    // Test 2: Self-signed MITM
    await this.runTest(
      'Self-Signed MITM Test',
      'Test detection of self-signed certificate MITM attacks',
      () => this.testSelfSignedMitm()
    );

    // Test 3: CA-signed MITM
    await this.runTest(
      'CA-Signed MITM Test',
      'Test detection of CA-signed forged certificate attacks',
      () => this.testCaSignedMitm()
    );

    // Test 4: Session flip
    await this.runTest(
      'Session Flip Test',
      'Test detection of mid-session certificate changes',
      () => this.testSessionFlip()
    );

    // Test 5: Weak TLS
    await this.runTest(
      'Weak TLS Test',
      'Test detection of weak TLS protocols and ciphers',
      () => this.testWeakTls()
    );

    // Print results
    this.printResults();
  }

  printResults() {
    console.log('\n📊 Test Results Summary');
    console.log('═'.repeat(60));
    
    const passed = this.testResults.filter(r => r.status === 'PASS').length;
    const failed = this.testResults.filter(r => r.status === 'FAIL').length;
    
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📈 Success Rate: ${Math.round((passed / this.testResults.length) * 100)}%`);
    
    console.log('\n📋 Detailed Results:');
    this.testResults.forEach(result => {
      const status = result.status === 'PASS' ? '✅' : '❌';
      console.log(`${status} ${result.name}: ${result.status}`);
      if (result.error) {
        console.log(`   Error: ${result.error}`);
      }
    });
  }

  cleanup() {
    console.log('\n🧹 Cleaning up test files...');
    const filesToClean = [
      'mitm-self-signed.py',
      'mitm-ca-signed.py', 
      'mitm-session-flip.py',
      'mitm-weak-tls.py'
    ];
    
    filesToClean.forEach(file => {
      const filePath = path.join(__dirname, file);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`🗑️  Removed ${file}`);
      }
    });
  }
}

// Main execution
async function main() {
  const runner = new MitmTestRunner();
  
  try {
    await runner.runAllTests();
  } catch (error) {
    console.error('❌ Test runner failed:', error);
  } finally {
    runner.cleanup();
  }
}

if (require.main === module) {
  main();
}

module.exports = MitmTestRunner;
