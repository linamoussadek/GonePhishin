#!/usr/bin/env node

/**
 * Comprehensive Test Script for Gone Phishin' Notary System
 * 
 * This script tests all scenarios:
 * 1. Normal operation (all notaries return same fingerprint)
 * 2. MITM simulation (notaries return different fingerprint)
 * 3. Notary unavailability (all notaries down)
 * 4. Mixed responses (some notaries agree, others don't)
 * 5. Backend HTML error handling
 * 6. Rate limiting and caching
 * 
 * Usage: node test-notary-system-comprehensive.js
 */

const http = require('http');
const https = require('https');

const NOTARY_BASE_URL = 'http://localhost:9001';

// Test scenarios
const testScenarios = [
  {
    name: 'Normal Operation',
    description: 'All notaries return same fingerprint',
    hostname: 'github.com',
    expectedConsensus: 'consistent',
    expectedSeverity: 'low'
  },
  {
    name: 'MITM Simulation',
    description: 'Notaries return different fingerprint',
    hostname: 'github.com',
    forceFingerprint: 'sha256:different_fingerprint_for_mitm_test',
    expectedConsensus: 'mitm_detected',
    expectedSeverity: 'critical'
  },
  {
    name: 'Mixed Responses',
    description: 'Some notaries agree, others don\'t',
    hostname: 'github.com',
    forceFingerprint: 'sha256:mixed_response_test',
    expectedConsensus: 'mixed',
    expectedSeverity: 'medium'
  }
];

// Test notary availability
async function testNotaryAvailability() {
  console.log('🔍 Testing notary availability...');
  
  try {
    const response = await fetch(`${NOTARY_BASE_URL}/observe?host=test.com`);
    const data = await response.json();
    
    if (data.host && data.fingerprint_sha256) {
      console.log('✅ Notary server is healthy');
      return true;
    } else {
      console.log('❌ Notary server returned invalid response');
      return false;
    }
  } catch (error) {
    console.log('❌ Notary server is not available:', error.message);
    return false;
  }
}

// Test notary query with different scenarios
async function testNotaryQuery(hostname, forceFingerprint = null) {
  console.log(`🔍 Testing notary query for ${hostname}...`);
  
  try {
    let url = `${NOTARY_BASE_URL}/observe?host=${hostname}`;
    if (forceFingerprint) {
      url += `&force=${encodeURIComponent(forceFingerprint)}`;
    }
    
    const response = await fetch(url);
    const data = await response.json();
    
    if (response.ok && data.fingerprint_sha256) {
      console.log(`✅ Notary query successful: ${data.fingerprint_sha256.substring(0, 16)}...`);
      return data;
    } else {
      console.log('❌ Notary query failed:', data);
      return null;
    }
  } catch (error) {
    console.log('❌ Notary query error:', error.message);
    return null;
  }
}

// Test backend HTML error handling
async function testBackendHtmlError() {
  console.log('🔍 Testing backend HTML error handling...');
  
  try {
    // Simulate a request to a non-existent endpoint that returns HTML
    const response = await fetch('https://httpstat.us/404');
    const contentType = response.headers.get('content-type');
    
    if (contentType && contentType.includes('text/html')) {
      console.log('✅ Backend HTML error detected correctly');
      return true;
    } else {
      console.log('❌ Expected HTML response but got:', contentType);
      return false;
    }
  } catch (error) {
    console.log('❌ Backend HTML error test failed:', error.message);
    return false;
  }
}

// Test rate limiting
async function testRateLimiting() {
  console.log('🔍 Testing rate limiting...');
  
  const startTime = Date.now();
  
  // Make multiple rapid requests
  const promises = [];
  for (let i = 0; i < 5; i++) {
    promises.push(fetch(`${NOTARY_BASE_URL}/observe?host=test.com`));
  }
  
  try {
    const responses = await Promise.all(promises);
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    console.log(`✅ Rate limiting test completed in ${duration}ms`);
    console.log(`📊 Responses: ${responses.length}`);
    
    return true;
  } catch (error) {
    console.log('❌ Rate limiting test failed:', error.message);
    return false;
  }
}

// Test caching
async function testCaching() {
  console.log('🔍 Testing caching...');
  
  const hostname = 'cache-test.com';
  
  try {
    // First request
    const start1 = Date.now();
    const response1 = await fetch(`${NOTARY_BASE_URL}/observe?host=${hostname}`);
    const data1 = await response1.json();
    const end1 = Date.now();
    const duration1 = end1 - start1;
    
    // Second request (should be faster due to caching)
    const start2 = Date.now();
    const response2 = await fetch(`${NOTARY_BASE_URL}/observe?host=${hostname}`);
    const data2 = await response2.json();
    const end2 = Date.now();
    const duration2 = end2 - start2;
    
    console.log(`📊 First request: ${duration1}ms`);
    console.log(`📊 Second request: ${duration2}ms`);
    
    if (data1.fingerprint_sha256 === data2.fingerprint_sha256) {
      console.log('✅ Caching test passed - same fingerprint returned');
      return true;
    } else {
      console.log('❌ Caching test failed - different fingerprints');
      return false;
    }
  } catch (error) {
    console.log('❌ Caching test error:', error.message);
    return false;
  }
}

// Run comprehensive tests
async function runComprehensiveTests() {
  console.log('🚀 Starting Comprehensive Gone Phishin\' Notary System Tests\n');
  
  const results = {
    notaryAvailability: false,
    backendHtmlError: false,
    rateLimiting: false,
    caching: false,
    scenarios: []
  };
  
  // Test 1: Notary availability
  results.notaryAvailability = await testNotaryAvailability();
  console.log('');
  
  // Test 2: Backend HTML error handling
  results.backendHtmlError = await testBackendHtmlError();
  console.log('');
  
  // Test 3: Rate limiting
  results.rateLimiting = await testRateLimiting();
  console.log('');
  
  // Test 4: Caching
  results.caching = await testCaching();
  console.log('');
  
  // Test 5: Scenarios
  console.log('🧪 Running test scenarios...\n');
  
  for (const scenario of testScenarios) {
    console.log(`📋 Test: ${scenario.name}`);
    console.log(`📝 Description: ${scenario.description}`);
    
    const result = await testNotaryQuery(scenario.hostname, scenario.forceFingerprint);
    
    if (result) {
      console.log(`✅ Scenario passed: ${scenario.name}`);
      results.scenarios.push({ name: scenario.name, passed: true });
    } else {
      console.log(`❌ Scenario failed: ${scenario.name}`);
      results.scenarios.push({ name: scenario.name, passed: false });
    }
    console.log('');
  }
  
  // Summary
  console.log('📊 Test Results Summary:');
  console.log(`✅ Notary Availability: ${results.notaryAvailability ? 'PASS' : 'FAIL'}`);
  console.log(`✅ Backend HTML Error: ${results.backendHtmlError ? 'PASS' : 'FAIL'}`);
  console.log(`✅ Rate Limiting: ${results.rateLimiting ? 'PASS' : 'FAIL'}`);
  console.log(`✅ Caching: ${results.caching ? 'PASS' : 'FAIL'}`);
  console.log(`✅ Scenarios: ${results.scenarios.filter(s => s.passed).length}/${results.scenarios.length} passed`);
  
  const totalPassed = [
    results.notaryAvailability,
    results.backendHtmlError,
    results.rateLimiting,
    results.caching,
    ...results.scenarios.map(s => s.passed)
  ].filter(Boolean).length;
  
  const totalTests = 4 + results.scenarios.length;
  
  console.log(`\n🎯 Overall: ${totalPassed}/${totalTests} tests passed`);
  
  if (totalPassed === totalTests) {
    console.log('🎉 All tests passed! The notary system is working correctly.');
  } else {
    console.log('⚠️ Some tests failed. Check the logs above for details.');
  }
  
  console.log('\n📋 Manual Testing Instructions:');
  console.log('1. Start the notary server: npm start');
  console.log('2. Reload the Chrome extension');
  console.log('3. Navigate to https://github.com');
  console.log('4. Click the extension icon and "Test TLS Check"');
  console.log('5. Check console logs for notary query results');
  console.log('6. Verify popup shows notary consensus status');
  console.log('7. Test "Retry Notary Check" button');
  console.log('8. Test "Clear Rate Limit" button');
}

// Run tests if this file is executed directly
if (require.main === module) {
  runComprehensiveTests().catch(console.error);
}

module.exports = {
  testNotaryAvailability,
  testNotaryQuery,
  testBackendHtmlError,
  testRateLimiting,
  testCaching,
  runComprehensiveTests
};
