#!/usr/bin/env node

/**
 * Test Script for Gone Phishin' Notary System
 * 
 * This script tests the notary system with various scenarios:
 * 1. Normal operation (all notaries return same fingerprint)
 * 2. MITM simulation (notaries return different fingerprint)
 * 3. Notary unavailability (all notaries down)
 * 4. Mixed responses (some notaries agree, others don't)
 * 
 * Usage: node test-notary-system.js
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
    const response = await fetch(`${NOTARY_BASE_URL}/health`);
    const data = await response.json();
    
    if (data.status === 'healthy') {
      console.log('✅ Notary server is healthy');
      return true;
    } else {
      console.log('❌ Notary server is not healthy');
      return false;
    }
  } catch (error) {
    console.log('❌ Notary server is not available:', error.message);
    return false;
  }
}

// Test notary query
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

// Simulate extension notary querying
async function simulateExtensionNotaryQuery(hostname) {
  console.log(`🌐 Simulating extension notary query for ${hostname}...`);
  
  const notaryEndpoints = [
    `${NOTARY_BASE_URL}/observe`,
    `${NOTARY_BASE_URL}/observe?force=sha256:consensus_fingerprint`,
    `${NOTARY_BASE_URL}/observe?force=sha256:consensus_fingerprint`
  ];
  
  const results = [];
  
  for (const endpoint of notaryEndpoints) {
    try {
      const url = `${endpoint}&host=${hostname}`;
      const response = await fetch(url);
      const data = await response.json();
      
      if (response.ok && data.fingerprint_sha256) {
        results.push({
          endpoint,
          fingerprint: data.fingerprint_sha256,
          success: true
        });
        console.log(`✅ ${endpoint}: ${data.fingerprint_sha256.substring(0, 16)}...`);
      } else {
        results.push({
          endpoint,
          success: false,
          error: 'Invalid response'
        });
        console.log(`❌ ${endpoint}: Invalid response`);
      }
    } catch (error) {
      results.push({
        endpoint,
        success: false,
        error: error.message
      });
      console.log(`❌ ${endpoint}: ${error.message}`);
    }
  }
  
  const successful = results.filter(r => r.success);
  const votes = successful.map(r => r.fingerprint);
  
  return {
    total: results.length,
    successful: successful.length,
    failed: results.length - successful.length,
    votes,
    errors: results.filter(r => !r.success).map(r => r.error)
  };
}

// Simulate consensus evaluation
function simulateConsensusEvaluation(localFingerprint, notaryResults) {
  if (!notaryResults || notaryResults.successful === 0) {
    return { 
      consensus: 'no_data', 
      severity: 'medium', 
      message: 'Notary servers unreachable — unable to corroborate certificate'
    };
  }

  const votes = notaryResults.votes || [];
  const localMatches = votes.filter(fp => fp === localFingerprint).length;
  const majority = Math.floor(votes.length / 2) + 1;

  if (localMatches >= majority) {
    return { 
      consensus: 'consistent', 
      severity: 'low', 
      message: 'Notaries agree with local view'
    };
  } else if (localMatches === 0) {
    return { 
      consensus: 'mitm_detected', 
      severity: 'critical', 
      message: 'Potential MITM detected - notaries disagree'
    };
  } else {
    return { 
      consensus: 'mixed', 
      severity: 'medium', 
      message: 'Mixed notary responses'
    };
  }
}

// Run test scenarios
async function runTestScenarios() {
  console.log('🧪 Running test scenarios...\n');
  
  for (const scenario of testScenarios) {
    console.log(`📋 Test: ${scenario.name}`);
    console.log(`📝 Description: ${scenario.description}`);
    
    // Simulate local fingerprint (what the extension would see)
    const localFingerprint = 'sha256:local_fingerprint_for_testing';
    
    // Query notaries
    const notaryResults = await simulateExtensionNotaryQuery(scenario.hostname);
    
    // Evaluate consensus
    const consensus = simulateConsensusEvaluation(localFingerprint, notaryResults);
    
    // Check results
    const consensusMatch = consensus.consensus === scenario.expectedConsensus;
    const severityMatch = consensus.severity === scenario.expectedSeverity;
    
    console.log(`📊 Results:`);
    console.log(`   Total notaries: ${notaryResults.total}`);
    console.log(`   Successful: ${notaryResults.successful}`);
    console.log(`   Failed: ${notaryResults.failed}`);
    console.log(`   Votes: ${notaryResults.votes.map(v => v.substring(0, 16) + '...').join(', ')}`);
    console.log(`   Consensus: ${consensus.consensus} (${consensus.severity})`);
    console.log(`   Message: ${consensus.message}`);
    
    console.log(`✅ Consensus match: ${consensusMatch ? 'PASS' : 'FAIL'}`);
    console.log(`✅ Severity match: ${severityMatch ? 'PASS' : 'FAIL'}`);
    console.log(`✅ Overall: ${consensusMatch && severityMatch ? 'PASS' : 'FAIL'}\n`);
  }
}

// Test notary unavailability
async function testNotaryUnavailability() {
  console.log('🔍 Testing notary unavailability scenario...');
  
  // Simulate all notaries being down
  const notaryResults = {
    total: 3,
    successful: 0,
    failed: 3,
    votes: [],
    errors: ['Network error (CORS/connectivity)', 'Timeout after 3000ms', 'Failed to fetch']
  };
  
  const localFingerprint = 'sha256:local_fingerprint_for_testing';
  const consensus = simulateConsensusEvaluation(localFingerprint, notaryResults);
  
  console.log(`📊 Results:`);
  console.log(`   Consensus: ${consensus.consensus} (${consensus.severity})`);
  console.log(`   Message: ${consensus.message}`);
  console.log(`✅ Expected no_data: ${consensus.consensus === 'no_data' ? 'PASS' : 'FAIL'}`);
  console.log(`✅ Expected medium severity: ${consensus.severity === 'medium' ? 'PASS' : 'FAIL'}\n`);
}

// Main test function
async function runTests() {
  console.log('🚀 Starting Gone Phishin\' Notary System Tests\n');
  
  // Test notary availability
  const notaryAvailable = await testNotaryAvailability();
  if (!notaryAvailable) {
    console.log('❌ Notary server is not available. Please start it with: node notary-stub-dev.js');
    process.exit(1);
  }
  
  // Test basic notary query
  const basicQuery = await testNotaryQuery('github.com');
  if (!basicQuery) {
    console.log('❌ Basic notary query failed');
    process.exit(1);
  }
  
  // Run test scenarios
  await runTestScenarios();
  
  // Test notary unavailability
  await testNotaryUnavailability();
  
  console.log('🎉 All tests completed!');
  console.log('\n📋 Manual Testing Instructions:');
  console.log('1. Start the notary server: node notary-stub-dev.js');
  console.log('2. Reload the Chrome extension');
  console.log('3. Navigate to https://github.com');
  console.log('4. Click the extension icon and "Test TLS Check"');
  console.log('5. Check console logs for notary query results');
  console.log('6. Verify popup shows notary consensus status');
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = {
  testNotaryAvailability,
  testNotaryQuery,
  simulateExtensionNotaryQuery,
  simulateConsensusEvaluation,
  runTestScenarios,
  testNotaryUnavailability
};
