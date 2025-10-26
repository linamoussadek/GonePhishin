// test-complete-system.js
// Comprehensive test script to validate the complete TLS & Notary system

const https = require('https');
const http = require('http');

console.log('🧪 Testing Complete TLS & Notary System');
console.log('=====================================\n');

// Test 1: Notary Server Availability
async function testNotaryServer() {
  console.log('1️⃣ Testing Notary Server Availability...');
  
  try {
    const response = await fetch('http://localhost:9001/observe?host=github.com');
    if (response.ok) {
      const data = await response.json();
      console.log('✅ Notary server is running');
      console.log('📋 Response:', data);
      return true;
    } else {
      console.log('❌ Notary server returned error:', response.status);
      return false;
    }
  } catch (error) {
    console.log('❌ Notary server is not accessible:', error.message);
    return false;
  }
}

// Test 2: CORS Headers
async function testCORSHeaders() {
  console.log('\n2️⃣ Testing CORS Headers...');
  
  try {
    const response = await fetch('http://localhost:9001/observe?host=github.com', {
      method: 'OPTIONS',
      headers: {
        'Origin': 'chrome-extension://test-extension-id',
        'Access-Control-Request-Method': 'GET'
      }
    });
    
    const corsOrigin = response.headers.get('Access-Control-Allow-Origin');
    const corsMethods = response.headers.get('Access-Control-Allow-Methods');
    
    console.log('📋 CORS Headers:');
    console.log('  - Access-Control-Allow-Origin:', corsOrigin);
    console.log('  - Access-Control-Allow-Methods:', corsMethods);
    
    if (corsOrigin && corsMethods) {
      console.log('✅ CORS headers are properly set');
      return true;
    } else {
      console.log('❌ CORS headers are missing or incomplete');
      return false;
    }
  } catch (error) {
    console.log('❌ CORS test failed:', error.message);
    return false;
  }
}

// Test 3: Multiple Notary Endpoints
async function testMultipleEndpoints() {
  console.log('\n3️⃣ Testing Multiple Notary Endpoints...');
  
  const endpoints = [
    'http://localhost:9001/observe',
    'http://127.0.0.1:9001/observe',
    'http://localhost:9001/observe?force=sha256:test_fingerprint'
  ];
  
  const results = [];
  
  for (const endpoint of endpoints) {
    try {
      const url = `${endpoint}&host=github.com`;
      const response = await fetch(url);
      
      if (response.ok) {
        const data = await response.json();
        console.log(`✅ ${endpoint}: ${data.fingerprint_sha256}`);
        results.push({ endpoint, success: true, fingerprint: data.fingerprint_sha256 });
      } else {
        console.log(`❌ ${endpoint}: HTTP ${response.status}`);
        results.push({ endpoint, success: false, error: `HTTP ${response.status}` });
      }
    } catch (error) {
      console.log(`❌ ${endpoint}: ${error.message}`);
      results.push({ endpoint, success: false, error: error.message });
    }
  }
  
  const successful = results.filter(r => r.success).length;
  console.log(`📊 Results: ${successful}/${results.length} endpoints successful`);
  
  return results;
}

// Test 4: Error Handling
async function testErrorHandling() {
  console.log('\n4️⃣ Testing Error Handling...');
  
  // Test invalid host
  try {
    const response = await fetch('http://localhost:9001/observe?host=invalid-domain-that-does-not-exist.com');
    const data = await response.json();
    
    if (data.error) {
      console.log('✅ Error handling works for invalid domain');
      console.log('📋 Error response:', data);
      return true;
    } else {
      console.log('❌ Expected error response for invalid domain');
      return false;
    }
  } catch (error) {
    console.log('❌ Error handling test failed:', error.message);
    return false;
  }
}

// Test 5: Forced Fingerprint (MITM Simulation)
async function testForcedFingerprint() {
  console.log('\n5️⃣ Testing Forced Fingerprint (MITM Simulation)...');
  
  try {
    const response = await fetch('http://localhost:9001/observe?host=github.com&force=sha256:different_fingerprint_for_mitm_test');
    
    if (response.ok) {
      const data = await response.json();
      console.log('✅ Forced fingerprint works');
      console.log('📋 Response:', data);
      
      if (data.fingerprint_sha256 === 'sha256:different_fingerprint_for_mitm_test') {
        console.log('✅ MITM simulation successful');
        return true;
      } else {
        console.log('❌ Forced fingerprint not applied correctly');
        return false;
      }
    } else {
      console.log('❌ Forced fingerprint test failed:', response.status);
      return false;
    }
  } catch (error) {
    console.log('❌ Forced fingerprint test error:', error.message);
    return false;
  }
}

// Test 6: Content-Type Validation
async function testContentTypeValidation() {
  console.log('\n6️⃣ Testing Content-Type Validation...');
  
  try {
    const response = await fetch('http://localhost:9001/observe?host=github.com');
    const contentType = response.headers.get('content-type');
    
    console.log('📋 Content-Type:', contentType);
    
    if (contentType && contentType.includes('application/json')) {
      console.log('✅ Content-Type is correctly set to application/json');
      return true;
    } else {
      console.log('❌ Content-Type is not application/json');
      return false;
    }
  } catch (error) {
    console.log('❌ Content-Type test failed:', error.message);
    return false;
  }
}

// Main test runner
async function runAllTests() {
  console.log('🚀 Starting comprehensive system tests...\n');
  
  const tests = [
    { name: 'Notary Server', fn: testNotaryServer },
    { name: 'CORS Headers', fn: testCORSHeaders },
    { name: 'Multiple Endpoints', fn: testMultipleEndpoints },
    { name: 'Error Handling', fn: testErrorHandling },
    { name: 'Forced Fingerprint', fn: testForcedFingerprint },
    { name: 'Content-Type Validation', fn: testContentTypeValidation }
  ];
  
  const results = [];
  
  for (const test of tests) {
    try {
      const result = await test.fn();
      results.push({ name: test.name, success: result });
    } catch (error) {
      console.log(`❌ ${test.name} test crashed:`, error.message);
      results.push({ name: test.name, success: false, error: error.message });
    }
  }
  
  // Summary
  console.log('\n📊 Test Summary');
  console.log('===============');
  
  const successful = results.filter(r => r.success).length;
  const total = results.length;
  
  results.forEach(result => {
    const status = result.success ? '✅' : '❌';
    console.log(`${status} ${result.name}`);
    if (result.error) {
      console.log(`   Error: ${result.error}`);
    }
  });
  
  console.log(`\n🎯 Overall: ${successful}/${total} tests passed`);
  
  if (successful === total) {
    console.log('🎉 All tests passed! The system is ready for use.');
  } else {
    console.log('⚠️ Some tests failed. Please check the issues above.');
  }
  
  return { successful, total, results };
}

// Run tests if this script is executed directly
if (require.main === module) {
  runAllTests().catch(console.error);
}

module.exports = { runAllTests };
