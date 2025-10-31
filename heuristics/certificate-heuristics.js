// Certificate Heuristics - Analyzes certificate issuer for MITM indicators

// Let's Encrypt issuer strings
const LETS_ENCRYPT_ISSUERS = [
  'Let\'s Encrypt',
  'Let\'s Encrypt Authority',
  'R3',
  'E1',
  'RSA CA 2018',
  'RSA CA 2021'
];

// Check if certificate is from Let's Encrypt
function checkLetsEncryptCertificate(issuer, hostname) {
  const isLetsEncrypt = LETS_ENCRYPT_ISSUERS.some(le => 
    issuer && issuer.includes(le)
  );
  
  if (!isLetsEncrypt) {
    return { severity: 'secure', score: 0 };
  }
  
  // Check if site is sensitive (banking, login, payments, etc.)
  const sensitivePatterns = [
    /bank|banking|finance|financial/i,
    /login|auth|secure|account/i,
    /pay|payment|transaction|checkout/i,
    /medical|healthcare|insurance|pharmacy/i,
    /government|gov|state|federal/i
  ];
  
  const isSensitive = sensitivePatterns.some(pattern => pattern.test(hostname));
  
  if (isSensitive) {
    console.warn('⚠️ Let\'s Encrypt certificate on sensitive site:', hostname);
    
    return {
      severity: 'warning',
      score: 25,
      warning: 'Let\'s Encrypt certificates are free and auto-issued, making MITM attacks easier on sensitive sites',
      recommendation: 'Consider using Extended Validation (EV) certificate for better security',
      issuer: issuer
    };
  }
  
  // Let's Encrypt on non-sensitive sites is fine
  return { severity: 'secure', score: 0 };
}

// Check for wildcard certificate
function checkWildcardCertificate(subject) {
  if (!subject) return { severity: 'secure', score: 0 };
  
  if (subject.includes('*.') || subject.includes('*')) {
    console.warn('⚠️ Wildcard certificate detected');
    
    return {
      severity: 'warning',
      score: 15,
      warning: 'Wildcard certificates are more susceptible to MITM',
      subject: subject
    };
  }
  
  return { severity: 'secure', score: 0 };
}

// Check certificate age
function checkCertificateAge(validFrom, hostname, certificateDatabase) {
  if (!validFrom) return { severity: 'secure', score: 0 };
  
  const certAge = Date.now() - new Date(validFrom).getTime();
  const daysOld = certAge / (1000 * 60 * 60 * 24);
  
  // Less than 30 days old = recently issued
  if (daysOld < 30) {
    // Check if site is established (has history in database)
    const isEstablished = certificateDatabase && certificateDatabase.has(hostname);
    
    if (isEstablished) {
      console.warn('⚠️ Recently issued certificate on established site');
      
      return {
        severity: 'warning',
        score: 20,
        warning: 'Certificate issued recently - verify legitimate renewal',
        daysOld: Math.round(daysOld)
      };
    }
  }
  
  return { severity: 'secure', score: 0 };
}

// Comprehensive certificate check
function analyzeCertificate(certificateInfo, hostname, certificateDatabase) {
  const checks = [];
  let totalScore = 0;
  
  // Check Let's Encrypt
  const letsEncryptCheck = checkLetsEncryptCertificate(
    certificateInfo.issuer, 
    hostname
  );
  if (letsEncryptCheck.score > 0) {
    checks.push(letsEncryptCheck);
    totalScore += letsEncryptCheck.score;
  }
  
  // Check wildcard
  const wildcardCheck = checkWildcardCertificate(certificateInfo.subject);
  if (wildcardCheck.score > 0) {
    checks.push(wildcardCheck);
    totalScore += wildcardCheck.score;
  }
  
  // Check age
  const ageCheck = checkCertificateAge(
    certificateInfo.validFrom,
    hostname,
    certificateDatabase
  );
  if (ageCheck.score > 0) {
    checks.push(ageCheck);
    totalScore += ageCheck.score;
  }
  
  return {
    score: totalScore,
    severity: totalScore >= 20 ? 'warning' : 'secure',
    checks,
    warnings: checks.filter(c => c.warning).map(c => c.warning)
  };
}

// Export functions
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    checkLetsEncryptCertificate,
    checkWildcardCertificate,
    checkCertificateAge,
    analyzeCertificate
  };
}

