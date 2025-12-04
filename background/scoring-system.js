// ============================================
// Unified Mathematical Scoring System
// ============================================
// 
// This module implements a mathematical scoring system that combines
// all security features into normalized threat and confidence scores.
//
// Formula:
//   Final Threat Score = min(100, Σ(weight_i × normalized_score_i))
//   Final Confidence Score = Σ(weight_i × confidence_i)
//
// Where:
//   - Each feature contributes a score (0-100) and confidence (0-100)
//   - Weights sum to 1.0
//   - Scores are normalized using min-max normalization
//   - Confidence is a weighted average

// Feature weights (must sum to 1.0)
const FEATURE_WEIGHTS = {
  URLSCAN: 0.60,       // 60% - Most reliable signal when available
  HEURISTICS: 0.25,    // 25% - Pattern-based analysis
  HTTPS_ENFORCEMENT: 0.15,  // 15% - Important but binary
  CONNECTION_SECURITY: 0.00  // 0% - Removed from scoring (handled by browser)
};

// Maximum possible scores for normalization
const MAX_SCORES = {
  HEURISTICS: 200,     // Reduced max from heuristics (pattern-based analysis)
  // Max breakdown: Form submissions (80-130), Link patterns (100-155), Network requests (60)
  URLSCAN: 100,        // Binary: 0 or 100
  HTTPS_ENFORCEMENT: 20,  // Binary: 0 or 20
  CONNECTION_SECURITY: 10  // Binary: 0 or 10 (not used in scoring)
};

/**
 * Normalize a score to 0-100 range using min-max normalization
 * @param {number} score - Raw score
 * @param {number} maxScore - Maximum possible score for this feature
 * @returns {number} Normalized score (0-100)
 */
function normalizeScore(score, maxScore) {
  if (maxScore === 0) return 0;
  // Clamp score to [0, maxScore] then normalize to [0, 100]
  const clampedScore = Math.max(0, Math.min(score, maxScore));
  return (clampedScore / maxScore) * 100;
}

/**
 * Calculate HTTPS Enforcement feature score
 * @param {boolean} wasUpgraded - Whether HTTP was upgraded to HTTPS
 * @param {boolean} isHTTPS - Whether current connection is HTTPS
 * @returns {{score: number, confidence: number}}
 */
function calculateHttpsEnforcementScore(wasUpgraded, isHTTPS) {
  let score = 0;
  let confidence = 100;
  
  if (!isHTTPS) {
    // HTTP connection - security risk
    score = 20;  // Max penalty
    confidence = 50;  // Lower confidence (could be intentional)
  } else if (wasUpgraded) {
    // HTTPS enforced by extension - good
    score = 0;
    confidence = 100;
  } else {
    // Already HTTPS - good
    score = 0;
    confidence = 100;
  }
  
  return {
    score: normalizeScore(score, MAX_SCORES.HTTPS_ENFORCEMENT),
    confidence
  };
}

/**
 * Calculate Connection Security feature score
 * @param {boolean} isHTTPS - Whether connection uses HTTPS
 * @param {boolean} isValidCertificate - Whether certificate is valid (Chrome/Firefox)
 * @returns {{score: number, confidence: number}}
 */
function calculateConnectionSecurityScore(isHTTPS, isValidCertificate) {
  let score = 0;
  let confidence = 100;
  
  if (!isHTTPS) {
    score = 10;  // Penalty for HTTP
    confidence = 0;  // No confidence in security
  } else if (!isValidCertificate) {
    score = 10;  // Penalty for invalid certificate
    confidence = 0;
  } else {
    score = 0;  // Secure connection
    confidence = 100;
  }
  
  return {
    score: normalizeScore(score, MAX_SCORES.CONNECTION_SECURITY),
    confidence
  };
}

/**
 * Calculate URLScan.io feature score
 * @param {Object|null} urlScanResult - URLScan result object
 * @returns {{score: number, confidence: number, available: boolean}}
 */
function calculateUrlScanScore(urlScanResult) {
  if (!urlScanResult || urlScanResult.unavailable) {
    // URLScan unavailable - don't penalize, but lower confidence
    return {
      score: 0,
      confidence: 0,  // No contribution to confidence when unavailable
      available: false
    };
  }
  
  if (urlScanResult.result?.success && urlScanResult.result?.data) {
    const isMalicious = urlScanResult.result.data.isMalicious;
    
    if (isMalicious) {
      return {
        score: normalizeScore(100, MAX_SCORES.URLSCAN),
        confidence: 100,  // High confidence when URLScan flags as malicious
        available: true
      };
    } else {
      return {
        score: 0,
        confidence: 80,  // Good confidence when URLScan verifies as safe
        available: true
      };
    }
  }
  
  // No verdict available
  return {
    score: 0,
    confidence: 0,
    available: false
  };
}

/**
 * Calculate Heuristics Analysis feature score
 * @param {number} anomalyScore - Raw anomaly score from heuristics
 * @param {number} confidenceScore - Confidence score from heuristics (0-100)
 * @returns {{score: number, confidence: number}}
 */
function calculateHeuristicsScore(anomalyScore, confidenceScore) {
  // Normalize heuristics score to 0-100
  const normalizedScore = normalizeScore(anomalyScore, MAX_SCORES.HEURISTICS);
  
  // Use heuristics confidence directly (already 0-100)
  const confidence = Math.max(0, Math.min(100, confidenceScore));
  
  return {
    score: normalizedScore,
    confidence
  };
}

/**
 * Calculate final unified threat and confidence scores
 * @param {Object} featureScores - Object containing scores from all features
 * @returns {{threatScore: number, confidenceScore: number, breakdown: Object}}
 */
function calculateFinalScores(featureScores) {
  const {
    heuristics,
    urlScan,
    httpsEnforcement,
    connectionSecurity
  } = featureScores;
  
  // Calculate weighted threat score
  let weightedThreatScore = 0;
  let totalWeight = 0;
  
  // URLScan (only if available) - Most reliable signal (60%)
  if (urlScan.available) {
    weightedThreatScore += FEATURE_WEIGHTS.URLSCAN * urlScan.score;
    totalWeight += FEATURE_WEIGHTS.URLSCAN;
  }
  
  // Heuristics (always available) - Pattern-based analysis (25%)
  weightedThreatScore += FEATURE_WEIGHTS.HEURISTICS * heuristics.score;
  totalWeight += FEATURE_WEIGHTS.HEURISTICS;
  
  // HTTPS Enforcement (always available) - Binary check (15%)
  weightedThreatScore += FEATURE_WEIGHTS.HTTPS_ENFORCEMENT * httpsEnforcement.score;
  totalWeight += FEATURE_WEIGHTS.HTTPS_ENFORCEMENT;
  
  // Connection Security (not used in scoring - handled by browser)
  // weightedThreatScore += FEATURE_WEIGHTS.CONNECTION_SECURITY * connectionSecurity.score;
  // totalWeight += FEATURE_WEIGHTS.CONNECTION_SECURITY;
  
  // Normalize by actual weight used (in case URLScan unavailable)
  const normalizedThreatScore = totalWeight > 0 
    ? weightedThreatScore / totalWeight 
    : 0;
  
  // Clamp to [0, 100]
  const finalThreatScore = Math.max(0, Math.min(100, normalizedThreatScore));
  
  // Calculate weighted confidence score
  let weightedConfidence = 0;
  let confidenceWeight = 0;
  
  // URLScan confidence (only if available) - Most reliable signal (60%)
  if (urlScan.available) {
    weightedConfidence += FEATURE_WEIGHTS.URLSCAN * urlScan.confidence;
    confidenceWeight += FEATURE_WEIGHTS.URLSCAN;
  }
  
  // Heuristics confidence - Pattern-based analysis (25%)
  weightedConfidence += FEATURE_WEIGHTS.HEURISTICS * heuristics.confidence;
  confidenceWeight += FEATURE_WEIGHTS.HEURISTICS;
  
  // HTTPS Enforcement confidence - Binary check (15%)
  weightedConfidence += FEATURE_WEIGHTS.HTTPS_ENFORCEMENT * httpsEnforcement.confidence;
  confidenceWeight += FEATURE_WEIGHTS.HTTPS_ENFORCEMENT;
  
  // Connection Security confidence (not used in scoring)
  // weightedConfidence += FEATURE_WEIGHTS.CONNECTION_SECURITY * connectionSecurity.confidence;
  // confidenceWeight += FEATURE_WEIGHTS.CONNECTION_SECURITY;
  
  // Normalize confidence
  const normalizedConfidence = confidenceWeight > 0
    ? weightedConfidence / confidenceWeight
    : 0;
  
  // Clamp to [0, 100]
  const finalConfidenceScore = Math.max(0, Math.min(100, normalizedConfidence));
  
  return {
    threatScore: Math.round(finalThreatScore * 100) / 100,  // Round to 2 decimals
    confidenceScore: Math.round(finalConfidenceScore * 100) / 100,
    breakdown: {
      urlScan: {
        score: Math.round(urlScan.score * 100) / 100,
        confidence: Math.round(urlScan.confidence * 100) / 100,
        weight: FEATURE_WEIGHTS.URLSCAN,
        available: urlScan.available
      },
      heuristics: {
        score: Math.round(heuristics.score * 100) / 100,
        confidence: Math.round(heuristics.confidence * 100) / 100,
        weight: FEATURE_WEIGHTS.HEURISTICS
      },
      httpsEnforcement: {
        score: Math.round(httpsEnforcement.score * 100) / 100,
        confidence: Math.round(httpsEnforcement.confidence * 100) / 100,
        weight: FEATURE_WEIGHTS.HTTPS_ENFORCEMENT
      },
      connectionSecurity: {
        score: Math.round(connectionSecurity.score * 100) / 100,
        confidence: Math.round(connectionSecurity.confidence * 100) / 100,
        weight: FEATURE_WEIGHTS.CONNECTION_SECURITY
      }
    }
  };
}

/**
 * Determine severity based on final threat score
 * @param {number} threatScore - Final normalized threat score (0-100)
 * @param {number} confidenceScore - Final confidence score (0-100)
 * @returns {string} 'critical' | 'warning' | 'secure'
 */
function determineSeverity(threatScore, confidenceScore) {
  // Use confidence-adjusted score for severity determination
  const adjustedScore = threatScore * (confidenceScore / 100);
  
  if (adjustedScore >= 80 || (threatScore >= 90 && confidenceScore >= 60)) {
    return 'critical';
  }
  if (adjustedScore >= 40 || (threatScore >= 50 && confidenceScore >= 40)) {
    return 'warning';
  }
  return 'secure';
}

/**
 * Calculate unified scores from all features
 * @param {Object} data - Feature data
 * @returns {Object} Final scores and breakdown
 */
function calculateUnifiedScores(data) {
  const {
    heuristicsAnomalyScore = 0,
    heuristicsConfidenceScore = 0,
    urlScanResult = null,
    httpsUpgraded = false,
    isHTTPS = true,
    isValidCertificate = true
  } = data;
  
  // Calculate individual feature scores
  const heuristics = calculateHeuristicsScore(
    heuristicsAnomalyScore,
    heuristicsConfidenceScore
  );
  
  const urlScan = calculateUrlScanScore(urlScanResult);
  
  const httpsEnforcement = calculateHttpsEnforcementScore(
    httpsUpgraded,
    isHTTPS
  );
  
  const connectionSecurity = calculateConnectionSecurityScore(
    isHTTPS,
    isValidCertificate
  );
  
  // Calculate final unified scores
  const finalScores = calculateFinalScores({
    heuristics,
    urlScan,
    httpsEnforcement,
    connectionSecurity
  });
  
  // Determine severity
  const severity = determineSeverity(
    finalScores.threatScore,
    finalScores.confidenceScore
  );
  
  return {
    ...finalScores,
    severity,
    rawScores: {
      heuristicsAnomalyScore,
      heuristicsConfidenceScore
    }
  };
}

// Export for use in background script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    calculateUnifiedScores,
    determineSeverity,
    FEATURE_WEIGHTS,
    MAX_SCORES
  };
}

