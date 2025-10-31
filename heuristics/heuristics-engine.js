// Heuristics Engine - Main orchestrator for MITM detection
// Analyzes DOM, forms, links, and network requests for data exfiltration patterns

let anomalyScore = 0;
let externalLinks = [];
let externalPosts = [];
let detectedIssues = [];

// Known good CDNs and domains to whitelist
const KNOWN_GOOD_DOMAINS = [
  'google.com', 'googleapis.com', 'gstatic.com',
  'facebook.com', 'fbcdn.net',
  'cloudflare.com', 'cloudflare.net',
  'amazonaws.com', 'amazon.com',
  'jsdelivr.net', 'cdnjs.com',
  'github.com', 'githubusercontent.com',
  'twitter.com', 'twimg.com'
];

// Initialize heuristics on page load
function initHeuristics() {
  console.log('🔍 Initializing heuristics engine');
  
  anomalyScore = 0;
  externalLinks = [];
  externalPosts = [];
  detectedIssues = [];
  
  // Run all heuristics
  checkFormSubmissions();
  checkExternalLinks();
  checkHiddenIframes();
  interceptNetworkRequests();
  
  // Monitor for dynamic changes
  setupMutationObserver();
  
  // Collect results
  const results = compileResults();
  
  // Report to background
  reportToBackground(results);
  
  return results;
}

// Check for forms submitting to external domains
function checkFormSubmissions() {
  const forms = document.querySelectorAll('form');
  console.log(`🔍 Checking ${forms.length} forms for external submissions`);
  
  forms.forEach((form, index) => {
    const action = form.getAttribute('action') || '';
    
    try {
      const formUrl = new URL(action, location.origin);
      
      if (formUrl.origin !== location.origin) {
        console.warn(`🚨 Form #${index + 1} submits to external domain:`, formUrl.hostname);
        
        anomalyScore += 90;
        
        // Extra suspicion if it has password fields
        const hasPassword = form.querySelector('input[type="password"]');
        if (hasPassword) {
          console.warn('🚨 CRITICAL: Password form submits externally!');
          anomalyScore += 50;
          detectedIssues.push({
            type: 'password_exfiltration',
            severity: 'critical',
            message: `Password form submits to ${formUrl.hostname}`
          });
        }
        
        // Check if form is hidden
        const style = window.getComputedStyle(form);
        if (style.display === 'none' || style.visibility === 'hidden') {
          console.warn('⚠️ Form is hidden!');
          anomalyScore += 30;
          detectedIssues.push({
            type: 'hidden_form',
            severity: 'warning',
            message: `Hidden form submits to ${formUrl.hostname}`
          });
        } else {
          detectedIssues.push({
            type: 'external_form',
            severity: 'critical',
            message: `Form submits to ${formUrl.hostname}`
          });
        }
      }
    } catch (e) {
      // Invalid URL, skip
    }
  });
}

// Extract all external links and analyze their domains
function checkExternalLinks() {
  const links = document.querySelectorAll('a[href]');
  console.log(`🔍 Checking ${links.length} links for external domains`);
  
  links.forEach(link => {
    const href = link.getAttribute('href');
    
    try {
      const linkUrl = new URL(href, location.origin);
      
      if (linkUrl.origin !== location.origin) {
        externalLinks.push({
          url: linkUrl.href,
          domain: linkUrl.hostname,
          text: link.textContent.trim().substring(0, 50),
          isVisible: isElementVisible(link)
        });
        
        // Check for suspicious patterns
        if (isSuspiciousDomain(linkUrl.hostname)) {
          anomalyScore += 20;
          detectedIssues.push({
            type: 'suspicious_link',
            severity: 'warning',
            message: `Suspicious external link: ${linkUrl.hostname}`
          });
        }
      }
    } catch (e) {
      // Invalid URL, skip
    }
  });
  
  // Analyze link patterns
  analyzeLinkPatterns();
}

// Check for suspicious domain patterns
function isSuspiciousDomain(hostname) {
  const suspiciousPatterns = [
    /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly/gi,  // URL shorteners
    /^\d+\.\d+\.\d+\.\d+$/g,                     // IP addresses
    /\.tk$|\.ml$|\.ga$|\.cf$|\.xyz$/gi,          // Suspicious TLDs
    /^[a-z0-9-]{1,10}\.[a-z]{2,3}$/gi            // Very short domains
  ];
  
  return suspiciousPatterns.some(pattern => pattern.test(hostname));
}

// Check for hidden external iframes
function checkHiddenIframes() {
  const iframes = document.querySelectorAll('iframe');
  console.log(`🔍 Checking ${iframes.length} iframes`);
  
  iframes.forEach(iframe => {
    const style = window.getComputedStyle(iframe);
    const isHidden = style.display === 'none' || 
                     style.visibility === 'hidden' ||
                     parseFloat(style.opacity) === 0;
    
    if (iframe.src) {
      try {
        const iframeUrl = new URL(iframe.src, location.origin);
        
        if (iframeUrl.origin !== location.origin) {
          if (isHidden) {
            console.warn('🚨 Hidden external iframe:', iframeUrl.hostname);
            anomalyScore += 60;
            detectedIssues.push({
              type: 'hidden_iframe',
              severity: 'critical',
              message: `Hidden iframe from ${iframeUrl.hostname}`
            });
          }
        }
      } catch (e) {
        // Can't access iframe content - suspicious
        if (isHidden) {
          anomalyScore += 30;
        }
      }
    }
  });
}

// Intercept network requests to detect POST exfiltration
function interceptNetworkRequests() {
  // Intercept fetch
  const originalFetch = window.fetch;
  window.fetch = function(url, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    
    if (method === 'POST') {
      try {
        const requestUrl = typeof url === 'string' ? url : url.href;
        const reqUrl = new URL(requestUrl, location.origin);
        
        if (reqUrl.origin !== location.origin) {
          console.warn('🚨 Fetch POST to external domain:', reqUrl.hostname);
          anomalyScore += 80;
          
          externalPosts.push({
            url: reqUrl.href,
            domain: reqUrl.hostname,
            method: 'fetch',
            timestamp: Date.now()
          });
          
          // Check for sensitive data
          if (options.body) {
            const bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
            if (containsSensitiveData(bodyStr)) {
              console.warn('🚨 CRITICAL: Sensitive data in POST!');
              anomalyScore += 40;
              detectedIssues.push({
                type: 'sensitive_data_exfiltration',
                severity: 'critical',
                message: `POSTing sensitive data to ${reqUrl.hostname}`
              });
            }
          }
        }
      } catch (e) {
        // Invalid URL, continue
      }
    }
    
    return originalFetch.apply(this, arguments);
  };
  
  // Intercept XMLHttpRequest
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._method = method;
    this._url = url;
    return originalXHROpen.apply(this, [method, url, ...args]);
  };
  
  XMLHttpRequest.prototype.send = function(data) {
    if (this._method && this._method.toUpperCase() === 'POST') {
      try {
        const reqUrl = new URL(this._url, location.origin);
        
        if (reqUrl.origin !== location.origin) {
          console.warn('🚨 XHR POST to external domain:', reqUrl.hostname);
          anomalyScore += 80;
          
          externalPosts.push({
            url: reqUrl.href,
            domain: reqUrl.hostname,
            method: 'xhr',
            timestamp: Date.now()
          });
          
          // Check for sensitive data
          if (data && containsSensitiveData(data.toString())) {
            console.warn('🚨 CRITICAL: Sensitive data in XHR POST!');
            anomalyScore += 40;
            detectedIssues.push({
              type: 'sensitive_data_exfiltration',
              severity: 'critical',
              message: `POSTing sensitive data via XHR to ${reqUrl.hostname}`
            });
          }
        }
      } catch (e) {
        // Invalid URL, continue
      }
    }
    
    return originalXHRSend.apply(this, arguments);
  };
}

// Helper to check if body contains sensitive data
function containsSensitiveData(str) {
  const lower = str.toLowerCase();
  const sensitivePatterns = [
    'password',
    'credit',
    'ssn',
    'social',
    'pin',
    'cvv',
    'cvc',
    'expiration',
    'card',
    'account',
    'routing'
  ];
  
  return sensitivePatterns.some(pattern => lower.includes(pattern));
}

// Analyze link patterns for anomalies
function analyzeLinkPatterns() {
  if (externalLinks.length === 0) return;
  
  const domainCounts = {};
  externalLinks.forEach(link => {
    domainCounts[link.domain] = (domainCounts[link.domain] || 0) + 1;
  });
  
  // If too many links point to one external domain
  Object.entries(domainCounts).forEach(([domain, count]) => {
    if (count > 10) {
      console.warn('⚠️ Excessive links to one external domain:', domain, `(${count} links)`);
      anomalyScore += 15;
    }
  });
  
  // Check for URL shorteners
  const shortenedLinks = externalLinks.filter(link => 
    /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly/gi.test(link.url)
  );
  
  if (shortenedLinks.length > 0) {
    console.warn('⚠️ URL shorteners detected:', shortenedLinks.length);
    anomalyScore += 20;
  }
}

// Setup MutationObserver to watch for dynamic changes
function setupMutationObserver() {
  const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.tagName === 'FORM') {
          // New form added
          const action = node.getAttribute('action') || '';
          try {
            const formUrl = new URL(action, location.origin);
            if (formUrl.origin !== location.origin) {
              console.warn('🚨 Dynamic form submits externally:', formUrl.hostname);
              anomalyScore += 90;
              
              const hasPassword = node.querySelector('input[type="password"]');
              if (hasPassword) {
                console.warn('🚨 CRITICAL: Dynamic password form!');
                anomalyScore += 50;
              }
            }
          } catch (e) {}
        } else if (node.tagName === 'A' && node.hasAttribute('href')) {
          // New link added
          const href = node.getAttribute('href');
          try {
            const linkUrl = new URL(href, location.origin);
            if (linkUrl.origin !== location.origin && isSuspiciousDomain(linkUrl.hostname)) {
              console.warn('🚨 Dynamic suspicious link:', linkUrl.hostname);
              anomalyScore += 20;
            }
          } catch (e) {}
        }
      });
    });
    
    // Report updated results
    const results = compileResults();
    reportToBackground(results);
  });
  
  observer.observe(document.body, { 
    childList: true, 
    subtree: true 
  });
}

// Helper to check if element is visible
function isElementVisible(element) {
  const style = window.getComputedStyle(element);
  return style.display !== 'none' && 
         style.visibility !== 'hidden' &&
         parseFloat(style.opacity) > 0;
}

// Compile all results
function compileResults() {
  const severity = determineSeverity(anomalyScore);
  
  return {
    anomalyScore,
    severity,
    externalPosts: externalPosts.length,
    externalLinks: externalLinks.length,
    linkDomains: [...new Set(externalLinks.map(l => l.domain))],
    detectedIssues,
    timestamp: Date.now()
  };
}

// Determine severity based on score
function determineSeverity(score) {
  if (score >= 100) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 20) return 'warning';
  return 'secure';
}

// Report results to background script
function reportToBackground(results) {
  chrome.runtime.sendMessage({
    action: 'heuristicsResults',
    data: results
  }).catch(err => {
    // Background script might not be ready
    console.log('Background not ready, will retry');
  });
}

// Export for content script use
if (typeof window !== 'undefined') {
  // Run heuristics on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(initHeuristics, 500); // Wait for page to settle
    });
  } else {
    setTimeout(initHeuristics, 500);
  }
}

console.log('🔍 Heuristics engine loaded');

