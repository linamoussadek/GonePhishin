# Testing Guide for Gone Phishin' Extension

This guide explains how to test all features of the extension using the provided test sites.

## Quick Start

1. **Start the test server:**
   ```bash
   node serve-test-site.js
   ```

2. **Load the phishing test site:**
   - Navigate to `http://localhost:8080/phishing-test-site.html`
   - The extension should automatically upgrade to HTTPS
   - Open DevTools (F12) to see heuristic analysis logs

3. **Check extension popup:**
   - Click the extension icon
   - Review the "Heuristic Analysis" layer
   - Check anomaly score and detected issues

## Test Files

### 1. `phishing-test-site.html` - Comprehensive Phishing Test Site

This is the main test site that includes:

#### Test 1: Password Form to Suspicious External Domain (CRITICAL)
- **Expected:** Anomaly score +80, Confidence +60
- **Pattern:** Password form submitting to `phishing-site.tk` (high-risk TLD)
- **What to verify:** Extension flags as CRITICAL threat

#### Test 2: Hidden Form with Payment Fields (CRITICAL)
- **Expected:** Anomaly score +50, Confidence +70
- **Pattern:** Hidden form with card_number, cvv fields submitting externally
- **What to verify:** Extension detects hidden sensitive form

#### Test 3: Link Clone Pattern (CRITICAL)
- **Expected:** Anomaly score +100, Confidence +85
- **Pattern:** 85% of links point to `fake-bank-clone.ga`
- **What to verify:** Extension detects full-site clone pattern

#### Test 4: URL Shortener Chain (WARNING)
- **Expected:** Anomaly score +25, Confidence +20
- **Pattern:** Multiple different URL shorteners (bit.ly, tinyurl, t.co, goo.gl)
- **What to verify:** Extension flags shortener chain

#### Test 5: Sensitive Data POST (CRITICAL)
- **Expected:** Anomaly score +60, Confidence +50
- **Pattern:** POST request with SSN, credit card, routing number to external domain
- **What to verify:** Extension intercepts and flags sensitive data exfiltration

#### Test 6: Legitimate Payment Processor (SHOULD PASS)
- **Expected:** No flag (whitelisted)
- **Pattern:** Form submitting to `checkout.stripe.com`
- **What to verify:** Extension recognizes legitimate service and doesn't flag

#### Test 7: OAuth Provider (SHOULD PASS)
- **Expected:** No flag (whitelisted)
- **Pattern:** Form submitting to `accounts.google.com`
- **What to verify:** Extension recognizes OAuth provider and doesn't flag

#### Test 8: Suspicious Domain Patterns (WARNING)
- **Expected:** Warnings for high-risk TLDs
- **Pattern:** Links to .tk, .ml, .ga, .cf domains
- **What to verify:** Extension flags suspicious TLDs

### 2. `test-extension.html` - HTTPS Upgrade Test

Tests HTTPS enforcement:
- HTTP to HTTPS automatic upgrades
- Extension badge updates
- Network tab verification

**How to use:**
1. Open `test-extension.html` in browser
2. Click test links (they use HTTP)
3. Check Network tab for `non-authoritative-reason: WebRequest API`
4. Verify extension badge shows upgrade count

### 3. `mixed-content-test.html` - Mixed Content Blocking Test

Tests mixed content blocking:
- HTTP images on HTTPS pages
- HTTP scripts on HTTPS pages
- HTTP stylesheets on HTTPS pages

**How to use:**
1. Load `mixed-content-test.html` (should auto-upgrade to HTTPS)
2. Open DevTools Network tab
3. Verify HTTP resources are blocked
4. Verify HTTPS resources load normally

## Testing Checklist

### Heuristic Analysis
- [ ] Password form to suspicious domain triggers CRITICAL alert
- [ ] Hidden form with sensitive fields is detected
- [ ] Link clone pattern (70%+ to one domain) triggers CRITICAL
- [ ] URL shortener chain triggers WARNING
- [ ] Sensitive data POST is intercepted and flagged
- [ ] Legitimate services (Stripe, Google OAuth) are NOT flagged
- [ ] Suspicious TLDs (.tk, .ml, .ga, .cf) trigger warnings

### HTTPS Enforcement
- [ ] HTTP requests automatically upgrade to HTTPS
- [ ] Extension badge shows upgrade count
- [ ] Mixed content (HTTP on HTTPS) is blocked
- [ ] Network tab shows `WebRequest API` redirects

### UI/UX
- [ ] Popup shows correct anomaly score
- [ ] Protection layers display correctly
- [ ] Dashboard shows detailed analysis
- [ ] Alerts are shown for critical threats
- [ ] Connection security shows HTTPS status

### False Positives
- [ ] Stripe checkout forms don't trigger alerts
- [ ] Google OAuth forms don't trigger alerts
- [ ] PayPal forms don't trigger alerts
- [ ] Normal external links don't trigger alerts

## Expected Scores

When testing `phishing-test-site.html`, you should see:

- **Anomaly Score:** ~315+ (sum of all detected issues)
- **Confidence Score:** ~285+ (confidence-adjusted)
- **Severity:** CRITICAL
- **Detected Issues:** 5+ critical issues

## Debugging

### Check Console Logs
Open DevTools Console (F12) and look for:
- `🔍 Initializing heuristics engine`
- `🚨 CRITICAL:` messages for threats
- `⚠️` warnings for suspicious patterns
- `✅` confirmations for legitimate services

### Check Extension Storage
1. Open extension popup
2. Open DevTools (right-click popup → Inspect)
3. Go to Application tab → Storage → Local Storage
4. Look for `heuristics_*` keys with analysis results

### Verify Heuristics Engine
The heuristics engine runs automatically when the page loads. Check:
- Console for analysis logs
- Extension popup for results
- Dashboard for detailed breakdown

## Common Issues

### Heuristics Not Running
- **Solution:** Check that `heuristics-engine.js` is loaded in content scripts
- Verify manifest.json includes the heuristics file

### False Positives
- **Solution:** Check whitelist in `heuristics-engine.js`
- Verify legitimate services are in `LEGITIMATE_EXTERNAL_SERVICES` array

### HTTPS Not Upgrading
- **Solution:** Check declarativeNetRequest rules in `rules/https_rules.json`
- Verify extension has `declarativeNetRequest` permission

## Academic Testing Notes

For your Honours Project evaluation:

1. **Document all test scenarios** - Show what you're testing and why
2. **Record false positive rates** - Show how whitelisting reduces false positives
3. **Demonstrate confidence scoring** - Show how confidence affects severity
4. **Compare with/without extension** - Show the value added
5. **Test edge cases** - OAuth flows, payment processors, etc.

## Next Steps

1. Test all scenarios in `phishing-test-site.html`
2. Verify false positives are minimized
3. Check that legitimate services pass through
4. Document results for your project report
5. Create additional test cases if needed

