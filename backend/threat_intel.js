const { URL } = require('url');

/**
 * Level 2 Threat Intelligence Client & Stubs
 */

// VirusTotal API v3 Client / Stub
async function lookupVirusTotal(urlString) {
  try {
    // Simulated VirusTotal v3 intelligence response based on domain heuristics
    const parsed = new URL(urlString.startsWith('http') ? urlString : 'http://' + urlString);
    const domain = parsed.hostname;
    
    const isSuspicious = /(paypal|login|verify|account|bank|secure|xyz|top|info)/i.test(urlString);
    const flaggedCount = isSuspicious ? (domain.includes('paypal') ? 14 : 6) : 0;
    const totalEngines = 90;
    
    return {
      status: 'SUCCESS',
      provider: 'VirusTotal API v3',
      flagged_engines: flaggedCount,
      total_engines: totalEngines,
      community_score: flaggedCount > 0 ? -Math.min(flaggedCount * 5, 85) : 42,
      verdict: flaggedCount > 10 ? 'MALICIOUS' : flaggedCount > 0 ? 'SUSPICIOUS' : 'CLEAN',
      permalink: `https://www.virustotal.com/gui/domain/${domain}`
    };
  } catch (err) {
    return { status: 'ERROR', message: 'VirusTotal lookup failed' };
  }
}

// Google Safe Browsing API v5 Client / Stub
async function lookupGoogleSafeBrowsing(urlString) {
  try {
    const isPhishing = /(paypal|login|verify-account|bank-update)/i.test(urlString);
    return {
      status: 'SUCCESS',
      provider: 'Google Safe Browsing v5',
      is_flagged: isPhishing,
      threat_type: isPhishing ? 'SOCIAL_ENGINEERING (PHISHING)' : 'NONE',
      platform_type: 'ANY_PLATFORM'
    };
  } catch (err) {
    return { status: 'ERROR', message: 'Safe Browsing lookup failed' };
  }
}

// WHOIS Domain Registration Age Calculator
function lookupWhoisAge(hostname) {
  if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return {
      domain_age_days: 0,
      created_date: 'N/A (Raw IP Host)',
      is_young_domain: false,
      registrar: 'N/A'
    };
  }

  // Simulated WHOIS lookup based on domain characteristics
  const isKnownBrand = /(google|apple|microsoft|github|paypal\.com$)/i.test(hostname);
  const ageDays = isKnownBrand ? 8420 : (hostname.includes('verify') || hostname.includes('xyz') ? 4 : 520);
  const createdDate = new Date(Date.now() - ageDays * 86400000).toISOString().split('T')[0];

  return {
    domain_age_days: ageDays,
    created_date: createdDate,
    is_young_domain: ageDays < 30,
    registrar: isKnownBrand ? 'MarkMonitor Inc.' : 'NameCheap / PublicRegistrar'
  };
}

// SSL Certificate Security Inspector
function inspectSSLCert(urlString) {
  const isHttps = urlString.toLowerCase().startsWith('https:');
  if (!isHttps) {
    return {
      is_valid: false,
      issuer: 'None (Unencrypted HTTP)',
      valid_to: 'N/A',
      is_self_signed: false,
      cipher: 'None'
    };
  }

  const isSuspicious = urlString.includes('verify') || urlString.includes('xyz');
  return {
    is_valid: !isSuspicious,
    issuer: isSuspicious ? "Let's Encrypt Authority X3 (Untrusted Domain)" : 'DigiCert Global Root CA',
    valid_to: new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0],
    is_self_signed: isSuspicious,
    cipher: 'TLS_AES_256_GCM_SHA384'
  };
}

// Aggregate Threat Intelligence
async function getThreatIntel(urlString, hostname) {
  const [vt, gsb] = await Promise.all([
    lookupVirusTotal(urlString),
    lookupGoogleSafeBrowsing(urlString)
  ]);

  const whois = lookupWhoisAge(hostname);
  const ssl = inspectSSLCert(urlString);

  return {
    virustotal: vt,
    google_safe_browsing: gsb,
    whois,
    ssl_certificate: ssl
  };
}

module.exports = {
  lookupVirusTotal,
  lookupGoogleSafeBrowsing,
  lookupWhoisAge,
  inspectSSLCert,
  getThreatIntel
};
