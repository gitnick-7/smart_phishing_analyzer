const { URL } = require('url');

const PHISHING_KEYWORDS = [
  'login', 'verify', 'account', 'signin', 'banking', 'paypal', 
  'apple', 'microsoft', 'google', 'support', 'wallet', 'credential', 
  'token', 'update', 'auth', 'confirm', 'secure', 'webscr', 'cmd'
];

function analyzeUrl(urlString) {
  let riskScore = 0;
  let summaryReasons = [];
  
  let parsedUrl;
  try {
    parsedUrl = new URL(urlString);
  } catch (err) {
    return { error: 'Invalid URL format' };
  }

  const { protocol, hostname, pathname, search, searchParams } = parsedUrl;
  
  const telemetry = {
    url_length: urlString.length,
    url_length_flag: 'Safe',
    https_valid: protocol === 'https:',
    ssl_simulated_status: protocol === 'https:' ? 'Simulated Valid' : 'Insecure',
    suspicious_subdomains_detected: false,
    phishing_keywords_found: [],
    regex_matches: [],
    simulated_http_headers: {
      'x-frame-options': 'SAMEORIGIN',
      'strict-transport-security': protocol === 'https:' ? 'max-age=31536000' : 'none'
    }
  };

  // 1. Protocol Check
  if (protocol !== 'https:') {
    riskScore += 25;
    summaryReasons.push('The URL uses an unencrypted HTTP connection, which is less secure.');
  }

  // 2. Suspicious Subdomain Detection
  const hostParts = hostname.split('.');
  // e.g., login.paypal.verify-account.info -> subdomains: login, paypal, verify-account
  const domainPartsCount = hostParts.length;
  let subdomainCount = 0;
  let subdomains = [];
  let domain = '';
  let tld = '';

  if (domainPartsCount > 2) {
    subdomainCount = domainPartsCount - 2;
    subdomains = hostParts.slice(0, domainPartsCount - 2);
    domain = hostParts[domainPartsCount - 2];
    tld = hostParts[domainPartsCount - 1];
    
    if (subdomainCount > 2) {
      riskScore += 15;
      summaryReasons.push('Excessive subdomains were found, which is a common obfuscation tactic.');
      telemetry.suspicious_subdomains_detected = true;
    }
  } else if (domainPartsCount === 2) {
    domain = hostParts[0];
    tld = hostParts[1];
  } else {
    domain = hostname;
  }

  const allSubdomainText = subdomains.join('.');
  let foundBrandSpoofing = false;
  PHISHING_KEYWORDS.forEach(keyword => {
    if (allSubdomainText.toLowerCase().includes(keyword)) {
      foundBrandSpoofing = true;
      telemetry.phishing_keywords_found.push(keyword);
    }
  });

  if (foundBrandSpoofing) {
    riskScore += 30;
    summaryReasons.push('Suspicious keywords often associated with phishing were found in the subdomains.');
    telemetry.suspicious_subdomains_detected = true;
  }

  // 3. URL Length & Query Analysis
  if (urlString.length > 100) {
    riskScore += 20;
    telemetry.url_length_flag = 'HIGH Risk';
    summaryReasons.push('The URL is exceptionally long (> 100 characters), which can hide malicious payloads.');
  } else if (urlString.length > 75) {
    riskScore += 10;
    telemetry.url_length_flag = 'MODERATE';
    summaryReasons.push('The URL is quite long (> 75 characters).');
  }
  
  const queryParamCount = Array.from(searchParams.keys()).length;
  if (queryParamCount > 5) {
    riskScore += 10;
    summaryReasons.push('An unusually high number of query parameters was detected.');
  }
  
  if (urlString.includes('@')) {
    riskScore += 35;
    summaryReasons.push('The URL contains an "@" symbol, often used to obscure the actual destination.');
    telemetry.regex_matches.push('@ symbol');
  }

  // 4. Phishing Keyword Scanning (domain and path)
  const domainAndPathText = (domain + pathname + search).toLowerCase();
  PHISHING_KEYWORDS.forEach(keyword => {
    if (domainAndPathText.includes(keyword) && !telemetry.phishing_keywords_found.includes(keyword)) {
      telemetry.phishing_keywords_found.push(keyword);
    }
  });
  
  if (telemetry.phishing_keywords_found.length > 0 && !foundBrandSpoofing) {
    riskScore += 15;
    summaryReasons.push('Suspicious keywords were detected in the domain or path.');
  }

  // Normalize risk score to 100
  riskScore = Math.min(riskScore, 100);

  let riskLevel = 'Safe';
  let finalSummary = '';

  if (riskScore <= 30) {
    riskLevel = 'Safe';
    finalSummary = summaryReasons.length > 0 ? summaryReasons.join(' ') : 'No significant security risks were detected. The URL appears safe.';
  } else if (riskScore <= 69) {
    riskLevel = 'Caution';
    finalSummary = 'Proceed with caution. ' + summaryReasons.join(' ');
  } else {
    riskLevel = 'High Risk';
    finalSummary = 'High risk of phishing or malicious activity! ' + summaryReasons.join(' ');
  }

  return {
    user_layer: {
      risk_score: riskScore,
      risk_level: riskLevel,
      summary: finalSummary.trim()
    },
    expert_layer: {
      domain_breakdown: {
        protocol,
        hostname,
        subdomain: allSubdomainText,
        domain,
        tld,
        path: pathname,
        query_params_count: queryParamCount
      },
      telemetry
    }
  };
}

module.exports = {
  analyzeUrl
};
