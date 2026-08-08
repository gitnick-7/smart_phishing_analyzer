const { URL } = require('url');

const PHISHING_KEYWORDS = [
  'login', 'verify', 'account', 'signin', 'banking', 'paypal', 
  'apple', 'microsoft', 'google', 'support', 'wallet', 'credential', 
  'token', 'update', 'auth', 'confirm', 'secure', 'webscr', 'cmd',
  'passcode', 'security', 'validation', 'alert', 'checkout', 'metamask'
];

const HIGH_RISK_TLDS = [
  'xyz', 'top', 'info', 'online', 'cc', 'site', 'tk', 'ml', 'ga', 
  'cf', 'gq', 'club', 'work', 'vip', 'cam', 'icu', 'rest', 'fit'
];

// Calculate Shannon Entropy for DGA (Domain Generation Algorithm) detection
function calculateEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(2));
}

// Check if string is an IP address
function isIPAddress(hostname) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^\[?[a-fA-F0-9:]+\]?$/;
  return ipv4Regex.test(hostname) || ipv6Regex.test(hostname);
}

function analyzeUrl(urlString) {
  let riskScore = 0;
  let summaryReasons = [];
  const threatCategories = new Set();
  
  let parsedUrl;
  try {
    // Add protocol if missing for parsing attempt
    let formattedUrl = urlString;
    if (!/^https?:\/\//i.test(formattedUrl)) {
      formattedUrl = 'http://' + formattedUrl;
    }
    parsedUrl = new URL(formattedUrl);
  } catch (err) {
    return { error: 'Invalid URL format provided.' };
  }

  const { protocol, hostname, port, pathname, search, searchParams } = parsedUrl;
  
  const telemetry = {
    url_length: urlString.length,
    url_length_flag: 'Safe',
    https_valid: protocol === 'https:',
    ssl_simulated_status: protocol === 'https:' ? 'Simulated Valid' : 'Insecure / Missing SSL',
    is_ip_host: isIPAddress(hostname),
    is_punycode: hostname.includes('xn--'),
    non_standard_port: Boolean(port && port !== '80' && port !== '443'),
    domain_entropy: calculateEntropy(hostname.split('.')[0] || hostname),
    high_risk_tld_detected: false,
    suspicious_subdomains_detected: false,
    phishing_keywords_found: [],
    decoded_query_payloads: [],
    regex_matches: [],
    simulated_http_headers: {
      'content-security-policy': 'MISSING (Vulnerable to XSS)',
      'x-frame-options': 'SAMEORIGIN',
      'strict-transport-security': protocol === 'https:' ? 'max-age=31536000; includeSubDomains' : 'none',
      'x-content-type-options': 'nosniff',
      'server-header': 'nginx/1.22.1 (Ubuntu)'
    }
  };

  // 1. Protocol & SSL Check
  if (protocol !== 'https:') {
    riskScore += 25;
    threatCategories.add('Unencrypted Connection');
    summaryReasons.push('The URL uses an unencrypted HTTP protocol, leaving transmissions vulnerable to interception.');
  }

  // 2. Direct IP Address Hostname
  if (telemetry.is_ip_host) {
    riskScore += 35;
    threatCategories.add('IP Host Bypassing DNS');
    summaryReasons.push('Uses a raw IP address instead of a domain name, commonly used to bypass domain blacklists.');
    telemetry.regex_matches.push({ rule: 'Direct IP Hostname', pattern: '^(\\d{1,3}\\.){3}\\d{1,3}$', matched: hostname });
  }

  // 3. Non-Standard Port Check
  if (telemetry.non_standard_port) {
    riskScore += 15;
    threatCategories.add('Non-Standard Web Port');
    summaryReasons.push(`Connects via non-standard web port :${port}.`);
  }

  // 4. Subdomain & TLD Analysis
  const hostParts = hostname.split('.');
  const domainPartsCount = hostParts.length;
  let subdomainCount = 0;
  let subdomains = [];
  let domain = '';
  let tld = '';

  if (!telemetry.is_ip_host) {
    if (domainPartsCount > 2) {
      subdomainCount = domainPartsCount - 2;
      subdomains = hostParts.slice(0, domainPartsCount - 2);
      domain = hostParts[domainPartsCount - 2];
      tld = hostParts[domainPartsCount - 1].toLowerCase();
      
      if (subdomainCount >= 2) {
        riskScore += 20;
        threatCategories.add('Subdomain Obfuscation');
        summaryReasons.push(`Excessive subdomains detected (${subdomainCount}), a frequent tactic to mimic legitimate brands.`);
        telemetry.suspicious_subdomains_detected = true;
      }
    } else if (domainPartsCount === 2) {
      domain = hostParts[0];
      tld = hostParts[1].toLowerCase();
    } else {
      domain = hostname;
    }

    // High Risk TLD Check
    if (HIGH_RISK_TLDS.includes(tld)) {
      riskScore += 15;
      telemetry.high_risk_tld_detected = true;
      threatCategories.add('High-Risk Top-Level Domain');
      summaryReasons.push(`Uses top-level domain .${tld}, statistically associated with spam and phishing campaigns.`);
    }

    // Punycode / Homograph Attack Detection
    if (telemetry.is_punycode) {
      riskScore += 30;
      threatCategories.add('IDN Homograph Spoofing');
      summaryReasons.push('Punycode detected (xn-- prefix), indicating a potential Internationalized Domain Name (IDN) homograph attack.');
      telemetry.regex_matches.push({ rule: 'Punycode Homograph', pattern: 'xn--', matched: hostname });
    }

    // DGA / Domain Entropy Analysis
    if (telemetry.domain_entropy > 3.75 && domain.length > 7) {
      riskScore += 20;
      threatCategories.add('High Domain Entropy (DGA)');
      summaryReasons.push(`High domain randomness score (${telemetry.domain_entropy}), suggesting algorithmic domain generation (DGA).`);
    }
  }

  // Brand Spoofing in Subdomains
  const allSubdomainText = subdomains.join('.').toLowerCase();
  PHISHING_KEYWORDS.forEach(keyword => {
    if (allSubdomainText.includes(keyword)) {
      telemetry.phishing_keywords_found.push(`subdomain:${keyword}`);
    }
  });

  if (telemetry.phishing_keywords_found.length > 0 && !telemetry.is_ip_host) {
    riskScore += 25;
    threatCategories.add('Brand Impersonation');
    summaryReasons.push('Target credential-harvesting keywords found in subdomain strings.');
    telemetry.suspicious_subdomains_detected = true;
  }

  // 5. URL Length & Query Analysis
  if (urlString.length > 100) {
    riskScore += 20;
    telemetry.url_length_flag = 'HIGH Risk';
    threatCategories.add('Excessive URL Length');
    summaryReasons.push('Excessively long URL (> 100 chars), often designed to hide malicious target strings.');
  } else if (urlString.length > 75) {
    riskScore += 10;
    telemetry.url_length_flag = 'MODERATE';
    summaryReasons.push('Long URL length (> 75 chars).');
  }

  // Obfuscated @ Symbol Check
  if (urlString.includes('@')) {
    riskScore += 35;
    threatCategories.add('URI Userinfo Obfuscation');
    summaryReasons.push('Contains an "@" symbol, which can force browser authentication redirection.');
    telemetry.regex_matches.push({ rule: 'URI Userinfo Obfuscation', pattern: '@', matched: '@' });
  }

  // Phishing Keyword Scanning across full URI
  const domainAndPathText = (hostname + pathname + search).toLowerCase();
  PHISHING_KEYWORDS.forEach(keyword => {
    if (domainAndPathText.includes(keyword) && !telemetry.phishing_keywords_found.includes(keyword)) {
      telemetry.phishing_keywords_found.push(keyword);
    }
  });

  if (telemetry.phishing_keywords_found.length > 0 && threatCategories.size === 0) {
    riskScore += 15;
    threatCategories.add('Credential Harvesting Pattern');
    summaryReasons.push('Security keywords detected in domain or path parameters.');
  }

  // Query Base64 payload decoder attempt
  searchParams.forEach((val, key) => {
    if (val.length > 16 && /^[A-Za-z0-9+/=]+$/.test(val)) {
      try {
        const decoded = Buffer.from(val, 'base64').toString('utf-8');
        if (/^https?:\/\//i.test(decoded) || decoded.includes('@')) {
          telemetry.decoded_query_payloads.push({ param: key, raw: val, decoded });
          riskScore += 20;
          threatCategories.add('Base64 Encoded Payload');
          summaryReasons.push(`Encoded Base64 redirect detected in query param '${key}'.`);
        }
      } catch (e) {
        // Not valid Base64 string
      }
    }
  });

  // Cap risk score at 100
  riskScore = Math.min(riskScore, 100);

  let riskLevel = 'Safe';
  let finalSummary = '';

  if (riskScore <= 25) {
    riskLevel = 'Safe';
    finalSummary = summaryReasons.length > 0 
      ? summaryReasons.join(' ') 
      : 'No significant risk factors detected. The URL appears safe based on Level 1 & 2 heuristics.';
  } else if (riskScore <= 65) {
    riskLevel = 'Caution';
    finalSummary = 'Proceed with caution. ' + summaryReasons.join(' ');
  } else {
    riskLevel = 'High Risk';
    finalSummary = 'CRITICAL RISK: High probability of phishing or credential harvesting! ' + summaryReasons.join(' ');
  }

  return {
    user_layer: {
      risk_score: riskScore,
      risk_level: riskLevel,
      threat_categories: Array.from(threatCategories),
      summary: finalSummary.trim()
    },
    expert_layer: {
      domain_breakdown: {
        protocol,
        hostname,
        subdomain: allSubdomainText || '(None)',
        domain: domain || hostname,
        tld: tld || '(None)',
        path: pathname || '/',
        port: port || (protocol === 'https:' ? '443' : '80'),
        query_params_count: Array.from(searchParams.keys()).length
      },
      telemetry
    }
  };
}

module.exports = {
  analyzeUrl
};
