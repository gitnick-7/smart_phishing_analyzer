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

// Top Authentic Apex Domains Allowlist
const TOP_DOMAIN_ALLOWLIST = new Set([
  'google.com', 'google.co.in', 'google.co.uk',
  'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com',
  'apple.com', 'icloud.com',
  'paypal.com',
  'github.com',
  'amazon.com', 'aws.amazon.com',
  'facebook.com', 'meta.com',
  'twitter.com', 'x.com',
  'linkedin.com',
  'youtube.com',
  'wikipedia.org',
  'netflix.com',
  'instagram.com',
  'adobe.com',
  'yahoo.com',
  'bing.com',
  'duckduckgo.com',
  'zoom.us',
  'dropbox.com',
  'spotify.com',
  'wordpress.org',
  'cloudflare.com',
  'reddit.com'
]);

// Top Brand Benchmarks for Levenshtein Typosquatting Detection
const BRAND_BENCHMARKS = [
  'google', 'microsoft', 'paypal', 'apple', 'github', 
  'amazon', 'facebook', 'twitter', 'linkedin', 'netflix',
  'instagram', 'metamask', 'binance', 'coinbase', 'adobe'
];

// Levenshtein Distance Algorithm for Fuzzy String Matching
function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

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

  let trimmedUrl = (urlString || '').trim();
  if (!trimmedUrl) {
    return { error: 'Please enter a URL to analyze.' };
  }

  // 1. URL Normalization & Scheme Sanitization
  let formattedUrl = trimmedUrl;
  if (!/^https?:\/\//i.test(formattedUrl)) {
    formattedUrl = 'https://' + formattedUrl;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(formattedUrl);
  } catch (err) {
    return { error: 'Invalid URL format provided.' };
  }

  const protocol = parsedUrl.protocol.toLowerCase();
  const hostname = parsedUrl.hostname.toLowerCase();
  const pathname = parsedUrl.pathname;
  const search = parsedUrl.search;
  const searchParams = parsedUrl.searchParams;
  const port = parsedUrl.port;
  const normalizedUrl = parsedUrl.href;

  // 2. Strict TLD & Apex Domain Extraction
  const isIp = isIPAddress(hostname);
  const hostParts = hostname.split('.');
  let subdomain = '(None)';
  let domain = hostname;
  let tld = '(None)';
  let apexDomain = hostname;

  if (!isIp) {
    if (hostParts.length > 2) {
      subdomain = hostParts.slice(0, hostParts.length - 2).join('.');
      domain = hostParts[hostParts.length - 2];
      tld = hostParts[hostParts.length - 1];
      apexDomain = `${domain}.${tld}`;
    } else if (hostParts.length === 2) {
      subdomain = '(None)';
      domain = hostParts[0];
      tld = hostParts[1];
      apexDomain = `${domain}.${tld}`;
    }
  }

  const isAllowlistedApex = TOP_DOMAIN_ALLOWLIST.has(apexDomain) || TOP_DOMAIN_ALLOWLIST.has(hostname);
  const isStandardSubdomain = subdomain === '(None)' || subdomain === 'www';

  // 3. Brand Homoglyph / Typosquatting Detector (Levenshtein Distance)
  let typosquattingDetected = false;
  let typosquattingTarget = null;
  let typosquattingDistance = null;

  if (!isIp && !isAllowlistedApex) {
    // Tokenize domain parts (e.g., g00gle-login-verify -> ['g00gle', 'login', 'verify'])
    const domainTokens = domain.split(/[-_.]+/);
    const normalizedDomainName = domain.replace(/[-_]/g, '');

    for (const brand of BRAND_BENCHMARKS) {
      if (domain === brand) continue;

      // 1. Check full domain name distance
      let dist = levenshteinDistance(normalizedDomainName, brand);

      // 2. Check individual token distance (e.g. g00gle in g00gle-login-verify)
      if (dist > 2) {
        for (const token of domainTokens) {
          if (token === brand) continue;
          const tokenDist = levenshteinDistance(token, brand);
          if (tokenDist <= 2 && token.length >= (brand.length - 2)) {
            dist = tokenDist;
            break;
          }
        }
      }
      
      // If Levenshtein distance <= 2 OR domain contains brand lookalike string
      if (dist <= 2) {
        typosquattingDetected = true;
        typosquattingTarget = brand;
        typosquattingDistance = dist;
        break;
      }
    }
  }

  const telemetry = {
    normalized_url: normalizedUrl,
    apex_domain: apexDomain,
    subdomain: subdomain,
    tld: tld,
    url_length: normalizedUrl.length,
    url_length_flag: 'Safe',
    https_valid: protocol === 'https:',
    ssl_simulated_status: protocol === 'https:' ? 'Simulated Valid' : 'Insecure / Missing SSL',
    is_ip_host: isIp,
    is_punycode: hostname.includes('xn--'),
    non_standard_port: Boolean(port && port !== '80' && port !== '443'),
    domain_entropy: calculateEntropy(domain),
    high_risk_tld_detected: false,
    suspicious_subdomains_detected: false,
    allowlist_matched: isAllowlistedApex && isStandardSubdomain,
    typosquatting_detected: typosquattingDetected,
    typosquatting_target: typosquattingTarget,
    levenshtein_distance: typosquattingDistance,
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

  // 4. Weighted Threat Vector Scoring Logic
  if (telemetry.allowlist_matched) {
    // Top-Domain Allowlist Guard: Cap Risk Score at 0 for legitimate root domains
    riskScore = 0;
    summaryReasons.push(`Verified authentic apex domain (${apexDomain}). Risk score capped at 0 (Safe).`);
  } else {
    // Typosquatting / Brand Lookalike Penalty (+80 pts)
    if (typosquattingDetected) {
      riskScore += 80;
      threatCategories.add('Typosquatting Lookalike');
      summaryReasons.push(`Brand typosquatting detected! Hostname '${domain}' is a lookalike of authentic brand '${typosquattingTarget}' (Levenshtein distance: ${typosquattingDistance}).`);
      telemetry.regex_matches.push({ rule: 'Brand Typosquatting Lookalike', pattern: typosquattingTarget, matched: domain });
    }

    // Protocol Check (+25 pts)
    if (protocol !== 'https:') {
      riskScore += 25;
      threatCategories.add('Unencrypted Connection');
      summaryReasons.push('Uses an unencrypted HTTP connection.');
    }

    // Direct IP Host Check (+35 pts)
    if (telemetry.is_ip_host) {
      riskScore += 35;
      threatCategories.add('IP Host Bypassing DNS');
      summaryReasons.push('Uses a raw IP address instead of a domain name.');
    }

    // Non-Standard Port (+15 pts)
    if (telemetry.non_standard_port) {
      riskScore += 15;
      threatCategories.add('Non-Standard Web Port');
      summaryReasons.push(`Connects via non-standard port :${port}.`);
    }

    // Subdomain Obfuscation (+20 pts)
    if (subdomain !== '(None)' && subdomain.split('.').length >= 2) {
      riskScore += 20;
      threatCategories.add('Subdomain Obfuscation');
      summaryReasons.push(`Excessive subdomains detected (${subdomain}).`);
      telemetry.suspicious_subdomains_detected = true;
    }

    // High Risk TLD (+15 pts)
    if (HIGH_RISK_TLDS.includes(tld)) {
      riskScore += 15;
      telemetry.high_risk_tld_detected = true;
      threatCategories.add('High-Risk Top-Level Domain');
      summaryReasons.push(`Uses high-risk top-level domain .${tld}.`);
    }

    // Punycode Homograph (+30 pts)
    if (telemetry.is_punycode) {
      riskScore += 30;
      threatCategories.add('IDN Homograph Spoofing');
      summaryReasons.push('Punycode homograph spoofing detected.');
    }

    // Shannon Entropy (+20 pts)
    if (telemetry.domain_entropy > 3.75 && domain.length > 7) {
      riskScore += 20;
      threatCategories.add('High Domain Entropy (DGA)');
      summaryReasons.push(`High domain randomness score (${telemetry.domain_entropy}).`);
    }

    // Phishing Keywords in Path or Query (+15 pts)
    const domainAndPathText = (hostname + pathname + search).toLowerCase();
    PHISHING_KEYWORDS.forEach(keyword => {
      if (domainAndPathText.includes(keyword) && keyword !== domain) {
        if (!telemetry.phishing_keywords_found.includes(keyword)) {
          telemetry.phishing_keywords_found.push(keyword);
        }
      }
    });

    if (telemetry.phishing_keywords_found.length > 0 && !typosquattingDetected) {
      riskScore += 15;
      threatCategories.add('Credential Harvesting Pattern');
      summaryReasons.push('Target credential-harvesting keywords found in URL path.');
    }

    // Base64 Payload Check (+20 pts)
    searchParams.forEach((val, key) => {
      if (val.length > 16 && /^[A-Za-z0-9+/=]+$/.test(val)) {
        try {
          const decoded = Buffer.from(val, 'base64').toString('utf-8');
          if (/^https?:\/\//i.test(decoded) || decoded.includes('@')) {
            telemetry.decoded_query_payloads.push({ param: key, raw: val, decoded });
            riskScore += 20;
            threatCategories.add('Base64 Encoded Payload');
            summaryReasons.push(`Base64 payload detected in query param '${key}'.`);
          }
        } catch (e) {}
      }
    });
  }

  // Cap final score at 100
  riskScore = Math.min(riskScore, 100);

  let riskLevel = 'Safe';
  let finalSummary = '';

  if (riskScore <= 25) {
    riskLevel = 'Safe';
    finalSummary = summaryReasons.length > 0 ? summaryReasons.join(' ') : 'No significant threat factors detected. The URL appears safe.';
  } else if (riskScore <= 65) {
    riskLevel = 'Caution';
    finalSummary = 'Proceed with caution. ' + summaryReasons.join(' ');
  } else {
    riskLevel = 'High Risk';
    finalSummary = 'CRITICAL RISK: High probability of phishing or brand impersonation! ' + summaryReasons.join(' ');
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
        subdomain,
        domain,
        apex_domain: apexDomain,
        tld,
        path: pathname || '/',
        port: port || (protocol === 'https:' ? '443' : '80'),
        query_params_count: Array.from(searchParams.keys()).length
      },
      telemetry
    }
  };
}

module.exports = {
  analyzeUrl,
  levenshteinDistance
};
