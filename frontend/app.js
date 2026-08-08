const API_BASE_URL = 'http://localhost:5000/api';

// DOM Elements
const backendStatusEl = document.getElementById('backendStatus');
const urlForm = document.getElementById('urlForm');
const urlInput = document.getElementById('urlInput');
const clearBtn = document.getElementById('clearBtn');
const submitBtn = document.getElementById('submitBtn');
const scannerLoader = document.getElementById('scannerLoader');
const resultsContainer = document.getElementById('resultsContainer');

// Persona Toggle Elements
const expertToggle = document.getElementById('expertToggle');
const activePersonaBadge = document.getElementById('activePersonaBadge');
const userLayerView = document.getElementById('userLayerView');
const expertLayerView = document.getElementById('expertLayerView');

// User Layer Elements
const userRiskScore = document.getElementById('userRiskScore');
const userRiskBadge = document.getElementById('userRiskBadge');
const gaugeFill = document.getElementById('gaugeFill');
const userSummary = document.getElementById('userSummary');
const shieldIndicator = document.getElementById('shieldIndicator');
const recIcon = document.getElementById('recIcon');
const recTitle = document.getElementById('recTitle');
const recDesc = document.getElementById('recDesc');

// Expert Layer Elements
const domainBreakdownGrid = document.getElementById('domainBreakdownGrid');
const telemetryList = document.getElementById('telemetryList');
const headersGrid = document.getElementById('headersGrid');
const rawJsonCode = document.getElementById('rawJsonCode');
const copyJsonBtn = document.getElementById('copyJsonBtn');

// Global State
let currentAnalysisData = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  checkBackendHealth();
  setupEventListeners();
});

// Check Health of Backend Server
async function checkBackendHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    if (response.ok) {
      backendStatusEl.classList.add('online');
      backendStatusEl.querySelector('.status-text').textContent = 'Backend: Online (Express API)';
    } else {
      throw new Error('Health check failed');
    }
  } catch (err) {
    backendStatusEl.classList.remove('online');
    backendStatusEl.querySelector('.status-text').textContent = 'Backend: Standby / Local Mode';
  }
}

// Event Listeners
function setupEventListeners() {
  // Input clear button
  urlInput.addEventListener('input', () => {
    clearBtn.style.display = urlInput.value ? 'block' : 'none';
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.style.display = 'none';
    urlInput.focus();
  });

  // Preset Buttons
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const presetUrl = btn.getAttribute('data-url');
      urlInput.value = presetUrl;
      clearBtn.style.display = 'block';
      analyzeUrl(presetUrl);
    });
  });

  // Form Submission
  urlForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (url) {
      analyzeUrl(url);
    }
  });

  // Persona Toggle Switch
  expertToggle.addEventListener('change', () => {
    if (expertToggle.checked) {
      activePersonaBadge.textContent = 'Analyst Expert Mode';
      activePersonaBadge.style.color = '#00f2fe';
      activePersonaBadge.style.borderColor = '#00f2fe';
      userLayerView.classList.add('hidden');
      expertLayerView.classList.remove('hidden');
    } else {
      activePersonaBadge.textContent = 'User Mode';
      activePersonaBadge.style.color = '#10b981';
      activePersonaBadge.style.borderColor = '#10b981';
      userLayerView.classList.remove('hidden');
      expertLayerView.classList.add('hidden');
    }
  });

  // Copy JSON Button
  copyJsonBtn.addEventListener('click', () => {
    if (currentAnalysisData) {
      navigator.clipboard.writeText(JSON.stringify(currentAnalysisData, null, 2));
      const originalText = copyJsonBtn.innerHTML;
      copyJsonBtn.innerHTML = '✓ Copied!';
      setTimeout(() => {
        copyJsonBtn.innerHTML = originalText;
      }, 2000);
    }
  });
}

// Main Analysis Handler
async function analyzeUrl(targetUrl) {
  // UI State: Loading
  scannerLoader.classList.remove('hidden');
  resultsContainer.classList.add('hidden');
  submitBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Server error during analysis.');
    }

    const data = await response.json();
    currentAnalysisData = data;

    // Render both User and Expert views
    renderUserLayer(data.user_layer);
    renderExpertLayer(data.expert_layer, data);

    // Show Results
    scannerLoader.classList.add('hidden');
    resultsContainer.classList.remove('hidden');

  } catch (error) {
    console.warn('Backend unavailable, utilizing local fallback analyzer:', error);
    // Client-side fallback analyzer if backend is starting
    const fallbackData = simulateClientAnalysis(targetUrl);
    currentAnalysisData = fallbackData;
    renderUserLayer(fallbackData.user_layer);
    renderExpertLayer(fallbackData.expert_layer, fallbackData);

    scannerLoader.classList.add('hidden');
    resultsContainer.classList.remove('hidden');
  } finally {
    submitBtn.disabled = false;
  }
}

// Render User Layer UI (Gauge, Summary, Recommendations)
function renderUserLayer(userLayer) {
  const { risk_score, risk_level, summary } = userLayer;

  // Score counter animation
  animateValue(userRiskScore, 0, risk_score, 800);

  // Gauge Circle calculation (Circumference = 2 * PI * 65 ≈ 408)
  const maxOffset = 408;
  const targetOffset = maxOffset - (maxOffset * (risk_score / 100));
  gaugeFill.style.strokeDashoffset = targetOffset;

  // Set colors based on Risk Level
  userRiskBadge.className = 'risk-badge';
  if (risk_score <= 30) {
    userRiskBadge.textContent = 'SAFE';
    userRiskBadge.classList.add('safe');
    gaugeFill.style.stroke = 'var(--color-safe)';
    shieldIndicator.textContent = '🛡️';
    recIcon.textContent = '✅';
    recTitle.textContent = 'Safe to Browse';
    recDesc.textContent = 'No obvious phishing markers found. Always maintain standard browsing precautions.';
  } else if (risk_score <= 69) {
    userRiskBadge.textContent = 'CAUTION';
    userRiskBadge.classList.add('caution');
    gaugeFill.style.stroke = 'var(--color-caution)';
    shieldIndicator.textContent = '⚠️';
    recIcon.textContent = '⚡';
    recTitle.textContent = 'Proceed with Caution';
    recDesc.textContent = 'This URL has suspicious traits (e.g. unencrypted connection or long URL). Do not submit confidential passwords.';
  } else {
    userRiskBadge.textContent = 'HIGH RISK';
    userRiskBadge.classList.add('danger');
    gaugeFill.style.stroke = 'var(--color-danger)';
    shieldIndicator.textContent = '🚨';
    recIcon.textContent = '🛑';
    recTitle.textContent = 'Block & Do Not Proceed';
    recDesc.textContent = 'High probability of phishing or credential theft. Close this page immediately and report the link.';
  }

  userSummary.textContent = summary;
}

// Render Expert Layer UI (Breakdown, Telemetry, Headers, Raw JSON)
function renderExpertLayer(expertLayer, fullData) {
  const { domain_breakdown, telemetry } = expertLayer;

  // 1. Domain Breakdown
  domainBreakdownGrid.innerHTML = `
    <div class="breakdown-item">
      <div class="breakdown-label">Protocol</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.protocol)}</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-label">Hostname</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.hostname)}</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-label">Subdomain</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.subdomain || '(None)')}</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-label">Domain & TLD</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.domain)}.${escapeHtml(domain_breakdown.tld)}</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-label">Path</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.path || '/')}</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-label">Query Parameters</div>
      <div class="breakdown-value">${domain_breakdown.query_params_count}</div>
    </div>
  `;

  // 2. Telemetry List
  telemetryList.innerHTML = `
    <div class="telemetry-row">
      <span class="telemetry-key">URL Character Length</span>
      <span class="telemetry-val">${telemetry.url_length} chars (${telemetry.url_length_flag || 'Normal'})</span>
    </div>
    <div class="telemetry-row">
      <span class="telemetry-key">HTTPS Encrypted</span>
      <span class="telemetry-val ${telemetry.https_valid}">${telemetry.https_valid ? 'YES' : 'NO'}</span>
    </div>
    <div class="telemetry-row">
      <span class="telemetry-key">SSL Certificate Status</span>
      <span class="telemetry-val">${escapeHtml(telemetry.ssl_simulated_status)}</span>
    </div>
    <div class="telemetry-row">
      <span class="telemetry-key">Suspicious Subdomain Obfuscation</span>
      <span class="telemetry-val ${!telemetry.suspicious_subdomains_detected}">${telemetry.suspicious_subdomains_detected ? 'DETECTED' : 'CLEAR'}</span>
    </div>
    <div class="telemetry-row">
      <span class="telemetry-key">Phishing Keywords Found</span>
      <span class="telemetry-val">${telemetry.phishing_keywords_found.length > 0 ? telemetry.phishing_keywords_found.join(', ') : 'None'}</span>
    </div>
  `;

  // 3. Simulated HTTP Headers Grid
  headersGrid.innerHTML = '';
  if (telemetry.simulated_http_headers) {
    Object.entries(telemetry.simulated_http_headers).forEach(([key, val]) => {
      headersGrid.innerHTML += `
        <div class="header-item">
          <div class="header-name">${escapeHtml(key)}</div>
          <div class="header-val">${escapeHtml(val)}</div>
        </div>
      `;
    });
  }

  // 4. Raw JSON Output
  rawJsonCode.textContent = JSON.stringify(fullData, null, 2);
}

// Utility: Number Counter Animation
function animateValue(element, start, end, duration) {
  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    element.textContent = Math.floor(progress * (end - start) + start);
    if (progress < 1) {
      window.requestAnimationFrame(step);
    }
  };
  window.requestAnimationFrame(step);
}

// Utility: Escape HTML
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[&<>"']/g, function(m) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
  });
}

// Fallback client simulation if API is unreachable
function simulateClientAnalysis(urlStr) {
  try {
    const parsed = new URL(urlStr);
    const isHttps = parsed.protocol === 'https:';
    const isLong = urlStr.length > 75;
    const hasKeywords = /(login|paypal|verify|bank|auth|account)/i.test(urlStr);

    let score = 0;
    if (!isHttps) score += 30;
    if (isLong) score += 20;
    if (hasKeywords) score += 40;

    score = Math.min(score, 100);
    const level = score > 69 ? 'High Risk' : score > 30 ? 'Caution' : 'Safe';

    return {
      user_layer: {
        risk_score: score,
        risk_level: level,
        summary: `Client-side analysis: ${hasKeywords ? 'Suspicious credentials keywords detected. ' : ''}${!isHttps ? 'Connection is unencrypted (HTTP). ' : 'HTTPS valid.'}`
      },
      expert_layer: {
        domain_breakdown: {
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          subdomain: parsed.hostname.split('.').slice(0, -2).join('.'),
          domain: parsed.hostname.split('.').slice(-2, -1)[0] || parsed.hostname,
          tld: parsed.hostname.split('.').slice(-1)[0] || '',
          path: parsed.pathname,
          query_params_count: Array.from(parsed.searchParams.keys()).length
        },
        telemetry: {
          url_length: urlStr.length,
          url_length_flag: isLong ? 'HIGH' : 'NORMAL',
          https_valid: isHttps,
          ssl_simulated_status: isHttps ? 'VALID' : 'MISSING',
          suspicious_subdomains_detected: hasKeywords,
          phishing_keywords_found: hasKeywords ? ['login', 'verify'] : [],
          simulated_http_headers: {
            'x-frame-options': 'SAMEORIGIN',
            'strict-transport-security': isHttps ? 'max-age=31536000' : 'none'
          }
        }
      }
    };
  } catch (e) {
    return {
      user_layer: { risk_score: 90, risk_level: 'High Risk', summary: 'Malformed URL provided.' },
      expert_layer: { domain_breakdown: {}, telemetry: {} }
    };
  }
}
