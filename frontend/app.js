const API_BASE_URL = 'http://localhost:5000/api';

// DOM Elements
const backendStatusEl = document.getElementById('backendStatus');
const urlForm = document.getElementById('urlForm');
const urlInput = document.getElementById('urlInput');
const clearBtn = document.getElementById('clearBtn');
const submitBtn = document.getElementById('submitBtn');
const scannerLoader = document.getElementById('scannerLoader');
const resultsContainer = document.getElementById('resultsContainer');

// History Drawer Elements
const historyToggleBtn = document.getElementById('historyToggleBtn');
const historyCountEl = document.getElementById('historyCount');
const historyModal = document.getElementById('historyModal');
const closeHistoryBtn = document.getElementById('closeHistoryBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const historyList = document.getElementById('historyList');

// Persona Views & Tabs
const personaTabs = document.getElementById('personaTabs');
const userLayerView = document.getElementById('userLayerView');
const expertLayerView = document.getElementById('expertLayerView');
const threatLayerView = document.getElementById('threatLayerView');
const exportReportBtn = document.getElementById('exportReportBtn');

// User Layer Elements
const userRiskScore = document.getElementById('userRiskScore');
const userRiskBadge = document.getElementById('userRiskBadge');
const gaugeFill = document.getElementById('gaugeFill');
const userSummary = document.getElementById('userSummary');
const shieldIndicator = document.getElementById('shieldIndicator');
const recIcon = document.getElementById('recIcon');
const recTitle = document.getElementById('recTitle');
const recDesc = document.getElementById('recDesc');
const threatCategoriesWrapper = document.getElementById('threatCategoriesWrapper');

// Expert Layer Elements
const domainBreakdownGrid = document.getElementById('domainBreakdownGrid');
const telemetryList = document.getElementById('telemetryList');
const headersGrid = document.getElementById('headersGrid');
const rawJsonCode = document.getElementById('rawJsonCode');
const copyJsonBtn = document.getElementById('copyJsonBtn');

// Threat Matrix Layer Elements
const matrixBarsContainer = document.getElementById('matrixBarsContainer');

// Global State
let currentAnalysisData = null;
let currentTargetUrl = '';
let scanHistory = JSON.parse(localStorage.getItem('phish_scan_history') || '[]');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  checkBackendHealth();
  setupEventListeners();
  updateHistoryUI();
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

// Event Listeners Setup
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

  // Tab Switcher between User, Expert, and Threat Matrix
  personaTabs.addEventListener('click', (e) => {
    const tabBtn = e.target.closest('.tab-btn');
    if (!tabBtn) return;

    personaTabs.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    tabBtn.classList.add('active');

    const tab = tabBtn.getAttribute('data-tab');
    userLayerView.classList.add('hidden');
    expertLayerView.classList.add('hidden');
    threatLayerView.classList.add('hidden');

    if (tab === 'user') {
      userLayerView.classList.remove('hidden');
    } else if (tab === 'expert') {
      expertLayerView.classList.remove('hidden');
    } else if (tab === 'threat') {
      threatLayerView.classList.remove('hidden');
    }
  });

  // Export Security Audit Report
  exportReportBtn.addEventListener('click', generateAuditReport);

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

  // History Drawer Listeners
  historyToggleBtn.addEventListener('click', () => {
    historyModal.classList.remove('hidden');
  });

  closeHistoryBtn.addEventListener('click', () => {
    historyModal.classList.add('hidden');
  });

  historyModal.addEventListener('click', (e) => {
    if (e.target === historyModal) {
      historyModal.classList.add('hidden');
    }
  });

  clearHistoryBtn.addEventListener('click', () => {
    scanHistory = [];
    localStorage.setItem('phish_scan_history', JSON.stringify([]));
    updateHistoryUI();
  });
}

// Main Analysis Handler
async function analyzeUrl(targetUrl) {
  currentTargetUrl = targetUrl;
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

    // Render User, Expert, and Threat Matrix views
    renderUserLayer(data.user_layer);
    renderExpertLayer(data.expert_layer, data);
    renderThreatMatrix(data);

    // Save to history
    saveToHistory(targetUrl, data.user_layer);

    // Show Results
    scannerLoader.classList.add('hidden');
    resultsContainer.classList.remove('hidden');

  } catch (error) {
    console.warn('Backend unavailable, utilizing local fallback analyzer:', error);
    const fallbackData = simulateClientAnalysis(targetUrl);
    currentAnalysisData = fallbackData;

    renderUserLayer(fallbackData.user_layer);
    renderExpertLayer(fallbackData.expert_layer, fallbackData);
    renderThreatMatrix(fallbackData);
    saveToHistory(targetUrl, fallbackData.user_layer);

    scannerLoader.classList.add('hidden');
    resultsContainer.classList.remove('hidden');
  } finally {
    submitBtn.disabled = false;
  }
}

// Render User Layer UI (Gauge, Threat Chips, Summary, Advice)
function renderUserLayer(userLayer) {
  const { risk_score, risk_level, summary, threat_categories } = userLayer;

  // Score counter animation
  animateValue(userRiskScore, 0, risk_score, 800);

  // Gauge Circle calculation (Circumference = 2 * PI * 65 ≈ 408)
  const maxOffset = 408;
  const targetOffset = maxOffset - (maxOffset * (risk_score / 100));
  gaugeFill.style.strokeDashoffset = targetOffset;

  // Threat Category Chips
  threatCategoriesWrapper.innerHTML = '';
  if (threat_categories && threat_categories.length > 0) {
    threat_categories.forEach(cat => {
      const chip = document.createElement('span');
      chip.className = 'threat-chip';
      chip.textContent = cat;
      threatCategoriesWrapper.appendChild(chip);
    });
  }

  // Set colors based on Risk Level
  userRiskBadge.className = 'risk-badge';
  if (risk_score <= 25) {
    userRiskBadge.textContent = 'SAFE';
    userRiskBadge.classList.add('safe');
    gaugeFill.style.stroke = 'var(--color-safe)';
    shieldIndicator.textContent = '🛡️';
    recIcon.textContent = '✅';
    recTitle.textContent = 'Safe to Browse';
    recDesc.textContent = 'No obvious phishing markers found. Always maintain standard security precautions.';
  } else if (risk_score <= 65) {
    userRiskBadge.textContent = 'CAUTION';
    userRiskBadge.classList.add('caution');
    gaugeFill.style.stroke = 'var(--color-caution)';
    shieldIndicator.textContent = '⚠️';
    recIcon.textContent = '⚡';
    recTitle.textContent = 'Proceed with Caution';
    recDesc.textContent = 'This URL exhibits suspicious traits (e.g. unencrypted connection, non-standard port, or long URL). Do not enter passwords.';
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
      <div class="breakdown-label">Subdomains</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.subdomain)}</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-label">Domain & TLD</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.domain)}.${escapeHtml(domain_breakdown.tld)}</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-label">Port</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.port || '80')}</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-label">Path</div>
      <div class="breakdown-value">${escapeHtml(domain_breakdown.path)}</div>
    </div>
  `;

  // 2. Telemetry List
  telemetryList.innerHTML = `
    <div class="telemetry-row">
      <span class="telemetry-key">URL Character Length</span>
      <span class="telemetry-val">${telemetry.url_length} chars (${telemetry.url_length_flag || 'Normal'})</span>
    </div>
    <div class="telemetry-row">
      <span class="telemetry-key">Domain Entropy (DGA Test)</span>
      <span class="telemetry-val">${telemetry.domain_entropy || '0.0'} (${telemetry.domain_entropy > 3.75 ? 'HIGH ENTROPY' : 'NORMAL'})</span>
    </div>
    <div class="telemetry-row">
      <span class="telemetry-key">Raw IP Hostname</span>
      <span class="telemetry-val ${!telemetry.is_ip_host}">${telemetry.is_ip_host ? 'IP DETECTED' : 'NO (Domain Host)'}</span>
    </div>
    <div class="telemetry-row">
      <span class="telemetry-key">Punycode / Homograph</span>
      <span class="telemetry-val ${!telemetry.is_punycode}">${telemetry.is_punycode ? 'SPOOFING DETECTED' : 'CLEAR'}</span>
    </div>
    <div class="telemetry-row">
      <span class="telemetry-key">Phishing Keywords Found</span>
      <span class="telemetry-val">${telemetry.phishing_keywords_found && telemetry.phishing_keywords_found.length > 0 ? telemetry.phishing_keywords_found.join(', ') : 'None'}</span>
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

// Render Threat Intel Matrix Bars
function renderThreatMatrix(fullData) {
  const { user_layer, expert_layer } = fullData;
  const { telemetry } = expert_layer || {};

  const protocolScore = telemetry?.https_valid ? 0 : 25;
  const subdomainScore = telemetry?.suspicious_subdomains_detected ? 30 : 0;
  const keywordScore = (telemetry?.phishing_keywords_found?.length || 0) * 10;
  const entropyScore = (telemetry?.domain_entropy > 3.75) ? 20 : 5;
  const ipScore = telemetry?.is_ip_host ? 35 : 0;

  const matrixFactors = [
    { title: 'Protocol & Encryption Safety', weight: protocolScore, color: protocolScore > 0 ? 'var(--color-danger)' : 'var(--color-safe)' },
    { title: 'IP Host & DNS Bypass Risk', weight: ipScore, color: ipScore > 0 ? 'var(--color-danger)' : 'var(--color-safe)' },
    { title: 'Subdomain Obfuscation Weight', weight: subdomainScore, color: subdomainScore > 0 ? 'var(--color-caution)' : 'var(--color-safe)' },
    { title: 'Credential Keyword Match Weight', weight: Math.min(keywordScore, 40), color: keywordScore > 0 ? 'var(--color-danger)' : 'var(--color-safe)' },
    { title: 'Domain Randomness / DGA Entropy', weight: Math.min(entropyScore, 30), color: entropyScore > 15 ? 'var(--color-caution)' : 'var(--color-safe)' }
  ];

  matrixBarsContainer.innerHTML = '';
  matrixFactors.forEach(factor => {
    const percentage = Math.min(Math.round((factor.weight / 40) * 100), 100);
    matrixBarsContainer.innerHTML += `
      <div class="matrix-bar-item">
        <div class="matrix-label-row">
          <span class="matrix-title">${escapeHtml(factor.title)}</span>
          <span class="matrix-weight">${factor.weight} pts</span>
        </div>
        <div class="matrix-progress-track">
          <div class="matrix-progress-fill" style="width: ${percentage}%; background-color: ${factor.color}"></div>
        </div>
      </div>
    `;
  });
}

// Generate Security Audit Report Window
function generateAuditReport() {
  if (!currentAnalysisData) return;

  const { user_layer, expert_layer } = currentAnalysisData;
  const reportWindow = window.open('', '_blank');

  const reportHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Security Audit Report - ${escapeHtml(currentTargetUrl)}</title>
      <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; padding: 2rem; color: #1e293b; line-height: 1.6; }
        h1 { color: #0f172a; border-bottom: 2px solid #00f2fe; padding-bottom: 0.5rem; }
        .score-box { background: #f8fafc; border: 1px solid #cbd5e1; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
        .badge { font-weight: bold; padding: 4px 10px; border-radius: 4px; color: white; display: inline-block; }
        .badge.High { background: #ef4444; }
        .badge.Caution { background: #f59e0b; }
        .badge.Safe { background: #10b981; }
        pre { background: #0f172a; color: #a7f3d0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
      </style>
    </head>
    <body>
      <h1>🛡️ Smart Phishing Threat Telemetry Report</h1>
      <p><strong>Target URL:</strong> <code>${escapeHtml(currentTargetUrl)}</code></p>
      <p><strong>Generated At:</strong> ${new Date().toLocaleString()}</p>
      
      <div class="score-box">
        <h2>Risk Assessment: <span class="badge ${user_layer.risk_level.split(' ')[0]}">${user_layer.risk_level} (${user_layer.risk_score}/100)</span></h2>
        <p><strong>Summary:</strong> ${escapeHtml(user_layer.summary)}</p>
      </div>

      <h3>Detailed Telemetry Payload</h3>
      <pre>${escapeHtml(JSON.stringify(currentAnalysisData, null, 2))}</pre>

      <script>window.print();</script>
    </body>
    </html>
  `;

  reportWindow.document.write(reportHtml);
  reportWindow.document.close();
}

// History Management
function saveToHistory(url, userLayer) {
  const newScan = {
    url,
    score: userLayer.risk_score,
    level: userLayer.risk_level,
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  };

  scanHistory.unshift(newScan);
  if (scanHistory.length > 20) scanHistory.pop();

  localStorage.setItem('phish_scan_history', JSON.stringify(scanHistory));
  updateHistoryUI();
}

function updateHistoryUI() {
  historyCountEl.textContent = scanHistory.length;

  if (scanHistory.length === 0) {
    historyList.innerHTML = '<p class="empty-history">No recent scans recorded in this session.</p>';
    return;
  }

  historyList.innerHTML = '';
  scanHistory.forEach(item => {
    const historyItem = document.createElement('div');
    historyItem.className = 'history-item';
    historyItem.innerHTML = `
      <div class="history-url">${escapeHtml(item.url)}</div>
      <span class="risk-badge ${item.level.toLowerCase().split(' ')[0]}">${item.score}/100</span>
    `;
    historyItem.addEventListener('click', () => {
      urlInput.value = item.url;
      clearBtn.style.display = 'block';
      historyModal.classList.add('hidden');
      analyzeUrl(item.url);
    });
    historyList.appendChild(historyItem);
  });
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

// Client Fallback Simulation
function simulateClientAnalysis(urlStr) {
  try {
    const parsed = new URL(urlStr.startsWith('http') ? urlStr : 'http://' + urlStr);
    const isHttps = parsed.protocol === 'https:';
    const isLong = urlStr.length > 75;
    const hasKeywords = /(login|paypal|verify|bank|auth|account)/i.test(urlStr);

    let score = 0;
    if (!isHttps) score += 25;
    if (isLong) score += 20;
    if (hasKeywords) score += 40;

    score = Math.min(score, 100);
    const level = score > 65 ? 'High Risk' : score > 25 ? 'Caution' : 'Safe';

    return {
      user_layer: {
        risk_score: score,
        risk_level: level,
        threat_categories: hasKeywords ? ['Credential Harvesting', 'Unencrypted Connection'] : ['Standard Connection'],
        summary: `Client-side analysis: ${hasKeywords ? 'Credential keywords detected. ' : ''}${!isHttps ? 'Connection is unencrypted (HTTP). ' : 'HTTPS valid.'}`
      },
      expert_layer: {
        domain_breakdown: {
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          subdomain: parsed.hostname.split('.').slice(0, -2).join('.') || '(None)',
          domain: parsed.hostname.split('.').slice(-2, -1)[0] || parsed.hostname,
          tld: parsed.hostname.split('.').slice(-1)[0] || '',
          path: parsed.pathname,
          port: parsed.port || (isHttps ? '443' : '80'),
          query_params_count: Array.from(parsed.searchParams.keys()).length
        },
        telemetry: {
          url_length: urlStr.length,
          url_length_flag: isLong ? 'HIGH' : 'NORMAL',
          https_valid: isHttps,
          ssl_simulated_status: isHttps ? 'VALID' : 'MISSING',
          domain_entropy: 3.2,
          suspicious_subdomains_detected: hasKeywords,
          phishing_keywords_found: hasKeywords ? ['login', 'verify'] : [],
          simulated_http_headers: {
            'strict-transport-security': isHttps ? 'max-age=31536000' : 'none'
          }
        }
      }
    };
  } catch (e) {
    return {
      user_layer: { risk_score: 90, risk_level: 'High Risk', threat_categories: ['Malformed Input'], summary: 'Malformed URL provided.' },
      expert_layer: { domain_breakdown: {}, telemetry: {} }
    };
  }
}
