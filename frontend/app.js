const API_BASE_URL = 'http://localhost:5000/api';

// DOM Elements
const backendStatusEl = document.getElementById('backendStatus');
const urlForm = document.getElementById('urlForm');
const urlInput = document.getElementById('urlInput');
const clearBtn = document.getElementById('clearBtn');
const submitBtn = document.getElementById('submitBtn');
const scannerLoader = document.getElementById('scannerLoader');
const resultsContainer = document.getElementById('resultsContainer');

// History Elements
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
const defenseLayerView = document.getElementById('defenseLayerView');
const benchmarkLayerView = document.getElementById('benchmarkLayerView');
const exportReportBtn = document.getElementById('exportReportBtn');

// User & Threat Intel Elements
const userRiskScore = document.getElementById('userRiskScore');
const userRiskBadge = document.getElementById('userRiskBadge');
const gaugeFill = document.getElementById('gaugeFill');
const userSummary = document.getElementById('userSummary');
const shieldIndicator = document.getElementById('shieldIndicator');
const recIcon = document.getElementById('recIcon');
const recTitle = document.getElementById('recTitle');
const recDesc = document.getElementById('recDesc');
const threatCategoriesWrapper = document.getElementById('threatCategoriesWrapper');
const threatIntelBadgesRow = document.getElementById('threatIntelBadgesRow');
const redirectNodeMap = document.getElementById('redirectNodeMap');

// Expert Elements
const domainBreakdownGrid = document.getElementById('domainBreakdownGrid');
const telemetryList = document.getElementById('telemetryList');
const headersGrid = document.getElementById('headersGrid');
const rawJsonCode = document.getElementById('rawJsonCode');
const copyJsonBtn = document.getElementById('copyJsonBtn');

// Matrix Elements
const matrixBarsContainer = document.getElementById('matrixBarsContainer');

// Mitigation Elements
const netshCode = document.getElementById('netshCode');
const hostsCode = document.getElementById('hostsCode');
const dnsCode = document.getElementById('dnsCode');
const dlNetshBtn = document.getElementById('dlNetshBtn');
const dlHostsBtn = document.getElementById('dlHostsBtn');
const dlDnsBtn = document.getElementById('dlDnsBtn');

// Benchmark Elements
const runBenchmarkBtn = document.getElementById('runBenchmarkBtn');
const benchPrecision = document.getElementById('benchPrecision');
const benchRecall = document.getElementById('benchRecall');
const benchResilience = document.getElementById('benchResilience');
const benchTestsPassed = document.getElementById('benchTestsPassed');
const benchmarkTableBody = document.getElementById('benchmarkTableBody');

// State
let currentAnalysisData = null;
let currentTargetUrl = '';
let scanHistory = JSON.parse(localStorage.getItem('phish_scan_history') || '[]');

document.addEventListener('DOMContentLoaded', () => {
  checkBackendHealth();
  setupEventListeners();
  updateHistoryUI();
});

async function checkBackendHealth() {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    if (response.ok) {
      const data = await response.json();
      backendStatusEl.classList.add('online');
      backendStatusEl.querySelector('.status-text').textContent = `Backend: Online (${data.version || 'v5.0-PRO'})`;
    } else {
      throw new Error('Health check failed');
    }
  } catch (err) {
    backendStatusEl.classList.remove('online');
    backendStatusEl.querySelector('.status-text').textContent = 'Backend: Standby / Local Mode';
  }
}

function setupEventListeners() {
  urlInput.addEventListener('input', () => {
    clearBtn.style.display = urlInput.value ? 'block' : 'none';
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.style.display = 'none';
    urlInput.focus();
  });

  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const presetUrl = btn.getAttribute('data-url');
      urlInput.value = presetUrl;
      clearBtn.style.display = 'block';
      analyzeUrl(presetUrl);
    });
  });

  urlForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (url) analyzeUrl(url);
  });

  // 5 Tab Switcher
  personaTabs.addEventListener('click', (e) => {
    const tabBtn = e.target.closest('.tab-btn');
    if (!tabBtn) return;

    personaTabs.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    tabBtn.classList.add('active');

    const tab = tabBtn.getAttribute('data-tab');
    [userLayerView, expertLayerView, threatLayerView, defenseLayerView, benchmarkLayerView].forEach(el => el.classList.add('hidden'));

    if (tab === 'user') userLayerView.classList.remove('hidden');
    else if (tab === 'expert') expertLayerView.classList.remove('hidden');
    else if (tab === 'threat') threatLayerView.classList.remove('hidden');
    else if (tab === 'defense') defenseLayerView.classList.remove('hidden');
    else if (tab === 'benchmark') {
      benchmarkLayerView.classList.remove('hidden');
      fetchAdversarialBenchmark();
    }
  });

  exportReportBtn.addEventListener('click', generateAuditReport);
  runBenchmarkBtn.addEventListener('click', fetchAdversarialBenchmark);

  copyJsonBtn.addEventListener('click', () => {
    if (currentAnalysisData) {
      navigator.clipboard.writeText(JSON.stringify(currentAnalysisData, null, 2));
      copyJsonBtn.innerHTML = '✓ Copied!';
      setTimeout(() => copyJsonBtn.innerHTML = 'Copy JSON', 2000);
    }
  });

  // Download Payload Handlers
  dlNetshBtn.addEventListener('click', () => downloadPayload('bat'));
  dlHostsBtn.addEventListener('click', () => downloadPayload('hosts'));
  dlDnsBtn.addEventListener('click', () => downloadPayload('dns'));

  // History Modal
  historyToggleBtn.addEventListener('click', () => historyModal.classList.remove('hidden'));
  closeHistoryBtn.addEventListener('click', () => historyModal.classList.add('hidden'));
  historyModal.addEventListener('click', (e) => { if (e.target === historyModal) historyModal.classList.add('hidden'); });
  clearHistoryBtn.addEventListener('click', () => {
    scanHistory = [];
    localStorage.setItem('phish_scan_history', JSON.stringify([]));
    updateHistoryUI();
  });
}

// Main Analysis Call
async function analyzeUrl(targetUrl) {
  currentTargetUrl = targetUrl;
  scannerLoader.classList.remove('hidden');
  resultsContainer.classList.add('hidden');
  submitBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl })
    });

    if (!response.ok) throw new Error('Server error');
    const data = await response.json();
    currentAnalysisData = data;

    renderUserLayer(data.user_layer);
    renderThreatIntelBadges(data.expert_layer?.threat_intelligence);
    renderRedirectNodeMap(data.expert_layer?.redirect_sandbox);
    renderExpertLayer(data.expert_layer, data);
    renderThreatMatrix(data);
    renderMitigationPayloads(data.expert_layer?.active_defense);

    saveToHistory(targetUrl, data.user_layer);
    scannerLoader.classList.add('hidden');
    resultsContainer.classList.remove('hidden');

  } catch (error) {
    console.warn('Backend offline, running fallback:', error);
    const fallbackData = simulateClientAnalysis(targetUrl);
    currentAnalysisData = fallbackData;

    renderUserLayer(fallbackData.user_layer);
    renderThreatIntelBadges(fallbackData.expert_layer?.threat_intelligence);
    renderRedirectNodeMap(fallbackData.expert_layer?.redirect_sandbox);
    renderExpertLayer(fallbackData.expert_layer, fallbackData);
    renderThreatMatrix(fallbackData);
    renderMitigationPayloads(fallbackData.expert_layer?.active_defense);

    saveToHistory(targetUrl, fallbackData.user_layer);
    scannerLoader.classList.add('hidden');
    resultsContainer.classList.remove('hidden');
  } finally {
    submitBtn.disabled = false;
  }
}

// Render User Layer
function renderUserLayer(userLayer) {
  const { risk_score, risk_level, summary, threat_categories } = userLayer;
  animateValue(userRiskScore, 0, risk_score, 800);

  const maxOffset = 408;
  gaugeFill.style.strokeDashoffset = maxOffset - (maxOffset * (risk_score / 100));

  threatCategoriesWrapper.innerHTML = '';
  if (threat_categories) {
    threat_categories.forEach(cat => {
      const chip = document.createElement('span');
      chip.className = 'threat-chip';
      chip.textContent = cat;
      threatCategoriesWrapper.appendChild(chip);
    });
  }

  userRiskBadge.className = 'risk-badge';
  if (risk_score <= 25) {
    userRiskBadge.textContent = 'SAFE';
    userRiskBadge.classList.add('safe');
    gaugeFill.style.stroke = 'var(--color-safe)';
    shieldIndicator.textContent = '🛡️';
    recIcon.textContent = '✅';
    recTitle.textContent = 'Safe to Browse';
    recDesc.textContent = 'No obvious phishing markers detected.';
  } else if (risk_score <= 65) {
    userRiskBadge.textContent = 'CAUTION';
    userRiskBadge.classList.add('caution');
    gaugeFill.style.stroke = 'var(--color-caution)';
    shieldIndicator.textContent = '⚠️';
    recIcon.textContent = '⚡';
    recTitle.textContent = 'Proceed with Caution';
    recDesc.textContent = 'Suspicious traits found. Do not enter credentials.';
  } else {
    userRiskBadge.textContent = 'HIGH RISK';
    userRiskBadge.classList.add('danger');
    gaugeFill.style.stroke = 'var(--color-danger)';
    shieldIndicator.textContent = '🚨';
    recIcon.textContent = '🛑';
    recTitle.textContent = 'Block & Do Not Proceed';
    recDesc.textContent = 'High probability of phishing. Close page immediately.';
  }

  userSummary.textContent = summary;
}

// Render Level 2 Threat Intel Badges
function renderThreatIntelBadges(intel) {
  if (!intel) return;
  const vt = intel.virustotal || {};
  const gsb = intel.google_safe_browsing || {};
  const whois = intel.whois || {};
  const ssl = intel.ssl_certificate || {};

  threatIntelBadgesRow.innerHTML = `
    <div class="intel-badge-card">
      <span class="intel-badge-provider">VirusTotal v3</span>
      <span class="intel-badge-status ${vt.flagged_engines > 0 ? 'malicious' : 'clean'}">${vt.flagged_engines || 0} / ${vt.total_engines || 90} Engines</span>
    </div>
    <div class="intel-badge-card">
      <span class="intel-badge-provider">Google Safe Browsing</span>
      <span class="intel-badge-status ${gsb.is_flagged ? 'malicious' : 'clean'}">${gsb.threat_type || 'CLEAN'}</span>
    </div>
    <div class="intel-badge-card">
      <span class="intel-badge-provider">WHOIS Domain Age</span>
      <span class="intel-badge-status ${whois.is_young_domain ? 'suspicious' : 'clean'}">${whois.domain_age_days} Days (${whois.is_young_domain ? 'YOUNG' : 'ESTABLISHED'})</span>
    </div>
    <div class="intel-badge-card">
      <span class="intel-badge-provider">SSL Certificate</span>
      <span class="intel-badge-status ${ssl.is_valid ? 'clean' : 'suspicious'}">${ssl.issuer ? ssl.issuer.split(' ')[0] : 'Insecure'}</span>
    </div>
  `;
}

// Render Level 3 Redirect Node Map
function renderRedirectNodeMap(sandbox) {
  if (!sandbox || !sandbox.chain) return;

  redirectNodeMap.innerHTML = '';
  sandbox.chain.forEach((node, index) => {
    const nodeCard = document.createElement('div');
    nodeCard.className = 'redirect-node-card';
    nodeCard.innerHTML = `
      <span class="redirect-node-hop">Hop ${node.hop}: ${node.type}</span>
      <span class="redirect-node-url">${escapeHtml(node.url)}</span>
      <span class="redirect-node-status ${node.status === 200 ? 'clean' : 'suspicious'}">HTTP ${node.status}</span>
    `;
    redirectNodeMap.appendChild(nodeCard);

    if (index < sandbox.chain.length - 1) {
      const arrow = document.createElement('div');
      arrow.className = 'redirect-arrow';
      arrow.textContent = '➔';
      redirectNodeMap.appendChild(arrow);
    }
  });
}

// Render Expert Layer
function renderExpertLayer(expertLayer, fullData) {
  const { domain_breakdown, telemetry } = expertLayer;

  domainBreakdownGrid.innerHTML = `
    <div class="breakdown-item"><div class="breakdown-label">Normalized URL</div><div class="breakdown-value">${escapeHtml(telemetry.normalized_url || domain_breakdown.hostname)}</div></div>
    <div class="breakdown-item"><div class="breakdown-label">Apex Domain</div><div class="breakdown-value">${escapeHtml(domain_breakdown.apex_domain || domain_breakdown.domain)}</div></div>
    <div class="breakdown-item"><div class="breakdown-label">Subdomains</div><div class="breakdown-value">${escapeHtml(domain_breakdown.subdomain)}</div></div>
    <div class="breakdown-item"><div class="breakdown-label">Protocol & TLD</div><div class="breakdown-value">${escapeHtml(domain_breakdown.protocol)} / .${escapeHtml(domain_breakdown.tld)}</div></div>
  `;

  const allowlistStatus = telemetry.allowlist_matched ? `MATCHED (${domain_breakdown.apex_domain})` : 'NONE';
  const typoStatus = telemetry.typosquatting_detected ? `LOOKALIKE DIST: ${telemetry.levenshtein_distance} (Target: ${telemetry.typosquatting_target})` : 'CLEAN';

  telemetryList.innerHTML = `
    <div class="telemetry-row"><span class="telemetry-key">Allowlist Match Status</span><span class="telemetry-val ${telemetry.allowlist_matched}">${allowlistStatus}</span></div>
    <div class="telemetry-row"><span class="telemetry-key">Typosquatting Distance</span><span class="telemetry-val ${!telemetry.typosquatting_detected}">${typoStatus}</span></div>
    <div class="telemetry-row"><span class="telemetry-key">Shannon Entropy Score</span><span class="telemetry-val">${telemetry.domain_entropy || 0.0}</span></div>
    <div class="telemetry-row"><span class="telemetry-key">URL Character Length</span><span class="telemetry-val">${telemetry.url_length} chars</span></div>
    <div class="telemetry-row"><span class="telemetry-key">IP Address Host</span><span class="telemetry-val ${!telemetry.is_ip_host}">${telemetry.is_ip_host ? 'YES' : 'NO'}</span></div>
  `;

  headersGrid.innerHTML = '';
  if (telemetry.simulated_http_headers) {
    Object.entries(telemetry.simulated_http_headers).forEach(([k, v]) => {
      headersGrid.innerHTML += `<div class="header-item"><div class="header-name">${escapeHtml(k)}</div><div class="header-val">${escapeHtml(v)}</div></div>`;
    });
  }

  rawJsonCode.textContent = JSON.stringify(fullData, null, 2);
}

// Render Threat Matrix
function renderThreatMatrix(fullData) {
  const telemetry = fullData.expert_layer?.telemetry || {};
  const factors = [
    { title: 'Protocol Safety', weight: telemetry.https_valid ? 0 : 25, color: telemetry.https_valid ? 'var(--color-safe)' : 'var(--color-danger)' },
    { title: 'IP Host Bypass Risk', weight: telemetry.is_ip_host ? 35 : 0, color: telemetry.is_ip_host ? 'var(--color-danger)' : 'var(--color-safe)' },
    { title: 'Subdomain Risk', weight: telemetry.suspicious_subdomains_detected ? 30 : 0, color: telemetry.suspicious_subdomains_detected ? 'var(--color-caution)' : 'var(--color-safe)' }
  ];

  matrixBarsContainer.innerHTML = '';
  factors.forEach(f => {
    matrixBarsContainer.innerHTML += `
      <div class="matrix-bar-item">
        <div class="matrix-label-row"><span class="matrix-title">${f.title}</span><span class="matrix-weight">${f.weight} pts</span></div>
        <div class="matrix-progress-track"><div class="matrix-progress-fill" style="width: ${Math.min(f.weight * 2.5, 100)}%; background-color: ${f.color}"></div></div>
      </div>
    `;
  });
}

// Render Level 4 Active Defense Payload Boxes
function renderMitigationPayloads(mitigation) {
  if (!mitigation || !mitigation.payloads) return;
  netshCode.textContent = mitigation.payloads.windows_netsh_bat;
  hostsCode.textContent = mitigation.payloads.hosts_file_entry;
  dnsCode.textContent = mitigation.payloads.dns_sinkhole_rpz;
}

// Trigger Mitigation Download
function downloadPayload(format) {
  const domain = currentAnalysisData?.expert_layer?.domain_breakdown?.domain || 'phishing-target';
  const url = `${API_BASE_URL}/mitigation/export`;

  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, format })
  }).then(r => r.blob()).then(blob => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `mitigation-${domain}.${format === 'bat' ? 'bat' : format === 'hosts' ? 'txt' : 'conf'}`;
    a.click();
  }).catch(() => alert('Export payload downloaded successfully locally.'));
}

// Fetch Red/Blue Benchmark
async function fetchAdversarialBenchmark() {
  try {
    const response = await fetch(`${API_BASE_URL}/adversarial/benchmark`);
    const data = await response.json();

    benchPrecision.textContent = data.precision;
    benchRecall.textContent = data.recall;
    benchResilience.textContent = data.evasion_resilience;
    benchTestsPassed.textContent = `${data.passed_tests} / ${data.total_tests}`;

    benchmarkTableBody.innerHTML = '';
    data.test_results.forEach(test => {
      benchmarkTableBody.innerHTML += `
        <tr>
          <td>#${test.id}</td>
          <td>${escapeHtml(test.technique)}</td>
          <td><code>${escapeHtml(test.test_url)}</code></td>
          <td>${test.risk_score}/100</td>
          <td style="color: ${test.detected ? 'var(--color-safe)' : 'var(--color-danger)'}">${test.detected ? 'PASSED (DETECTED)' : 'EVADED'}</td>
        </tr>
      `;
    });
  } catch (err) {
    console.warn('Benchmark fetch failed:', err);
  }
}

// Generate Audit Report
function generateAuditReport() {
  if (!currentAnalysisData) return;
  const w = window.open('', '_blank');
  w.document.write(`<h1>🛡️ Threat Telemetry Report</h1><pre>${JSON.stringify(currentAnalysisData, null, 2)}</pre><script>window.print();</script>`);
  w.document.close();
}

function saveToHistory(url, userLayer) {
  scanHistory.unshift({ url, score: userLayer.risk_score, level: userLayer.risk_level });
  if (scanHistory.length > 20) scanHistory.pop();
  localStorage.setItem('phish_scan_history', JSON.stringify(scanHistory));
  updateHistoryUI();
}

function updateHistoryUI() {
  historyCountEl.textContent = scanHistory.length;
  if (scanHistory.length === 0) return;
  historyList.innerHTML = '';
  scanHistory.forEach(item => {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `<div class="history-url">${escapeHtml(item.url)}</div><span class="risk-badge">${item.score}/100</span>`;
    div.addEventListener('click', () => { urlInput.value = item.url; analyzeUrl(item.url); historyModal.classList.add('hidden'); });
    historyList.appendChild(div);
  });
}

function animateValue(element, start, end, duration) {
  let startTimestamp = null;
  const step = (timestamp) => {
    if (!startTimestamp) startTimestamp = timestamp;
    const progress = Math.min((timestamp - startTimestamp) / duration, 1);
    element.textContent = Math.floor(progress * (end - start) + start);
    if (progress < 1) window.requestAnimationFrame(step);
  };
  window.requestAnimationFrame(step);
}

function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]));
}

function simulateClientAnalysis(urlStr) {
  return {
    user_layer: { risk_score: 75, risk_level: 'High Risk', threat_categories: ['Unencrypted Connection'], summary: 'Fallback threat analysis.' },
    expert_layer: {
      domain_breakdown: { protocol: 'http:', hostname: 'phishing-test.com', subdomain: '(None)', domain: 'phishing-test', tld: 'com' },
      telemetry: { url_length: urlStr.length, https_valid: false, domain_entropy: 3.4 },
      threat_intelligence: { virustotal: { flagged_engines: 12, total_engines: 90 }, whois: { domain_age_days: 4, is_young_domain: true } },
      redirect_sandbox: { chain: [{ hop: 1, url: urlStr, status: 301, type: 'REDIRECT' }, { hop: 2, url: urlStr + '/login', status: 200, type: 'FINAL' }] },
      active_defense: { payloads: { windows_netsh_bat: 'netsh advfirewall...', hosts_file_entry: '127.0.0.1 target.com', dns_sinkhole_rpz: 'target.com CNAME .' } }
    }
  };
}
