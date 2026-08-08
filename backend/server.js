const express = require('express');
const cors = require('cors');
const path = require('path');

const { analyzeUrl } = require('./analyzer');
const { getThreatIntel } = require('./threat_intel');
const { traceRedirects } = require('./sandbox');
const { analyzeCognitiveManipulation } = require('./nlp_profiler');
const { generateMitigationPayloads } = require('./mitigation');
const { runAdversarialBenchmark } = require('./adversarial_engine');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Health Endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '5.0-PRO' });
});

// Comprehensive Level 5 URL Analysis Endpoint
app.post('/api/analyze', async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid URL parameter.' });
  }

  // Level 1 & 2 Core Heuristics
  const coreResult = analyzeUrl(url);
  if (coreResult.error) {
    return res.status(400).json(coreResult);
  }

  const hostname = coreResult.expert_layer?.domain_breakdown?.hostname || 'localhost';
  const domain = coreResult.expert_layer?.domain_breakdown?.domain || hostname;

  // Level 2 Threat Intel Lookups, Level 3 Redirect Sandbox & NLP Profiler
  const [threatIntel, redirectData, nlpProfile] = await Promise.all([
    getThreatIntel(url, hostname),
    traceRedirects(url),
    Promise.resolve(analyzeCognitiveManipulation(url))
  ]);

  // Level 4 Active Defense Payload Generation
  const mitigationData = generateMitigationPayloads(url, domain, '127.0.0.1');

  // Merge Level 5 Response Structure
  const level5Result = {
    user_layer: {
      ...coreResult.user_layer,
      cognitive_nlp: nlpProfile
    },
    expert_layer: {
      ...coreResult.expert_layer,
      threat_intelligence: threatIntel,
      redirect_sandbox: redirectData,
      active_defense: mitigationData
    }
  };

  res.json(level5Result);
});

// Level 4 Active Defense Export Payload Endpoint
app.post('/api/mitigation/export', (req, res) => {
  const { domain, format } = req.body;
  const targetDomain = domain || 'phishing-target.com';
  const mitigation = generateMitigationPayloads(`http://${targetDomain}`, targetDomain, '127.0.0.1');

  if (format === 'bat') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename=block-${targetDomain}.bat`);
    return res.send(mitigation.payloads.windows_netsh_bat);
  } else if (format === 'hosts') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename=hosts-block.txt`);
    return res.send(mitigation.payloads.hosts_file_entry);
  } else if (format === 'dns') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename=dns-rpz.conf`);
    return res.send(mitigation.payloads.dns_sinkhole_rpz);
  }

  res.json(mitigation);
});

// Level 5 Autonomic Red/Blue Benchmark Endpoint
app.get('/api/adversarial/benchmark', (req, res) => {
  const benchmarkResults = runAdversarialBenchmark(analyzeUrl);
  res.json(benchmarkResults);
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Level 5 Autonomic Threat Intelligence Server running on port ${PORT}`);
  });
}

module.exports = app;
