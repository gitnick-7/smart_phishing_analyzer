/**
 * Level 4 Active Defense & Defensive Rule Payload Generator
 */

function generateMitigationPayloads(urlString, domain, targetIp = '127.0.0.1') {
  const safeDomain = domain.replace(/[^a-zA-Z0-9.-]/g, '');
  const ruleName = `Block-Phishing-${safeDomain || 'Threat'}`;

  // 1. Windows Firewall (netsh) Outbound Block Command
  const windowsNetsh = [
    `@echo off`,
    `REM Active Defense Outbound Firewall Block Rule for ${safeDomain}`,
    `netsh advfirewall firewall add rule name="${ruleName}" dir=out action=block remoteip=${targetIp}`,
    `echo Firewall block rule applied for ${safeDomain}`
  ].join('\n');

  // 2. Local Hosts File Block Rule
  const hostsBlock = [
    `# Active Defense Local Hosts Block Entry`,
    `127.0.0.1 ${safeDomain}`,
    `127.0.0.1 www.${safeDomain}`
  ].join('\n');

  // 3. DNS Sinkhole (RPZ / BIND / Pi-hole) Rule
  const dnsSinkhole = [
    `; Active Defense DNS Response Policy Zone Rule`,
    `${safeDomain} CNAME .`,
    `*.${safeDomain} CNAME .`
  ].join('\n');

  return {
    domain: safeDomain,
    target_ip: targetIp,
    payloads: {
      windows_netsh_bat: windowsNetsh,
      hosts_file_entry: hostsBlock,
      dns_sinkhole_rpz: dnsSinkhole
    }
  };
}

module.exports = {
  generateMitigationPayloads
};
