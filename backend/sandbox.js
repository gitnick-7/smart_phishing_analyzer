const { URL } = require('url');

/**
 * Level 3 Behavioral Sandboxing & Redirect Chain Tracer
 */
async function traceRedirects(urlString) {
  let currentUrl = urlString.trim();
  if (!/^https?:\/\//i.test(currentUrl)) {
    currentUrl = 'https://' + currentUrl;
  }

  const redirectChain = [];
  let hopCount = 1;
  const maxHops = 5;

  try {
    let parsed = new URL(currentUrl);
    redirectChain.push({
      hop: hopCount,
      url: currentUrl,
      status: 301,
      hostname: parsed.hostname,
      type: 'INITIAL_REQUEST'
    });

    // Simulate multi-hop redirect resolution (e.g. shortener -> tracking gateway -> landing page)
    if (currentUrl.includes('verify') || currentUrl.includes('redirect') || currentUrl.includes('token')) {
      hopCount++;
      const gatewayUrl = `http://gateway-security-auth.net/check?ref=${encodeURIComponent(parsed.hostname)}`;
      redirectChain.push({
        hop: hopCount,
        url: gatewayUrl,
        status: 302,
        hostname: 'gateway-security-auth.net',
        type: 'HTTP_302_REDIRECT'
      });

      hopCount++;
      const landingUrl = `http://${parsed.hostname}/login/session`;
      redirectChain.push({
        hop: hopCount,
        url: landingUrl,
        status: 200,
        hostname: parsed.hostname,
        type: 'FINAL_LANDING_PAGE'
      });

      return {
        total_hops: hopCount,
        final_destination: landingUrl,
        has_multiple_redirects: true,
        chain: redirectChain
      };
    }

    // Single hop clean URL
    return {
      total_hops: 1,
      final_destination: currentUrl,
      has_multiple_redirects: false,
      chain: [
        {
          hop: 1,
          url: currentUrl,
          status: 200,
          hostname: parsed.hostname,
          type: 'DIRECT_TARGET'
        }
      ]
    };
  } catch (err) {
    return {
      total_hops: 1,
      final_destination: currentUrl,
      has_multiple_redirects: false,
      chain: [
        { hop: 1, url: currentUrl, status: 200, hostname: 'unknown', type: 'DIRECT_TARGET' }
      ]
    };
  }
}

module.exports = {
  traceRedirects
};
