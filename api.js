/* ============================================
   API.JS — Real OSINT data from public APIs
   ============================================ */

'use strict';

const API = (() => {

  const CORS_PROXY = 'https://corsproxy.io/?';
  const TIMEOUT = 10000;

  /* ---------- Fetch with timeout ---------- */
  function fetchWithTimeout(url, ms) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms || TIMEOUT);
    return fetch(url, { signal: controller.signal })
      .then(res => { clearTimeout(timer); return res; })
      .catch(err => { clearTimeout(timer); throw err; });
  }

  /* ---------- crt.sh — Real subdomain enumeration ---------- */
  async function getSubdomains(domain) {
    try {
      const url = CORS_PROXY + encodeURIComponent(
        'https://crt.sh/?q=%25.' + domain + '&output=json'
      );
      const res = await fetchWithTimeout(url, 15000);
      const data = await res.json();

      if (!Array.isArray(data)) return null;

      // Extract unique subdomain names
      const seen = new Set();
      const results = [];

      data.forEach(entry => {
        const names = entry.name_value.split('\n');
        names.forEach(name => {
          const clean = name.trim().toLowerCase().replace(/^\*\./, '');
          if (clean && clean !== domain && clean.endsWith(domain) && !seen.has(clean)) {
            seen.add(clean);
            results.push({ name: clean, source: 'crt.sh' });
          }
        });
      });

      return results.slice(0, 30);
    } catch (e) {
      console.warn('[API] crt.sh failed:', e.message);
      return null;
    }
  }

  /* ---------- Google DNS — Real DNS records ---------- */
  async function getDNSRecords(domain) {
    const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
    const results = {};

    await Promise.all(types.map(async (type) => {
      try {
        const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`;
        const res = await fetchWithTimeout(url, 8000);
        const data = await res.json();

        if (data.Answer && data.Answer.length > 0) {
          results[type] = data.Answer.map(a => ({
            name: a.name,
            type: type,
            data: a.data,
            ttl: a.TTL,
          }));
        }
      } catch (e) {
        console.warn(`[API] DNS ${type} failed:`, e.message);
      }
    }));

    return Object.keys(results).length > 0 ? results : null;
  }

  /* ---------- Resolve domain to IP ---------- */
  async function resolveIP(domain) {
    try {
      const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`;
      const res = await fetchWithTimeout(url, 5000);
      const data = await res.json();
      if (data.Answer && data.Answer.length > 0) {
        return data.Answer[0].data;
      }
    } catch (e) {}
    return null;
  }

  /* ---------- IP Geolocation ---------- */
  async function getIPInfo(ip) {
    try {
      const url = `http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,query`;
      const res = await fetchWithTimeout(url, 5000);
      const data = await res.json();
      if (data.status === 'success') return data;
    } catch (e) {
      console.warn('[API] IP info failed:', e.message);
    }
    return null;
  }

  /* ---------- HTTP Headers via proxy ---------- */
  async function getHeaders(domain) {
    try {
      const url = CORS_PROXY + encodeURIComponent('https://' + domain);
      const res = await fetchWithTimeout(url, 8000);

      const headers = {};
      const interesting = [
        'server', 'x-powered-by', 'x-frame-options', 'content-security-policy',
        'strict-transport-security', 'x-content-type-options', 'x-xss-protection',
        'referrer-policy', 'permissions-policy', 'cf-ray', 'x-cache',
        'x-served-by', 'x-cdn', 'via'
      ];

      interesting.forEach(h => {
        const val = res.headers.get(h);
        if (val) headers[h] = val;
      });

      return Object.keys(headers).length > 0 ? headers : null;
    } catch (e) {
      console.warn('[API] Headers failed:', e.message);
      return null;
    }
  }

  /* ---------- Detect tech from headers ---------- */
  function detectTechFromHeaders(headers) {
    if (!headers) return [];
    const tech = [];

    const server = headers['server'];
    if (server) {
      if (/nginx/i.test(server)) tech.push({ category: 'server', name: 'Nginx', version: server.replace(/nginx\/?/i, '') || '' });
      else if (/apache/i.test(server)) tech.push({ category: 'server', name: 'Apache', version: server.replace(/apache\/?/i, '') || '' });
      else if (/cloudflare/i.test(server)) tech.push({ category: 'cdn', name: 'Cloudflare', version: '' });
      else if (/iis/i.test(server)) tech.push({ category: 'server', name: 'IIS', version: server.replace(/microsoft-iis\/?/i, '') || '' });
      else if (/litespeed/i.test(server)) tech.push({ category: 'server', name: 'LiteSpeed', version: '' });
      else if (/caddy/i.test(server)) tech.push({ category: 'server', name: 'Caddy', version: '' });
      else tech.push({ category: 'server', name: server.split('/')[0], version: server.split('/')[1] || '' });
    }

    if (headers['cf-ray']) tech.push({ category: 'cdn', name: 'Cloudflare', version: '' });
    if (headers['x-served-by'] && /cache/i.test(headers['x-served-by'])) tech.push({ category: 'cdn', name: 'Fastly', version: '' });

    const powered = headers['x-powered-by'];
    if (powered) {
      if (/php/i.test(powered)) tech.push({ category: 'server', name: 'PHP', version: powered.replace(/php\/?/i, '') });
      else if (/express/i.test(powered)) tech.push({ category: 'server', name: 'Express.js', version: '' });
      else if (/asp\.net/i.test(powered)) tech.push({ category: 'server', name: 'ASP.NET', version: '' });
      else tech.push({ category: 'server', name: powered, version: '' });
    }

    return tech;
  }

  /* ---------- Analyze security headers ---------- */
  function analyzeSecurityHeaders(headers) {
    if (!headers) return [];
    const issues = [];

    if (!headers['strict-transport-security']) {
      issues.push({ severity: 'medium', message: 'Missing HSTS header (Strict-Transport-Security)' });
    }
    if (!headers['content-security-policy']) {
      issues.push({ severity: 'medium', message: 'Missing Content-Security-Policy header' });
    }
    if (!headers['x-frame-options']) {
      issues.push({ severity: 'medium', message: 'Missing X-Frame-Options header — clickjacking possible' });
    }
    if (!headers['x-content-type-options']) {
      issues.push({ severity: 'low', message: 'Missing X-Content-Type-Options header' });
    }
    if (!headers['referrer-policy']) {
      issues.push({ severity: 'low', message: 'Missing Referrer-Policy header' });
    }
    if (headers['x-powered-by']) {
      issues.push({ severity: 'low', message: `Server exposes X-Powered-By: ${headers['x-powered-by']}` });
    }
    if (headers['server'] && /\d/.test(headers['server'])) {
      issues.push({ severity: 'low', message: `Server header reveals version: ${headers['server']}` });
    }

    return issues;
  }

  /* ---------- Full scan ---------- */
  async function fullScan(target, type, onProgress) {
    const results = {
      subdomains: null,
      dns: null,
      ip: null,
      ipInfo: null,
      headers: null,
      realTech: [],
      realAlerts: [],
    };

    const isDomain = type === 'domain';
    const isIP = type === 'ip';

    // Step 1: DNS + Subdomains
    if (isDomain) {
      onProgress('Querying DNS records...');
      results.dns = await getDNSRecords(target);

      onProgress('Enumerating subdomains via Certificate Transparency...');
      results.subdomains = await getSubdomains(target);

      onProgress('Resolving target IP...');
      results.ip = await resolveIP(target);
    }

    // Step 2: IP info
    const ipToCheck = isIP ? target : results.ip;
    if (ipToCheck) {
      onProgress('Fetching IP geolocation data...');
      results.ipInfo = await getIPInfo(ipToCheck);
    }

    // Step 3: HTTP headers + tech detection
    if (isDomain) {
      onProgress('Analyzing HTTP headers...');
      results.headers = await getHeaders(target);
      results.realTech = detectTechFromHeaders(results.headers);
      results.realAlerts = analyzeSecurityHeaders(results.headers);
    }

    return results;
  }

  /* ---------- Public API ---------- */
  return {
    getSubdomains,
    getDNSRecords,
    resolveIP,
    getIPInfo,
    getHeaders,
    detectTechFromHeaders,
    analyzeSecurityHeaders,
    fullScan,
  };

})();
