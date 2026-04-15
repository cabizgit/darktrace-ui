/* ============================================
   DATA-GENERATOR.JS — Deterministic fake data
   ============================================ */

'use strict';

const DataGen = (() => {

  /* ---------- Seeded Random ---------- */
  function seedHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return Math.abs(hash);
  }

  function seededRandom(seed) {
    let s = seed;
    return function() {
      s = (s * 16807 + 0) % 2147483647;
      return (s - 1) / 2147483646;
    };
  }

  function pick(arr, rng) {
    return arr[Math.floor(rng() * arr.length)];
  }

  function pickN(arr, n, rng) {
    const shuffled = [...arr].sort(() => rng() - 0.5);
    return shuffled.slice(0, Math.min(n, arr.length));
  }

  function randInt(min, max, rng) {
    return Math.floor(rng() * (max - min + 1)) + min;
  }

  function randIP(rng) {
    return `${randInt(1,254,rng)}.${randInt(0,255,rng)}.${randInt(0,255,rng)}.${randInt(1,254,rng)}`;
  }

  /* ---------- Data Pools ---------- */
  const SUBDOMAINS = [
    'admin', 'api', 'mail', 'webmail', 'ftp', 'vpn', 'dev', 'staging',
    'test', 'cdn', 'assets', 'static', 'app', 'dashboard', 'portal',
    'blog', 'docs', 'wiki', 'git', 'ci', 'jenkins', 'monitoring',
    'grafana', 'prometheus', 'elastic', 'kibana', 'db', 'redis',
    'queue', 'mq', 'auth', 'sso', 'id', 'login', 'secure',
    'backup', 'ns1', 'ns2', 'mx', 'smtp', 'imap', 'pop3'
  ];

  const TECH_STACKS = {
    server: [
      { name: 'Nginx', versions: ['1.24.0', '1.25.3', '1.26.0'] },
      { name: 'Apache', versions: ['2.4.57', '2.4.58', '2.4.59'] },
      { name: 'LiteSpeed', versions: ['6.1', '6.2'] },
      { name: 'Caddy', versions: ['2.7.5', '2.7.6'] },
      { name: 'IIS', versions: ['10.0', '10.1'] },
    ],
    frontend: [
      { name: 'React', versions: ['18.2.0', '18.3.1', '19.0.0'] },
      { name: 'Vue.js', versions: ['3.4.15', '3.5.0'] },
      { name: 'Next.js', versions: ['14.1.0', '14.2.3', '15.0.0'] },
      { name: 'Angular', versions: ['17.1', '17.2', '18.0'] },
      { name: 'jQuery', versions: ['3.7.1', '3.6.0'] },
      { name: 'Svelte', versions: ['4.2.8', '5.0.0'] },
    ],
    cms: [
      { name: 'WordPress', versions: ['6.4.2', '6.5.0', '6.6.0'] },
      { name: 'Drupal', versions: ['10.2', '10.3'] },
      { name: 'Ghost', versions: ['5.74', '5.80'] },
      { name: 'Strapi', versions: ['4.20', '5.0'] },
    ],
    cdn: [
      { name: 'Cloudflare', versions: [''] },
      { name: 'AWS CloudFront', versions: [''] },
      { name: 'Fastly', versions: [''] },
      { name: 'Akamai', versions: [''] },
    ],
    analytics: [
      { name: 'Google Analytics', versions: ['GA4'] },
      { name: 'Matomo', versions: ['5.0'] },
      { name: 'Plausible', versions: ['2.0'] },
      { name: 'Hotjar', versions: [''] },
    ]
  };

  const ALERTS = {
    critical: [
      'SQL injection vulnerability detected on login endpoint',
      'Exposed admin panel with default credentials',
      'Unpatched CVE-2024-3094 (XZ Utils backdoor) detected',
      'Database dump publicly accessible',
      'Remote code execution vulnerability in outdated CMS',
    ],
    high: [
      'SSL certificate expired 14 days ago',
      'Open redirect vulnerability on authentication flow',
      'Directory listing enabled on /backup/',
      'Sensitive headers exposed (X-Powered-By, Server version)',
      'CORS misconfiguration allows credential theft',
      'Exposed .git directory with source code',
    ],
    medium: [
      'Missing Content-Security-Policy header',
      'Cookies without Secure and HttpOnly flags',
      'Outdated TLS 1.0 still supported',
      'Missing rate limiting on API endpoints',
      'Clickjacking possible — X-Frame-Options not set',
    ],
    low: [
      'DNS zone transfer allowed',
      'HSTS header not configured',
      'Missing Referrer-Policy header',
      'Robots.txt reveals admin paths',
      'Email addresses found in HTML source',
    ]
  };

  const FEED_EVENTS = [
    { type: 'DNS', msg: 'A record query for {target}' },
    { type: 'DNS', msg: 'MX record resolved → mail.{target}' },
    { type: 'DNS', msg: 'CNAME lookup for cdn.{target}' },
    { type: 'HTTP', msg: 'GET /api/v1/status → 200 OK' },
    { type: 'HTTP', msg: 'POST /auth/login → 302 redirect' },
    { type: 'HTTP', msg: 'GET /robots.txt → 200 (164 bytes)' },
    { type: 'HTTP', msg: 'HEAD / → 200 (server: {server})' },
    { type: 'TCP', msg: 'SYN scan port {port} → open' },
    { type: 'TCP', msg: 'Connection to {ip}:{port} established' },
    { type: 'TCP', msg: 'FIN received from {ip}' },
    { type: 'SSL', msg: 'TLS handshake with {target} (TLS 1.3)' },
    { type: 'SSL', msg: 'Certificate chain verified (Let\'s Encrypt)' },
    { type: 'SSL', msg: 'OCSP stapling response validated' },
    { type: 'ALERT', msg: 'Anomalous traffic pattern detected from {ip}' },
    { type: 'DNS', msg: 'TXT record SPF policy retrieved' },
    { type: 'HTTP', msg: 'GET /sitemap.xml → 200 OK' },
    { type: 'TCP', msg: 'RST received on port {port}' },
    { type: 'HTTP', msg: 'GET /.well-known/security.txt → 404' },
  ];

  const LEAK_SOURCES = [
    'LinkedIn Data Breach (2024)',
    'Dark Web Forum Paste',
    'Pastebin Dump',
    'Credential Stuffing List',
    'Phishing Campaign Database',
    'Exposed S3 Bucket',
    'GitHub Repository Leak',
    'MongoDB Instance (no auth)',
  ];

  const PORTS = [
    { port: 21, service: 'FTP', common: true },
    { port: 22, service: 'SSH', common: true },
    { port: 25, service: 'SMTP', common: true },
    { port: 53, service: 'DNS', common: true },
    { port: 80, service: 'HTTP', common: true },
    { port: 110, service: 'POP3', common: false },
    { port: 143, service: 'IMAP', common: false },
    { port: 443, service: 'HTTPS', common: true },
    { port: 993, service: 'IMAPS', common: false },
    { port: 995, service: 'POP3S', common: false },
    { port: 3306, service: 'MySQL', common: false },
    { port: 5432, service: 'PostgreSQL', common: false },
    { port: 6379, service: 'Redis', common: false },
    { port: 8080, service: 'HTTP-Alt', common: true },
    { port: 8443, service: 'HTTPS-Alt', common: false },
    { port: 9090, service: 'WebSocket', common: false },
    { port: 27017, service: 'MongoDB', common: false },
  ];

  const FIRST_NAMES = ['james', 'maria', 'john', 'anna', 'marco', 'sarah', 'david', 'emma', 'alex', 'laura', 'michael', 'sofia', 'robert', 'elena', 'daniel'];
  const LAST_NAMES = ['smith', 'rossi', 'johnson', 'garcia', 'brown', 'martinez', 'jones', 'wilson', 'anderson', 'taylor', 'thomas', 'moore', 'white', 'harris'];

  /* ---------- Generate Functions ---------- */

  function generateSubdomains(target, rng, deep) {
    const count = deep ? randInt(8, 16, rng) : randInt(3, 7, rng);
    const subs = pickN(SUBDOMAINS, count, rng);
    return subs.map(sub => ({
      name: `${sub}.${target}`,
      ip: randIP(rng),
    }));
  }

  function generateTechStack(rng, deep) {
    const result = [];
    const categories = Object.keys(TECH_STACKS);
    const numCats = deep ? randInt(3, 5, rng) : randInt(2, 4, rng);
    const selectedCats = pickN(categories, numCats, rng);

    selectedCats.forEach(cat => {
      const tech = pick(TECH_STACKS[cat], rng);
      const version = pick(tech.versions, rng);
      result.push({
        category: cat,
        name: tech.name,
        version: version,
      });
    });

    return result;
  }

  function generateAlerts(rng, deep) {
    const result = [];
    const severities = ['critical', 'high', 'medium', 'low'];

    severities.forEach(sev => {
      const count = sev === 'critical'
        ? (rng() > 0.6 ? 1 : 0)
        : sev === 'high'
        ? randInt(deep ? 1 : 0, deep ? 3 : 2, rng)
        : randInt(1, deep ? 4 : 2, rng);

      const msgs = pickN(ALERTS[sev], count, rng);
      msgs.forEach(msg => {
        result.push({ severity: sev, message: msg });
      });
    });

    return result;
  }

  function generateLeaks(target, rng, deep) {
    const count = deep ? randInt(5, 12, rng) : randInt(2, 6, rng);
    const domain = target.includes('.') ? target : target + '.com';
    const result = [];

    for (let i = 0; i < count; i++) {
      const first = pick(FIRST_NAMES, rng);
      const last = pick(LAST_NAMES, rng);
      const patterns = [
        `${first}.${last}@${domain}`,
        `${first[0]}${last}@${domain}`,
        `${first}@${domain}`,
        `${first}${last[0]}@${domain}`,
      ];
      result.push({
        email: pick(patterns, rng),
        source: pick(LEAK_SOURCES, rng),
        date: `${randInt(2020, 2025, rng)}-${String(randInt(1,12,rng)).padStart(2,'0')}`,
      });
    }

    return result;
  }

  function generatePorts(rng, deep) {
    const count = deep ? randInt(6, 12, rng) : randInt(3, 7, rng);
    const selected = pickN(PORTS, count, rng);
    return selected.map(p => ({
      ...p,
      status: rng() > 0.2 ? 'open' : 'filtered',
    })).sort((a, b) => a.port - b.port);
  }

  function generateFeedEvent(target, rng) {
    const evt = pick(FEED_EVENTS, rng);
    let msg = evt.msg
      .replace('{target}', target)
      .replace('{ip}', randIP(rng))
      .replace('{port}', String(pick(PORTS, rng).port))
      .replace('{server}', pick(TECH_STACKS.server, rng).name);

    const now = new Date();
    const time = now.toTimeString().slice(0, 8);

    return {
      time,
      type: evt.type,
      message: msg,
    };
  }

  function generateRiskScore(alerts) {
    let score = 0;
    alerts.forEach(a => {
      if (a.severity === 'critical') score += 30;
      else if (a.severity === 'high') score += 15;
      else if (a.severity === 'medium') score += 5;
      else score += 1;
    });
    return Math.min(score, 100);
  }

  function getRiskLevel(score) {
    if (score >= 60) return 'CRITICAL';
    if (score >= 40) return 'HIGH';
    if (score >= 20) return 'MEDIUM';
    return 'LOW';
  }

  /* ---------- Terminal Lines ---------- */
  function getScanLines(target, type, deep) {
    const lines = [
      { text: `[*] Initializing DarkTrace scanner v2.4.1...`, cls: '' },
      { text: `[*] Target: ${target}`, cls: 'line-accent' },
      { text: `[*] Scan type: ${type.toUpperCase()}`, cls: '' },
      { text: `[*] Mode: ${deep ? 'DEEP SCAN' : 'STANDARD'}`, cls: deep ? 'line-warn' : '' },
      { text: `[+] Resolving target DNS records...`, cls: '' },
      { text: `[+] DNS A record found`, cls: 'line-accent' },
      { text: `[+] Starting subdomain enumeration...`, cls: '' },
      { text: `[+] Probing ${deep ? '40,000' : '10,000'} subdomain candidates...`, cls: '' },
      { text: `[+] Running port scan (SYN)...`, cls: '' },
      { text: `[+] Fingerprinting web technologies...`, cls: 'line-info' },
      { text: `[+] Checking SSL/TLS configuration...`, cls: '' },
      { text: `[+] Analyzing HTTP security headers...`, cls: '' },
      { text: `[!] Potential vulnerabilities detected`, cls: 'line-warn' },
      { text: `[+] Querying breach databases...`, cls: '' },
      { text: `[+] Correlating OSINT data sources...`, cls: 'line-info' },
    ];

    if (deep) {
      lines.push(
        { text: `[+] Running deep directory bruteforce...`, cls: 'line-warn' },
        { text: `[+] Analyzing JavaScript bundles...`, cls: '' },
        { text: `[+] Checking for exposed API endpoints...`, cls: '' },
        { text: `[+] Scanning for misconfigured cloud assets...`, cls: 'line-info' },
        { text: `[!] Sensitive data exposure detected`, cls: 'line-error' },
      );
    }

    lines.push(
      { text: `[+] Generating threat assessment...`, cls: '' },
      { text: `[*] Scan complete. Building dashboard...`, cls: 'line-accent' },
    );

    return lines;
  }

  /* ---------- Public API ---------- */
  return {
    seedHash,
    seededRandom,
    generateSubdomains,
    generateTechStack,
    generateAlerts,
    generateLeaks,
    generatePorts,
    generateFeedEvent,
    generateRiskScore,
    getRiskLevel,
    getScanLines,
  };

})();
