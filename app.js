/* ============================================
   APP.JS — DarkTrace UI Application
   ============================================ */

'use strict';

const App = (() => {

  /* ---------- State ---------- */
  let target = '';
  let scanType = 'domain';
  let deepScan = false;
  let rng = null;
  let scanData = {};
  let apiData = {};
  let feedInterval = null;
  let networkChart = null;
  let threatChart = null;
  let audioEnabled = false;
  let audioCtx = null;

  /* ---------- DOM Refs ---------- */
  const $ = id => document.getElementById(id);

  /* ---------- Clock ---------- */
  function updateClock() {
    const el = $('header-clock');
    if (el) el.textContent = new Date().toTimeString().slice(0, 8);
  }
  setInterval(updateClock, 1000);
  updateClock();

  /* ---------- Audio ---------- */
  function playBeep(freq, duration) {
    if (!audioEnabled) return;
    try {
      if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.frequency.value = freq || 800;
      gain.gain.value = 0.05;
      osc.start();
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + (duration || 0.1));
      osc.stop(audioCtx.currentTime + (duration || 0.1));
    } catch(e) {}
  }

  /* ---------- Form ---------- */
  function initForm() {
    const form = $('scan-form');
    const chips = document.querySelectorAll('.option-chip');

    chips.forEach(chip => {
      chip.addEventListener('click', () => {
        chips.forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
      });
    });

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = $('target-input');
      target = input.value.trim();
      if (!target) return;

      scanType = document.querySelector('input[name="scan-type"]:checked').value;
      deepScan = $('deep-scan').checked;
      startScan();
    });

    $('new-scan-btn').addEventListener('click', resetDashboard);

    $('audio-toggle').addEventListener('click', function() {
      audioEnabled = !audioEnabled;
      this.classList.toggle('active', audioEnabled);
      if (audioEnabled) playBeep(1200, 0.05);
    });
  }

  /* ---------- Scan ---------- */
  async function startScan() {
    const seed = DataGen.seedHash(target + scanType);
    rng = DataGen.seededRandom(seed);

    $('landing').classList.add('hidden');
    $('dashboard').classList.remove('hidden');
    $('scan-overlay').classList.remove('hidden');

    const statusEl = $('header-status');
    statusEl.innerHTML = '<span class="status-dot scanning"></span><span>SCANNING</span>';

    // Generate simulated data as baseline
    scanData = {
      subdomains: DataGen.generateSubdomains(target, rng, deepScan),
      techStack: DataGen.generateTechStack(rng, deepScan),
      alerts: DataGen.generateAlerts(rng, deepScan),
      leaks: DataGen.generateLeaks(target, rng, deepScan),
      ports: DataGen.generatePorts(rng, deepScan),
    };

    // Run terminal + real API calls in parallel
    const terminalLines = DataGen.getScanLines(target, scanType, deepScan);

    // Add real API lines to terminal
    const apiLines = [
      { text: '[+] Connecting to real OSINT sources...', cls: 'line-info' },
      { text: '[+] Querying crt.sh Certificate Transparency...', cls: 'line-info' },
      { text: '[+] Resolving DNS via Google DoH...', cls: 'line-info' },
      { text: '[+] Fetching HTTP headers...', cls: 'line-info' },
    ];
    terminalLines.splice(-2, 0, ...apiLines);

    // Start API calls
    const apiPromise = API.fullScan(target, scanType, () => {});

    // Run terminal animation
    await new Promise(resolve => {
      runTerminalAnimation(terminalLines, resolve);
    });

    // Wait for API results
    try {
      apiData = await apiPromise;
    } catch(e) {
      apiData = {};
    }

    // Merge real data with simulated
    mergeRealData();

    $('scan-overlay').classList.add('hidden');
    statusEl.innerHTML = '<span class="status-dot active"></span><span>MONITORING</span>';
    renderDashboard();
  }

  function mergeRealData() {
    // Real subdomains override simulated
    if (apiData.subdomains && apiData.subdomains.length > 0) {
      scanData.subdomainsReal = true;
      scanData.subdomains = apiData.subdomains.map(s => ({
        name: s.name,
        ip: '',
        source: 'crt.sh',
      }));

      // Try to resolve IPs for first few subdomains
      scanData.subdomains.forEach(s => {
        s.ip = '—';
      });
    }

    // Real tech from headers
    if (apiData.realTech && apiData.realTech.length > 0) {
      // Prepend real tech, mark them
      const realTech = apiData.realTech.map(t => ({ ...t, real: true }));
      const simTech = scanData.techStack.filter(st =>
        !realTech.some(rt => rt.name.toLowerCase() === st.name.toLowerCase())
      );
      scanData.techStack = [...realTech, ...simTech];
    }

    // Real security alerts from headers
    if (apiData.realAlerts && apiData.realAlerts.length > 0) {
      const realAlerts = apiData.realAlerts.map(a => ({ ...a, real: true }));
      scanData.alerts = [...realAlerts, ...scanData.alerts];
    }

    // Recalculate risk
    scanData.riskScore = DataGen.generateRiskScore(scanData.alerts);
    scanData.riskLevel = DataGen.getRiskLevel(scanData.riskScore);
  }

  /* ---------- Terminal Animation ---------- */
  function runTerminalAnimation(lines, onComplete) {
    const terminal = $('scan-terminal');
    const progressFill = $('scan-progress-fill');
    const progressText = $('scan-progress-text');
    terminal.innerHTML = '';

    let i = 0;
    const total = lines.length;
    const baseDelay = deepScan ? 180 : 130;

    function nextLine() {
      if (i >= total) {
        progressFill.style.width = '100%';
        progressText.textContent = 'Scan complete.';
        setTimeout(onComplete, 500);
        return;
      }

      const line = lines[i];
      const el = document.createElement('div');
      el.className = line.cls || '';
      el.textContent = line.text;
      terminal.appendChild(el);
      terminal.scrollTop = terminal.scrollHeight;

      const pct = Math.round(((i + 1) / total) * 100);
      progressFill.style.width = pct + '%';
      progressText.textContent = `Scanning... ${pct}%`;

      playBeep(600 + Math.random() * 400, 0.03);
      i++;
      setTimeout(nextLine, baseDelay + Math.random() * 120);
    }

    nextLine();
  }

  /* ---------- Render Dashboard ---------- */
  function renderDashboard() {
    $('dash-target').textContent = target;
    $('dash-type').textContent = scanType.toUpperCase();
    $('dash-mode').textContent = deepScan ? 'DEEP SCAN' : 'STANDARD';

    const riskEl = $('dash-risk');
    riskEl.textContent = `RISK: ${scanData.riskLevel} (${scanData.riskScore}/100)`;

    renderSubdomains();
    renderTechStack();
    renderAlerts();
    renderDNS();
    renderIPInfo();
    renderLeaks();
    renderPorts();
    renderNetworkChart();
    renderThreatChart();
    startLiveFeed();
  }

  /* ---------- Subdomains ---------- */
  function renderSubdomains() {
    const list = $('subdomain-list');
    const countEl = $('subdomain-count');
    const sourceEl = $('subdomain-source');

    countEl.textContent = scanData.subdomains.length;
    list.innerHTML = '';

    if (scanData.subdomainsReal) {
      sourceEl.style.display = '';
      sourceEl.style.background = 'rgba(0,180,255,0.15)';
      sourceEl.style.color = '#00b4ff';
      sourceEl.textContent = 'LIVE';
    } else {
      sourceEl.style.display = '';
      sourceEl.style.background = 'rgba(255,213,0,0.15)';
      sourceEl.style.color = '#ffd500';
      sourceEl.textContent = 'SIM';
    }

    scanData.subdomains.forEach((sub, i) => {
      const el = document.createElement('div');
      el.className = 'sub-item';
      el.style.animationDelay = (i * 0.04) + 's';
      el.innerHTML = `<span class="sub-name">${sub.name}</span><span class="sub-ip">${sub.ip || ''}</span>`;
      list.appendChild(el);
    });
  }

  /* ---------- Tech Stack ---------- */
  function renderTechStack() {
    const list = $('techstack-list');
    list.innerHTML = '';

    scanData.techStack.forEach((tech, i) => {
      const el = document.createElement('div');
      el.className = 'tech-item';
      el.style.animationDelay = (i * 0.05) + 's';
      const realBadge = tech.real ? ' <span style="font-size:0.55rem;color:#00b4ff;margin-left:4px;">REAL</span>' : '';
      el.innerHTML = `
        <span class="tech-badge ${tech.category}">${tech.category}</span>
        <span class="tech-name">${tech.name}${realBadge}</span>
        <span class="tech-version">${tech.version || ''}</span>
      `;
      list.appendChild(el);
    });
  }

  /* ---------- Alerts ---------- */
  function renderAlerts() {
    const list = $('alert-list');
    $('alert-count').textContent = scanData.alerts.length;
    list.innerHTML = '';

    scanData.alerts.forEach((alert, i) => {
      const el = document.createElement('div');
      el.className = `alert-item ${alert.severity}`;
      el.style.animationDelay = (i * 0.06) + 's';
      const realTag = alert.real ? '<span style="font-size:0.55rem;color:#00b4ff;margin-left:6px;font-weight:700;">[REAL]</span>' : '';
      el.innerHTML = `
        <span class="alert-severity">${alert.severity}</span>
        <span class="alert-msg">${alert.message}${realTag}</span>
      `;
      list.appendChild(el);
    });
  }

  /* ---------- DNS Records ---------- */
  function renderDNS() {
    const list = $('dns-list');
    list.innerHTML = '';

    if (apiData.dns) {
      Object.keys(apiData.dns).forEach(type => {
        apiData.dns[type].forEach((record, i) => {
          const el = document.createElement('div');
          el.className = 'sub-item';
          el.style.animationDelay = (i * 0.04) + 's';
          el.innerHTML = `
            <span class="tech-badge server" style="min-width:40px;text-align:center;">${type}</span>
            <span class="sub-name" style="flex:1;margin-left:8px;word-break:break-all;">${record.data}</span>
            <span class="sub-ip">TTL ${record.ttl}</span>
          `;
          list.appendChild(el);
        });
      });
    } else {
      list.innerHTML = '<div style="color:var(--text-dim);font-size:0.75rem;padding:8px 0;">DNS data not available for this target.</div>';
    }
  }

  /* ---------- IP Info ---------- */
  function renderIPInfo() {
    const list = $('ipinfo-list');
    list.innerHTML = '';

    if (apiData.ipInfo) {
      const info = apiData.ipInfo;
      const fields = [
        { label: 'IP Address', value: info.query },
        { label: 'Location', value: `${info.city}, ${info.regionName}, ${info.country}` },
        { label: 'ISP', value: info.isp },
        { label: 'Organization', value: info.org },
        { label: 'AS Number', value: info.as },
      ];

      fields.forEach((f, i) => {
        if (!f.value) return;
        const el = document.createElement('div');
        el.className = 'sub-item';
        el.style.animationDelay = (i * 0.05) + 's';
        el.innerHTML = `
          <span class="sub-ip" style="min-width:100px;">${f.label}</span>
          <span class="sub-name">${f.value}</span>
        `;
        list.appendChild(el);
      });
    } else if (apiData.ip) {
      list.innerHTML = `<div style="color:var(--text-secondary);font-size:0.75rem;padding:8px 0;">Resolved IP: <span style="color:var(--accent);">${apiData.ip}</span></div>`;
    } else {
      list.innerHTML = '<div style="color:var(--text-dim);font-size:0.75rem;padding:8px 0;">IP intelligence not available.</div>';
    }
  }

  /* ---------- Leaks ---------- */
  function renderLeaks() {
    const list = $('leak-list');
    $('leak-count').textContent = scanData.leaks.length;
    list.innerHTML = '';

    scanData.leaks.forEach((leak, i) => {
      const el = document.createElement('div');
      el.className = 'leak-item';
      el.style.animationDelay = (i * 0.05) + 's';
      el.innerHTML = `
        <div class="leak-email">${leak.email}</div>
        <div class="leak-source">${leak.source} &bull; ${leak.date}</div>
      `;
      list.appendChild(el);
    });
  }

  /* ---------- Ports ---------- */
  function renderPorts() {
    const list = $('port-list');
    list.innerHTML = '';

    scanData.ports.forEach((port, i) => {
      const el = document.createElement('div');
      el.className = 'port-item';
      el.style.animationDelay = (i * 0.05) + 's';
      el.innerHTML = `
        <span class="port-num">:${port.port}</span>
        <span class="port-service">${port.service}</span>
        <span class="port-status ${port.status}">${port.status.toUpperCase()}</span>
      `;
      list.appendChild(el);
    });
  }

  /* ---------- Charts ---------- */
  function renderNetworkChart() {
    const ctx = $('network-chart');
    if (!ctx) return;

    const labels = [];
    const data = [];
    const now = new Date();
    for (let i = 30; i >= 0; i--) {
      const t = new Date(now - i * 2000);
      labels.push(t.toTimeString().slice(0, 8));
      data.push(Math.floor(Math.random() * 60) + 10);
    }

    if (networkChart) networkChart.destroy();

    networkChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Packets/s',
          data,
          borderColor: '#00ff88',
          backgroundColor: 'rgba(0, 255, 136, 0.05)',
          borderWidth: 1.5,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        scales: {
          x: {
            ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 9 }, maxTicksLimit: 6 },
            grid: { color: 'rgba(255,255,255,0.03)' },
          },
          y: {
            ticks: { color: '#475569', font: { family: 'JetBrains Mono', size: 9 } },
            grid: { color: 'rgba(255,255,255,0.03)' },
          }
        },
        plugins: { legend: { display: false } }
      }
    });

    setInterval(() => {
      if (!networkChart) return;
      networkChart.data.labels.push(new Date().toTimeString().slice(0, 8));
      networkChart.data.labels.shift();
      networkChart.data.datasets[0].data.push(Math.floor(Math.random() * 60) + 10);
      networkChart.data.datasets[0].data.shift();
      networkChart.update('none');
    }, 2000);
  }

  function renderThreatChart() {
    const ctx = $('threat-chart');
    if (!ctx) return;

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    scanData.alerts.forEach(a => counts[a.severity]++);

    if (threatChart) threatChart.destroy();

    threatChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [counts.critical, counts.high, counts.medium, counts.low],
          backgroundColor: ['rgba(255,59,92,0.8)', 'rgba(255,140,0,0.8)', 'rgba(255,213,0,0.8)', 'rgba(0,180,255,0.8)'],
          borderColor: '#111827',
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, padding: 12, usePointStyle: true, pointStyleWidth: 8 }
          }
        }
      }
    });
  }

  /* ---------- Live Feed ---------- */
  function startLiveFeed() {
    if (feedInterval) clearInterval(feedInterval);
    const feed = $('activity-feed');
    feed.innerHTML = '';

    function addEvent() {
      const liveRng = DataGen.seededRandom(Date.now());
      const evt = DataGen.generateFeedEvent(target, liveRng);

      const el = document.createElement('div');
      el.className = 'feed-item';
      el.innerHTML = `
        <span class="feed-time">${evt.time}</span>
        <span class="feed-type ${evt.type.toLowerCase()}">${evt.type}</span>
        <span class="feed-msg">${evt.message}</span>
      `;
      feed.prepend(el);
      while (feed.children.length > 50) feed.removeChild(feed.lastChild);
      playBeep(400 + Math.random() * 200, 0.02);
    }

    for (let i = 0; i < 8; i++) addEvent();
    feedInterval = setInterval(addEvent, 1500 + Math.random() * 1500);
  }

  /* ---------- Reset ---------- */
  function resetDashboard() {
    if (feedInterval) { clearInterval(feedInterval); feedInterval = null; }
    if (networkChart) { networkChart.destroy(); networkChart = null; }
    if (threatChart) { threatChart.destroy(); threatChart = null; }

    $('dashboard').classList.add('hidden');
    $('landing').classList.remove('hidden');
    $('target-input').value = '';
    $('target-input').focus();

    $('header-status').innerHTML = '<span class="status-dot idle"></span><span>SYSTEM IDLE</span>';
    apiData = {};
  }

  /* ---------- Init ---------- */
  document.addEventListener('DOMContentLoaded', () => {
    initForm();
    $('target-input').focus();
  });

})();
