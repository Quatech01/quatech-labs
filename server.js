'use strict';
require('dotenv').config();
const express = require('express');
const path    = require('path');
const fs      = require('fs');
const http    = require('http');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { spawn } = require('child_process');

const app      = express();
const TOOLS_DIR = path.join(__dirname, 'tools');
const BASE      = '/tools';

app.use(express.json());

// ── Tool registry ────────────────────────────────────────────────────────────
const TOOLS = [
  { id:1,  slug:'xss-reflection-scanner',           title:'XSS Reflection Scanner',            category:'web_security',                lang:'node', repo:'cyberlab-xss-reflection-scanner' },
  { id:2,  slug:'port-scanner-service-fingerprinting', title:'Port Scanner & Service Fingerprinting', category:'network_security',           lang:'node', repo:'cyberlab-port-scanner-service-fingerprinting' },
  { id:3,  slug:'sql-injection-detector',            title:'SQL Injection Detector',             category:'web_security',                lang:'node', repo:'cyberlab-sql-injection-detector' },
  { id:4,  slug:'hash-collision-demonstrator',       title:'Hash Collision Demonstrator',        category:'cryptography',                lang:'node', repo:'cyberlab-hash-collision-demonstrator' },
  { id:5,  slug:'brute-force-rate-limiter-demo',     title:'Brute Force Rate Limiter Demo',      category:'authentication_and_access',   lang:'node', repo:'cyberlab-brute-force-rate-limiter-demo' },
  { id:6,  slug:'file-entropy-analyzer',             title:'File Entropy Analyzer',              category:'malware_analysis',            lang:'node', repo:'cyberlab-file-entropy-analyzer' },
  { id:7,  slug:'csrf-token-validator',              title:'CSRF Token Validator',               category:'web_security',                lang:'node', repo:'cyberlab-csrf-token-validator' },
  { id:8,  slug:'aes-encryption-mode-comparison',   title:'AES Encryption Mode Comparison',     category:'cryptography',                lang:'node', repo:'cyberlab-aes-encryption-mode-comparison' },
  { id:9,  slug:'input-sanitization-library',       title:'Input Sanitization Library',         category:'secure_coding',               lang:'node', repo:'cyberlab-input-sanitization-library' },
  { id:10, slug:'log-file-anomaly-detector',         title:'Log File Anomaly Detector',          category:'malware_analysis',            lang:'node', repo:'cyberlab-log-file-anomaly-detector' },
  { id:11, slug:'jwt-vulnerability-scanner',         title:'JWT Vulnerability Scanner',          category:'cryptography',                lang:'python', repo:'cyberlab-jwt-vulnerability-scanner' },
  { id:12, slug:'http-security-header-auditor',      title:'HTTP Security Header Auditor',       category:'web_security',                lang:'node', repo:'cyberlab-http-security-header-auditor' },
  { id:13, slug:'keylogger-detection-and-flagging',  title:'Keylogger Detection & Flagging',     category:'malware_analysis',            lang:'python', repo:'cyberlab-keylogger-detection-and-flagging' },
  { id:14, slug:'dns-record-analyzer',               title:'DNS Record Analyzer',                category:'network_security',            lang:'node', repo:'cyberlab-dns-record-analyzer' },
  { id:15, slug:'email-header-analyzer',             title:'Email Header Analyzer',              category:'osint_and_recon',             lang:'python', repo:'cyberlab-email-header-analyzer' },
  { id:16, slug:'oauth-pkce-flow-analyzer',          title:'OAuth 2.0 PKCE Flow Analyzer',       category:'authentication_and_access',   lang:'node', repo:'cyberlab-oauth-pkce-flow-analyzer' },
  { id:17, slug:'timing-attack-demonstrator',        title:'Timing Attack Demonstrator',         category:'cryptography',                lang:'python', repo:'cyberlab-timing-attack-demonstrator' },
  { id:18, slug:'open-redirect-checker',             title:'Open Redirect Checker',              category:'web_security',                lang:'node', repo:'cyberlab-open-redirect-checker' },
  { id:19, slug:'soc-tier1-alert-triage-simulator',  title:'SOC Tier 1 Alert Triage Simulator',  category:'malware_analysis',            lang:'python', repo:'cyberlab-soc-tier1-alert-triage-simulator' },
  { id:20, slug:'directory-traversal-detector',      title:'Directory Traversal Detector',       category:'web_security',                lang:'node', repo:'cyberlab-directory-traversal-detector' },
  { id:21, slug:'session-fixation-demonstrator',     title:'Session Fixation Vulnerability Demo', category:'authentication_and_access',  lang:'python', repo:'cyberlab-session-fixation-demonstrator' },
  { id:23, slug:'subdomain-enumerator',              title:'Subdomain Enumerator',               category:'osint_and_recon',             lang:'python', repo:'cyberlab-subdomain-enumerator' },
  { id:24, slug:'gp-appointment-booking-system',     title:'GP Appointment Booking System',      category:'uk_applications',             lang:'node', repo:'cyberlab-gp-appointment-booking-system' },
  { id:25, slug:'hash-generator-authenticator',      title:'Hash Generator & Authenticator',     category:'cryptography',                lang:'node', repo:'cyberlab-hash-generator-authenticator' },
  { id:26, slug:'form-platform',                     title:'Form Platform',                      category:'secure_coding',               lang:'node', repo:'cyberlab-form-platform' },
  { id:27, slug:'totp-demo',                         title:'TOTP Two-Factor Auth Demo',          category:'authentication_and_access',   lang:'node', repo:'cyberlab-totp-demo' },
  { id:28, slug:'tls-inspector',                     title:'TLS/SSL Certificate Inspector',      category:'network_security',            lang:'node', repo:'cyberlab-tls-inspector' },
];

// ── Python lazy-process manager ───────────────────────────────────────────────
const pyProcs  = {};
let nextPyPort = 3100;

function ensurePython(slug, toolPath, cb) {
  let info = pyProcs[slug];
  if (!info) {
    info = { port: nextPyPort++, proc: null, lastUsed: 0 };
    pyProcs[slug] = info;
  }
  info.lastUsed = Date.now();

  if (info.proc && info.proc.exitCode === null) return cb(null, info.port);

  // Start uvicorn
  info.proc = spawn('uvicorn', ['main:app', '--port', String(info.port), '--host', '127.0.0.1', '--log-level', 'error'], {
    cwd: toolPath, env: { ...process.env }
  });
  info.proc.on('error', err => cb(err));

  // Poll until ready (max 15s)
  const deadline = Date.now() + 15000;
  const poll = () => {
    if (Date.now() > deadline) return cb(new Error('uvicorn startup timeout'));
    const req = http.get(`http://127.0.0.1:${info.port}/`, () => { cb(null, info.port); });
    req.on('error', () => setTimeout(poll, 600));
    req.end();
  };
  setTimeout(poll, 1200);
}

// Kill idle Python processes every minute
setInterval(() => {
  const idle = 5 * 60 * 1000;
  for (const [slug, info] of Object.entries(pyProcs)) {
    if (info.proc && Date.now() - info.lastUsed > idle) {
      info.proc.kill();
      info.proc = null;
      console.log(`[labs] stopped idle python tool: ${slug}`);
    }
  }
}, 60000);

// ── Resolve tool entry point ──────────────────────────────────────────────────
function resolveToolPaths(toolPath) {
  // Layout A: server.js at root
  if (fs.existsSync(path.join(toolPath, 'server.js')))
    return { serverFile: path.join(toolPath, 'server.js'), pubDir: path.join(toolPath, 'public') };
  // Layout B: server/index.js (older tools)
  if (fs.existsSync(path.join(toolPath, 'server', 'index.js')))
    return { serverFile: path.join(toolPath, 'server', 'index.js'), pubDir: path.join(toolPath, 'server', 'public') };
  // Layout C: index.js at root
  if (fs.existsSync(path.join(toolPath, 'index.js')))
    return { serverFile: path.join(toolPath, 'index.js'), pubDir: path.join(toolPath, 'public') };
  // Layout D: backend/index.js (fullstack — serve frontend/ as static)
  if (fs.existsSync(path.join(toolPath, 'backend', 'index.js')))
    return { serverFile: path.join(toolPath, 'backend', 'index.js'), pubDir: path.join(toolPath, 'frontend') };
  return {};
}

function extractApp(mod) {
  if (typeof mod === 'function') return mod;           // module.exports = app
  if (mod && typeof mod.app === 'function') return mod.app;  // module.exports = { app, ... }
  return null;
}

// Auto-generate a simple tool page from README.md when no public/index.html exists
function autoPage(tool, toolPath) {
  const readmePath = path.join(toolPath, 'README.md');
  const readme = fs.existsSync(readmePath) ? fs.readFileSync(readmePath, 'utf8') : '';
  // Pick first non-heading, non-empty paragraph lines, strip markdown syntax
  const rawDesc = readme.split('\n')
    .filter(l => l.trim() && !l.startsWith('#') && !l.startsWith('```') && !l.startsWith('|'))
    .slice(0, 4).join(' ')
    .replace(/\*\*(.+?)\*\*/g, '$1')   // **bold**
    .replace(/\*(.+?)\*/g, '$1')        // *italic*
    .replace(/`(.+?)`/g, '$1')          // `code`
    .replace(/\[(.+?)\]\(.+?\)/g, '$1') // [link](url)
    .replace(/#+\s*/g, '')              // stray headings
    .trim();
  // Truncate at a sentence boundary, max 300 chars
  let desc = rawDesc.length > 300 ? rawDesc.slice(0, 300) : rawDesc;
  const lastPeriod = desc.lastIndexOf('.');
  if (lastPeriod > 80) desc = desc.slice(0, lastPeriod + 1);
  return `<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${tool.title}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap">
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#2563eb;--green:#3fb950}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);max-width:860px;margin:0 auto;padding:32px 16px 60px}
a.back{color:var(--accent);text-decoration:none;font-size:.82rem;display:inline-flex;align-items:center;gap:4px;margin-bottom:28px;opacity:.8}
a.back:hover{opacity:1}
h1{font-size:1.5rem;font-weight:700;letter-spacing:-.02em;margin-bottom:10px}
.meta{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:20px}
.badge{display:inline-block;padding:3px 10px;border-radius:10px;font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.badge-node{background:#1a3a1a;color:var(--green);border:1px solid #234823}
.badge-python{background:#1a2a3a;color:#60a5fa;border:1px solid #1e3a5f}
.badge-gh{background:transparent;color:var(--muted);border:1px solid var(--border);text-decoration:none}
.badge-gh:hover{border-color:var(--accent);color:var(--text)}
.desc{color:var(--muted);line-height:1.7;margin-bottom:32px;font-size:.92rem}
/* Explorer */
.explorer{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:28px}
.explorer-header{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.explorer-header h2{font-size:.82rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px #3fb95055}
.input-row{display:flex;gap:0;padding:16px 18px;border-bottom:1px solid var(--border)}
.method{background:var(--surface2);border:1px solid var(--border);border-right:none;border-radius:6px 0 0 6px;padding:9px 14px;font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--green);font-weight:600;white-space:nowrap}
#path-input{flex:1;background:var(--surface2);border:1px solid var(--border);border-right:none;padding:9px 12px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:.8rem;outline:none}
#path-input:focus{border-color:var(--accent)}
button#send{background:var(--accent);border:none;border-radius:0 6px 6px 0;padding:9px 18px;color:#fff;font-size:.82rem;font-weight:600;cursor:pointer;white-space:nowrap}
button#send:hover{background:#1d4ed8}
.presets{padding:10px 18px;display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--border)}
.preset{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-family:'JetBrains Mono',monospace;font-size:.73rem;color:var(--muted);cursor:pointer;transition:all .15s}
.preset:hover{border-color:var(--accent);color:var(--text)}
.response-area{padding:18px;min-height:120px}
.resp-meta{font-size:.75rem;color:var(--muted);margin-bottom:10px;font-family:'JetBrains Mono',monospace;display:flex;gap:16px}
.status-ok{color:var(--green)} .status-err{color:#f85149}
pre#response{font-family:'JetBrains Mono',monospace;font-size:.78rem;line-height:1.6;color:var(--text);white-space:pre-wrap;word-break:break-all;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;overflow-x:auto;max-height:400px;overflow-y:auto}
.placeholder{color:var(--muted);font-size:.85rem;text-align:center;padding:20px 0;font-style:italic}
</style></head><body>
<a class="back" href="/">← Back to Cyberlab</a>
<h1>${tool.title}</h1>
<div class="meta">
  <span class="badge badge-${tool.lang}">${tool.lang === 'node' ? 'Node.js' : 'Python'}</span>
  <a class="badge badge-gh" href="https://github.com/Quatech01/${tool.repo}" target="_blank" rel="noopener">View on GitHub ↗</a>
</div>
<p class="desc">${desc || 'Interactive security lab tool.'}</p>

<div class="explorer">
  <div class="explorer-header"><span class="dot"></span><h2>API Explorer — try it live</h2></div>
  <div class="input-row">
    <span class="method">GET</span>
    <input id="path-input" type="text" value="/tools/${tool.slug}/health" placeholder="/tools/${tool.slug}/...">
    <button id="send">Send →</button>
  </div>
  <div class="presets" id="presets"></div>
  <div class="response-area">
    <div id="resp-meta" class="resp-meta" hidden></div>
    <pre id="response"><div class="placeholder">Hit Send to see the response</div></pre>
  </div>
</div>

<script>
const BASE = '/tools/${tool.slug}';
const PRESETS = ['/health'];

// Try to discover more endpoints from the page URL pattern
const extra = ${JSON.stringify(
  (() => {
    const readmePath2 = path.join(toolPath, 'README.md');
    if (!fs.existsSync(readmePath2)) return [];
    const lines = fs.readFileSync(readmePath2, 'utf8').split('\\n');
    const eps = [];
    for (const l of lines) {
      const m = l.match(/GET\\s+(\/[\\w\\-\\/{}:]+)/);
      if (m && !eps.includes(m[1]) && eps.length < 8) eps.push(m[1]);
    }
    return eps;
  })()
)};
const presets = [...new Set([...PRESETS, ...extra])];

const presetsEl = document.getElementById('presets');
presets.forEach(p => {
  const btn = document.createElement('button');
  btn.className = 'preset'; btn.textContent = p;
  btn.onclick = () => { document.getElementById('path-input').value = BASE + p.replace(/^\\/tools\\/[^/]+/, ''); send(); };
  presetsEl.appendChild(btn);
});

async function send() {
  const rawPath = document.getElementById('path-input').value.trim() || BASE + '/health';
  const url = rawPath.startsWith('/') ? rawPath : '/' + rawPath;
  const t0 = Date.now();
  const metaEl = document.getElementById('resp-meta');
  const respEl = document.getElementById('response');
  respEl.textContent = 'Loading…';
  metaEl.hidden = true;
  try {
    const res = await fetch(url);
    const ms = Date.now() - t0;
    const ct = res.headers.get('content-type') || '';
    let body;
    if (ct.includes('json')) {
      body = JSON.stringify(await res.json(), null, 2);
    } else {
      body = await res.text();
    }
    metaEl.hidden = false;
    metaEl.innerHTML = '<span class="' + (res.ok ? 'status-ok' : 'status-err') + '">' + res.status + ' ' + res.statusText + '</span><span>' + ms + 'ms</span><span>' + ct + '</span>';
    respEl.textContent = body;
  } catch(e) {
    metaEl.hidden = false;
    metaEl.innerHTML = '<span class="status-err">Network error</span>';
    respEl.textContent = e.message;
  }
}

document.getElementById('send').onclick = send;
document.getElementById('path-input').addEventListener('keydown', e => { if (e.key === 'Enter') send(); });
</script>
</body></html>`;
}

// ── Mount all tools ───────────────────────────────────────────────────────────
for (const tool of TOOLS) {
  const toolPath = path.join(TOOLS_DIR, tool.slug);
  const toolBase = `${BASE}/${tool.slug}`;

  if (!fs.existsSync(toolPath)) continue;

  const { serverFile, pubDir } = resolveToolPaths(toolPath);

  // Python main.py can be at root or inside server/
  const mainFile = fs.existsSync(path.join(toolPath, 'main.py'))
    ? path.join(toolPath, 'main.py')
    : fs.existsSync(path.join(toolPath, 'server', 'main.py'))
    ? path.join(toolPath, 'server', 'main.py')
    : null;

  // Some Python tools ship a separate frontend/ directory alongside the API
  const frontendDir = path.join(toolPath, 'frontend');

  // 1. Response interceptor: patch absolute /api/ → relative in any HTML the tool sends
  app.use(toolBase, (req, res, next) => {
    const origSend = res.send.bind(res);
    res.send = function(body) {
      if (typeof body === 'string' && (res.getHeader('content-type') || '').includes('html')) {
        body = body.replace(/(['"`])\/api\//g, '$1api/');
      }
      return origSend(body);
    };
    next();
  });

  // 2. Static files — pubDir (Node tools) and frontendDir (Python tools with a UI)
  if (pubDir && fs.existsSync(pubDir)) app.use(toolBase, express.static(pubDir));
  if (fs.existsSync(frontendDir)) app.use(toolBase, express.static(frontendDir));

  // 3. Tool app (its own root UI and API routes come first)
  if (tool.lang === 'python' && mainFile) {
    // Python tools don't serve a root UI — show auto-page for root unless a static index.html exists
    const hasFrontendIndex = fs.existsSync(path.join(frontendDir, 'index.html'));
    const hasPubIndex      = pubDir && fs.existsSync(path.join(pubDir, 'index.html'));
    if (!hasFrontendIndex && !hasPubIndex) {
      app.get([toolBase, `${toolBase}/`], (req, res) => {
        res.type('html').send(autoPage(tool, toolPath));
      });
    }
    app.use(toolBase, (req, res, next) => {
      ensurePython(tool.slug, path.dirname(mainFile), (err, port) => {
        if (err) return res.status(503).json({ error: 'Tool is starting, retry in a moment', retry_after: 5 });
        createProxyMiddleware({
          target: `http://127.0.0.1:${port}`,
          changeOrigin: true,
          on: { error: (e, req, res) => res.status(502).json({ error: 'Tool unavailable' }) },
        })(req, res, next);
      });
    });
  } else if (tool.lang === 'node' && serverFile) {
    try {
      const mod     = require(serverFile);
      const toolApp = extractApp(mod);
      if (toolApp) {
        app.use(toolBase, toolApp);
        console.log(`[labs] mounted: /tools/${tool.slug}`);
      } else {
        console.warn(`[labs] skipped (no app export): ${tool.slug}`);
      }
    } catch (e) {
      console.error(`[labs] failed to load ${tool.slug}: ${e.message}`);
    }
  }

  // 4. Fallback: only shown when the tool has no public/index.html and no root route
  app.get([toolBase, `${toolBase}/`], (req, res) => {
    res.type('html').send(autoPage(tool, toolPath));
  });
}

// ── API: tool listing ─────────────────────────────────────────────────────────
app.get('/api/tools', (req, res) => {
  res.json(TOOLS.map(t => ({
    ...t,
    url: `${BASE}/${t.slug}`,
    available: fs.existsSync(path.join(TOOLS_DIR, t.slug)),
  })));
});

// ── Landing page ──────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3011;
if (require.main === module) {
  app.listen(PORT, () => console.log(`[labs] Cyberlab Labs on http://localhost:${PORT}`));
}
module.exports = app;
