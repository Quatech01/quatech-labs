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

// ── Mount all tools ───────────────────────────────────────────────────────────
for (const tool of TOOLS) {
  const toolPath  = path.join(TOOLS_DIR, tool.slug);
  const pubDir    = path.join(toolPath, 'public');
  const serverFile = path.join(toolPath, 'server.js');
  const mainFile  = path.join(toolPath, 'main.py');
  const toolBase  = `${BASE}/${tool.slug}`;

  if (!fs.existsSync(toolPath)) continue;

  // Serve index.html with API paths patched to relative
  const serveIndex = (req, res, next) => {
    const htmlPath = path.join(pubDir, 'index.html');
    if (!fs.existsSync(htmlPath)) return next();
    let html = fs.readFileSync(htmlPath, 'utf8');
    html = html.replace(/(['"`])\/api\//g, '$1api/');
    res.type('html').send(html);
  };
  app.get(toolBase,        serveIndex);
  app.get(`${toolBase}/`,  serveIndex);

  // Static files (css, js, assets)
  if (fs.existsSync(pubDir)) app.use(toolBase, express.static(pubDir));

  if (tool.lang === 'python' && fs.existsSync(mainFile)) {
    // Python: lazy-spawn uvicorn, proxy all requests under toolBase
    app.use(toolBase, (req, res, next) => {
      ensurePython(tool.slug, toolPath, (err, port) => {
        if (err) return res.status(503).json({ error: 'Tool is starting, retry in a moment', retry_after: 5 });
        createProxyMiddleware({
          target: `http://127.0.0.1:${port}`,
          changeOrigin: true,
          on: { error: (e, req, res) => res.status(502).json({ error: 'Tool unavailable' }) },
        })(req, res, next);
      });
    });
  } else if (tool.lang === 'node' && fs.existsSync(serverFile)) {
    try {
      const toolApp = require(serverFile);
      if (typeof toolApp === 'function') {
        app.use(toolBase, toolApp);
        console.log(`[labs] mounted: /tools/${tool.slug}`);
      } else {
        console.warn(`[labs] skipped (no export): ${tool.slug}`);
      }
    } catch (e) {
      console.error(`[labs] failed to load ${tool.slug}: ${e.message}`);
    }
  }
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
