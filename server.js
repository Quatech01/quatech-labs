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

// Per-tool presets: { label, method, path, body? } — verified against actual routes
const TOOL_PRESETS = {
  'xss-reflection-scanner': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Inject (vulnerable)', method:'GET',  path:'/search?q=<script>alert(1)</script>' },
    { label:'Inject (escaped)',    method:'GET',  path:'/search-escaped?q=<script>alert(1)</script>' },
    { label:'Inject (CSP)',        method:'GET',  path:'/search-csp?q=<script>alert(1)</script>' },
  ],
  'port-scanner-service-fingerprinting': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Scan results',        method:'GET',  path:'/api/data' },
  ],
  'sql-injection-detector': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Login (injection)',   method:'GET',  path:"/login?username=admin'--&password=wrong" },
    { label:'Login (safe)',        method:'GET',  path:"/login/safe?username=admin'--&password=wrong" },
    { label:'Search (vuln)',       method:'GET',  path:"/search?q=' OR 1=1--" },
    { label:'Search (safe)',       method:'GET',  path:"/search/safe?q=' OR 1=1--" },
  ],
  'hash-collision-demonstrator': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'List algorithms',     method:'GET',  path:'/algorithms' },
    { label:'Hash input',          method:'POST', path:'/hash',            body:'{"input":"Hello, World!","algorithm":"md5"}' },
    { label:'Verify (vulnerable)', method:'POST', path:'/verify-vulnerable',body:'{"input":"Hello, World!","algorithm":"md5","hash":"65a8e27d8879283831b664bd8b7f0ad4"}' },
    { label:'Verify (safe)',       method:'POST', path:'/verify-safe',      body:'{"input":"Hello, World!","algorithm":"sha256","hash":"dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986d"}' },
    { label:'Birthday demo',       method:'GET',  path:'/birthday-demo' },
  ],
  'brute-force-rate-limiter-demo': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Login (no limit)',    method:'POST', path:'/login/vulnerable', body:'{"username":"admin","password":"wrong"}' },
    { label:'Login (rate limited)',method:'POST', path:'/login/protected',  body:'{"username":"admin","password":"wrong"}' },
    { label:'Lockout status',      method:'GET',  path:'/lockout-status' },
    { label:'Reset lockout',       method:'POST', path:'/reset-lockout',    body:'{"username":"admin"}' },
  ],
  'file-entropy-analyzer': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'List files',          method:'GET',  path:'/files' },
    { label:'Low entropy file',    method:'GET',  path:'/files/low' },
    { label:'Medium entropy file', method:'GET',  path:'/files/medium' },
    { label:'High entropy file',   method:'GET',  path:'/files/high' },
    { label:'Encrypted file',      method:'GET',  path:'/files/encrypted' },
    { label:'Safe — low',          method:'GET',  path:'/safe/files/low' },
    { label:'Safe — deny high',    method:'GET',  path:'/safe/files/high' },
  ],
  'csrf-token-validator': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Get CSRF token',      method:'GET',  path:'/csrf-token' },
    { label:'Insecure cookie',     method:'GET',  path:'/account/insecure-cookie' },
    { label:'Secure cookie',       method:'GET',  path:'/account/secure-cookie' },
    { label:'Transfer (no CSRF)',  method:'POST', path:'/transfer/vulnerable', body:'{"amount":100,"to":"attacker"}' },
    { label:'Transfer (protected)',method:'POST', path:'/transfer/protected',  body:'{"amount":100,"to":"attacker","csrf_token":"<paste-token-here>"}' },
  ],
  'aes-encryption-mode-comparison': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'ECB (vulnerable)',    method:'POST', path:'/api/vulnerable/encrypt',  body:'{"plaintext":"YELLOW SUBMARINEYELLOW SUBMARINE"}' },
    { label:'3DES (deprecated)',   method:'POST', path:'/api/deprecated/encrypt',  body:'{"plaintext":"YELLOW SUBMARINEYELLOW SUBMARINE"}' },
    { label:'CBC (acceptable)',    method:'POST', path:'/api/acceptable/encrypt',  body:'{"plaintext":"YELLOW SUBMARINEYELLOW SUBMARINE"}' },
    { label:'GCM (secure)',        method:'POST', path:'/api/secure/encrypt',      body:'{"plaintext":"YELLOW SUBMARINEYELLOW SUBMARINE"}' },
    { label:'ECB weakness demo',   method:'GET',  path:'/demo/ecb-weakness' },
  ],
  'input-sanitization-library': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'HTML (vuln)',         method:'POST', path:'/vuln/html',       body:'{"input":"<script>alert(1)</script><img src=x onerror=alert(2)>"}' },
    { label:'HTML (safe)',         method:'POST', path:'/safe/html',       body:'{"input":"<script>alert(1)</script><img src=x onerror=alert(2)>"}' },
    { label:'Path (vuln)',         method:'GET',  path:'/vuln/path?file=../../../etc/passwd' },
    { label:'Path (safe)',         method:'GET',  path:'/safe/path?file=../../../etc/passwd' },
    { label:'Command (vuln)',      method:'POST', path:'/vuln/command',    body:'{"cmd":"ls; cat /etc/passwd"}' },
    { label:'Command (safe)',      method:'POST', path:'/safe/command',    body:'{"cmd":"ls; cat /etc/passwd"}' },
  ],
  'log-file-anomaly-detector': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Trigger SQL injection',method:'GET', path:"/api/users?id=' OR 1=1--" },
    { label:'Trigger path traversal',method:'GET',path:'/api/products?file=../../etc/passwd' },
    { label:'Normal request',      method:'GET',  path:'/api/orders' },
    { label:'View captured logs',  method:'GET',  path:'/logs' },
  ],
  'jwt-vulnerability-scanner': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Get none-alg token',  method:'GET',  path:'/auth/none/token' },
    { label:'Access (none-alg)',   method:'GET',  path:'/resource/none-accepted' },
    { label:'Get weak-secret token',method:'POST',path:'/auth/weak/token',  body:'{"username":"alice","role":"user"}' },
    { label:'No expiry check',     method:'GET',  path:'/resource/no-expiry-check' },
    { label:'Get secure token',    method:'POST', path:'/auth/secure/token', body:'{"username":"alice","role":"user"}' },
    { label:'Secure resource',     method:'GET',  path:'/resource/secure' },
  ],
  'http-security-header-auditor': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'No headers',          method:'GET',  path:'/headers/none' },
    { label:'Partial headers',     method:'GET',  path:'/headers/partial' },
    { label:'Full headers',        method:'GET',  path:'/headers/full' },
  ],
  'keylogger-detection-and-flagging': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Processes (vuln)',    method:'GET',  path:'/scan/processes' },
    { label:'Processes (safe)',    method:'GET',  path:'/scan/processes/safe' },
    { label:'Registry (vuln)',     method:'GET',  path:'/scan/registry' },
    { label:'Registry (safe)',     method:'GET',  path:'/scan/registry/safe' },
    { label:'Files (vuln)',        method:'GET',  path:'/scan/files' },
    { label:'Files (safe)',        method:'GET',  path:'/scan/files/safe' },
    { label:'Connections (vuln)',  method:'GET',  path:'/scan/connections' },
    { label:'Connections (safe)',  method:'GET',  path:'/scan/connections/safe' },
  ],
  'dns-record-analyzer': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Test domains',        method:'GET',  path:'/domains' },
    { label:'DNS — quatech.co.uk', method:'GET',  path:'/dns?domain=quatech.co.uk' },
    { label:'DNS — gmail.com',     method:'GET',  path:'/dns?domain=gmail.com' },
    { label:'DNS — MX records',    method:'GET',  path:'/dns?domain=quatech.co.uk&type=MX' },
    { label:'DNS — TXT/SPF',       method:'GET',  path:'/dns?domain=quatech.co.uk&type=TXT' },
  ],
  'email-header-analyzer': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'List samples',        method:'GET',  path:'/samples' },
    { label:'Sample 1',            method:'GET',  path:'/samples/1' },
    { label:'Sample 2',            method:'GET',  path:'/samples/2' },
    { label:'Sample 3',            method:'GET',  path:'/samples/3' },
  ],
  'oauth-pkce-flow-analyzer': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Authorize (vuln)',    method:'GET',  path:'/auth/authorize?client_id=demo&redirect_uri=http://localhost:3000/callback&response_type=code&state=xyz' },
    { label:'Token (no verifier)', method:'POST', path:'/auth/token',           body:'{"code":"demo_code","redirect_uri":"http://localhost:3000/callback"}' },
    { label:'Authorize (PKCE)',    method:'GET',  path:'/auth/secure/authorize?client_id=demo&redirect_uri=http://localhost:3000/callback&response_type=code&code_challenge=abc123&code_challenge_method=S256&state=xyz' },
    { label:'Token (PKCE)',        method:'POST', path:'/auth/secure/token',     body:'{"code":"demo_code","code_verifier":"valid_verifier","redirect_uri":"http://localhost:3000/callback"}' },
    { label:'Profile (auth header)',method:'GET', path:'/api/profile' },
  ],
  'timing-attack-demonstrator': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Secret info',         method:'GET',  path:'/api/secret-length' },
    { label:'Check (naive — vuln)',method:'GET',  path:'/api/check-naive?token=wrong_guess' },
    { label:'Check (safe)',        method:'GET',  path:'/api/check-safe?token=wrong_guess' },
  ],
  'open-redirect-checker': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Unsafe redirect',     method:'GET',  path:'/redirect/unsafe?url=https://evil.com' },
    { label:'Safe redirect',       method:'GET',  path:'/redirect/safe?url=https://evil.com' },
    { label:'Partial validation',  method:'GET',  path:'/redirect/partial?url=https://evil.com' },
    { label:'Login (redirect param)',method:'GET',path:'/login?redirect=https://evil.com' },
  ],
  'directory-traversal-detector': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Safe filename',       method:'GET',  path:'/files/unsafe?filename=readme.txt' },
    { label:'Traversal (unsafe)',  method:'GET',  path:'/files/unsafe?filename=../../../etc/passwd' },
    { label:'Traversal (blocked)', method:'GET',  path:'/files/safe?filename=../../../etc/passwd' },
    { label:'Encoded traversal',   method:'GET',  path:'/files/unsafe?filename=..%2F..%2Fetc%2Fpasswd' },
  ],
  'session-fixation-demonstrator': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Get session',         method:'GET',  path:'/session' },
    { label:'Login (vulnerable)',  method:'POST', path:'/login/vulnerable',  body:'{"username":"alice","password":"pass123"}' },
    { label:'Login (safe)',        method:'POST', path:'/login/safe',        body:'{"username":"alice","password":"pass123"}' },
    { label:'View profile',        method:'GET',  path:'/profile' },
  ],
  'subdomain-enumerator': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Resolve www.quatech.co.uk',method:'GET',path:'/resolve?name=www.quatech.co.uk' },
    { label:'Resolve admin (miss)',method:'GET',  path:'/resolve?name=admin.quatech.co.uk' },
    { label:'Resolve mail',        method:'GET',  path:'/resolve?name=mail.quatech.co.uk' },
  ],
  'hash-generator-authenticator': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'List algorithms',     method:'GET',  path:'/api/algorithms' },
    { label:'Generate SHA-256',    method:'POST', path:'/api/generate',        body:'{"algorithm":"sha256","input":"Hello, World!"}' },
    { label:'Generate all',        method:'POST', path:'/api/generate/all',    body:'{"input":"Hello, World!"}' },
    { label:'bcrypt hash',         method:'POST', path:'/api/generate',        body:'{"algorithm":"bcrypt","input":"my_secret_password"}' },
    { label:'Verify hash',         method:'POST', path:'/api/verify',          body:'{"algorithm":"sha256","input":"Hello, World!","hash":"dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986d"}' },
    { label:'Crack (dict attack)', method:'POST', path:'/api/crack/dictionary',body:'{"hash":"5f4dcc3b5aa765d61d8327deb882cf99","algorithm":"md5"}' },
    { label:'Benchmark',           method:'POST', path:'/api/benchmark',       body:'{"input":"benchmark_test"}' },
  ],
  'totp-demo': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Register',            method:'POST', path:'/api/auth/register',   body:'{"email":"demo@quatech.co.uk","password":"Demo@12345"}' },
    { label:'Login',               method:'POST', path:'/api/auth/login',      body:'{"email":"demo@quatech.co.uk","password":"Demo@12345"}' },
    { label:'Start TOTP enrolment',method:'POST', path:'/api/totp/enrol',      body:'{}' },
    { label:'Confirm TOTP',        method:'POST', path:'/api/totp/confirm',    body:'{"token":"123456"}' },
    { label:'Authenticate TOTP',   method:'POST', path:'/api/totp/authenticate',body:'{"token":"123456"}' },
    { label:'Protected endpoint',  method:'GET',  path:'/api/secure' },
  ],
  'tls-inspector': [
    { label:'Health',              method:'GET',  path:'/health' },
    { label:'Inspect quatech.co.uk',method:'POST',path:'/api/inspect',         body:'{"host":"quatech.co.uk"}' },
    { label:'Inspect expired cert',method:'POST', path:'/api/inspect',         body:'{"host":"expired.badssl.com"}' },
    { label:'Inspect weak cipher', method:'POST', path:'/api/inspect',         body:'{"host":"rc4.badssl.com"}' },
    { label:'Analyse PEM',         method:'POST', path:'/api/analyse-pem',     body:'{"pem":"-----BEGIN CERTIFICATE-----\\nMIID...\\n-----END CERTIFICATE-----"}' },
  ],
};

// Auto-generate a rich tool page from README.md when no public/index.html exists
function autoPage(tool, toolPath) {
  const readmePath = path.join(toolPath, 'README.md');
  const readme = fs.existsSync(readmePath) ? fs.readFileSync(readmePath, 'utf8') : '';
  const rawDesc = readme.split('\n')
    .filter(l => l.trim() && !l.startsWith('#') && !l.startsWith('```') && !l.startsWith('|'))
    .slice(0, 4).join(' ')
    .replace(/\*\*(.+?)\*\*/g, '$1').replace(/\*(.+?)\*/g, '$1')
    .replace(/`(.+?)`/g, '$1').replace(/\[(.+?)\]\(.+?\)/g, '$1')
    .replace(/#+\s*/g, '').trim();
  let desc = rawDesc.length > 300 ? rawDesc.slice(0, 300) : rawDesc;
  const lastPeriod = desc.lastIndexOf('.');
  if (lastPeriod > 80) desc = desc.slice(0, lastPeriod + 1);

  const presets = TOOL_PRESETS[tool.slug] || [{ label:'Health', method:'GET', path:'/health' }];

  return `<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${tool.title}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap">
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#2563eb;--green:#3fb950;--yellow:#d29922;--red:#f85149}
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
.explorer{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:28px}
.explorer-header{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.explorer-header h2{font-size:.82rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 6px #3fb95055}
.input-row{display:flex;gap:0;padding:14px 18px;border-bottom:1px solid var(--border);align-items:stretch}
select#method{background:var(--surface2);border:1px solid var(--border);border-right:none;border-radius:6px 0 0 6px;padding:9px 10px;font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--green);font-weight:600;cursor:pointer;appearance:none;-webkit-appearance:none;min-width:72px;text-align:center}
select#method option{background:var(--surface2);color:var(--text)}
#path-input{flex:1;background:var(--surface2);border:1px solid var(--border);border-right:none;padding:9px 12px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:.8rem;outline:none;min-width:0}
#path-input:focus{border-color:var(--accent)}
button#send{background:var(--accent);border:none;border-radius:0 6px 6px 0;padding:9px 18px;color:#fff;font-size:.82rem;font-weight:600;cursor:pointer;white-space:nowrap;flex-shrink:0}
button#send:hover{background:#1d4ed8}
.body-row{padding:10px 18px;border-bottom:1px solid var(--border)}
.body-label{font-size:.72rem;color:var(--muted);margin-bottom:6px;font-family:'JetBrains Mono',monospace}
#body-input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:.78rem;line-height:1.5;resize:vertical;min-height:80px;outline:none}
#body-input:focus{border-color:var(--accent)}
.presets{padding:10px 18px;display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--border)}
.preset{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:.73rem;color:var(--muted);cursor:pointer;transition:all .15s;white-space:nowrap}
.preset:hover{border-color:var(--accent);color:var(--text)}
.preset .pm{font-family:'JetBrains Mono',monospace;font-weight:600;margin-right:4px}
.pm-get{color:var(--green)}.pm-post{color:var(--yellow)}.pm-delete{color:var(--red)}
.response-area{padding:18px;min-height:120px}
.resp-meta{font-size:.75rem;color:var(--muted);margin-bottom:10px;font-family:'JetBrains Mono',monospace;display:flex;gap:16px;flex-wrap:wrap}
.status-ok{color:var(--green)}.status-err{color:var(--red)}
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
  <div class="explorer-header"><span class="dot"></span><h2>Live API Explorer</h2></div>
  <div class="input-row">
    <select id="method"><option>GET</option><option>POST</option><option>DELETE</option></select>
    <input id="path-input" type="text" value="/tools/${tool.slug}/health" placeholder="/tools/${tool.slug}/...">
    <button id="send">Send →</button>
  </div>
  <div class="body-row" id="body-row" hidden>
    <div class="body-label">Request Body (JSON)</div>
    <textarea id="body-input" placeholder='{"key": "value"}'></textarea>
  </div>
  <div class="presets" id="presets"></div>
  <div class="response-area">
    <div id="resp-meta" class="resp-meta" hidden></div>
    <pre id="response"><div class="placeholder">Pick a preset or type a path and hit Send</div></pre>
  </div>
</div>

<script>
const BASE = '/tools/${tool.slug}';
const PRESETS = ${JSON.stringify(presets).replace(/<\//g, '<\\/')};

const methodEl  = document.getElementById('method');
const pathEl    = document.getElementById('path-input');
const bodyRowEl = document.getElementById('body-row');
const bodyEl    = document.getElementById('body-input');

methodEl.addEventListener('change', () => {
  bodyRowEl.hidden = methodEl.value === 'GET' || methodEl.value === 'DELETE';
});

const presetsEl = document.getElementById('presets');
PRESETS.forEach(p => {
  const btn = document.createElement('button');
  btn.className = 'preset';
  const mColor = p.method === 'GET' ? 'get' : p.method === 'POST' ? 'post' : 'delete';
  btn.innerHTML = '<span class="pm pm-' + mColor + '">' + p.method + '</span>' + p.label;
  btn.onclick = () => {
    methodEl.value = p.method;
    pathEl.value   = BASE + p.path;
    if (p.body) {
      try { bodyEl.value = JSON.stringify(JSON.parse(p.body), null, 2); } catch { bodyEl.value = p.body; }
    } else { bodyEl.value = ''; }
    bodyRowEl.hidden = p.method === 'GET' || p.method === 'DELETE';
    send();
  };
  presetsEl.appendChild(btn);
});

async function send() {
  const method  = methodEl.value;
  const rawPath = pathEl.value.trim() || BASE + '/health';
  const url     = rawPath.startsWith('/') ? rawPath : '/' + rawPath;
  const t0 = Date.now();
  const metaEl = document.getElementById('resp-meta');
  const respEl = document.getElementById('response');
  respEl.innerHTML = '<div class="placeholder">Loading…</div>';
  metaEl.hidden = true;
  const opts = { method };
  if ((method === 'POST' || method === 'PUT') && bodyEl.value.trim()) {
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = bodyEl.value;
  }
  try {
    const res = await fetch(url, opts);
    const ms = Date.now() - t0;
    const ct = res.headers.get('content-type') || '';
    let body;
    if (ct.includes('json')) {
      body = JSON.stringify(await res.json(), null, 2);
    } else {
      body = await res.text();
    }
    metaEl.hidden = false;
    const sc = res.ok ? 'status-ok' : 'status-err';
    metaEl.innerHTML = '<span class="' + sc + '">' + res.status + ' ' + res.statusText + '</span><span>' + ms + 'ms</span><span>' + (ct.split(';')[0]) + '</span>';
    respEl.textContent = body;
  } catch(e) {
    metaEl.hidden = false;
    metaEl.innerHTML = '<span class="status-err">Network error</span>';
    respEl.textContent = e.message;
  }
}

document.getElementById('send').onclick = send;
pathEl.addEventListener('keydown', e => { if (e.key === 'Enter') send(); });
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
