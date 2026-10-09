#!/usr/bin/env node
'use strict';
// Patches a tool's server.js so it exports its Express app and guards app.listen
const fs   = require('fs');
const file = process.argv[2];
if (!file) { console.error('Usage: node patch-server.js <server.js>'); process.exit(1); }

let code = fs.readFileSync(file, 'utf8');
let changed = false;

// Guard app.listen() calls so they only run when the file is the entry point
if (!code.includes('require.main')) {
  code = code.replace(
    /^(app\.listen\([^)]+\).*)/m,
    'if (require.main === module) { $1 }'
  );
  // Also handle multi-arg listen: app.listen(PORT, () => ...)
  code = code.replace(
    /^(app\.listen\(\s*\w+\s*,\s*(?:function|\()[\s\S]*?\}\s*\)\s*;)/m,
    'if (require.main === module) { $1 }'
  );
  changed = true;
}

// Add module.exports = app if missing
if (!code.includes('module.exports')) {
  code += '\nmodule.exports = app;\n';
  changed = true;
}

if (changed) {
  fs.writeFileSync(file, code);
  console.log(`patched: ${file}`);
} else {
  console.log(`ok (no changes): ${file}`);
}
