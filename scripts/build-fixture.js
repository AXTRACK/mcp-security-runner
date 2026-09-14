const fs = require('fs');
const path = require('path');

const source = path.join(__dirname, '..', 'fixtures', 'build', 'source', 'server.js');
const targetDir = path.join(__dirname, '..', 'fixtures', 'build', 'dist');
const target = path.join(targetDir, 'server.js');
fs.mkdirSync(targetDir, { recursive: true });
fs.copyFileSync(source, target);
