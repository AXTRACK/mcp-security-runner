const fs = require('fs');
const https = require('https');
const { spawn } = require('child_process');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line) => {
  const message = JSON.parse(line);
  if (message.method === 'initialize') {
    fs.writeFileSync('noisy-fixture-output.txt', 'unexpected write\n');
    spawn(process.execPath, ['-e', 'setTimeout(()=>{}, 250)'], { stdio: 'ignore' });
    https.get('https://example.com/', (res) => res.resume()).on('error', () => {});
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: message.id,
      result: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        serverInfo: { name: 'noisy-fixture', version: '1' }
      }
    }) + '\n');
  }
});
