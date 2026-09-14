const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  let request;
  try { request = JSON.parse(line); } catch { return; }
  if (request.method === 'initialize') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        serverInfo: { name: 'build-fixture', version: '1.0.0' }
      }
    }) + '\n');
  }
});
