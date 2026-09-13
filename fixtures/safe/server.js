const fs = require('fs');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line) => {
  const message = JSON.parse(line);
  if (message.method === 'initialize') {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0',
      id: message.id,
      result: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        serverInfo: { name: 'safe-fixture', version: '1' }
      }
    }) + '\n');
  }
  if (message.method === 'notifications/initialized') {
    fs.writeFileSync('safe-fixture-initialized.txt', 'initialized notification received\n');
  }
});
