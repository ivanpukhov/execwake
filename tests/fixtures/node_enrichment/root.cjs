'use strict';

const { spawn } = require('node:child_process');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const { Worker } = require('node:worker_threads');

if (!String(process.env.NODE_OPTIONS).includes('--no-warnings')) {
  throw new Error('existing NODE_OPTIONS were not preserved');
}
void process.env.EXECWAKE_NODE_PARENT_PROBE;

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function spawnNode(file, port) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [file, String(port)], { stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0 && signal === null) resolve();
      else reject(new Error(`child failed: code=${code} signal=${signal}`));
    });
  });
}

function runWorker(file, port) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(file, { workerData: { port } });
    worker.once('error', reject);
    worker.once('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`worker failed: code=${code}`));
    });
  });
}

function runHttps(port) {
  return new Promise((resolve) => {
    const request = https.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: '/secure?https-query=https-query-value#https-fragment',
      rejectUnauthorized: false,
      headers: {
        authorization: 'Bearer https-header-value',
        cookie: 'session=https-cookie-value',
      },
    });
    request.once('error', resolve);
    request.end('https-request-body-value');
  });
}

async function main() {
  const httpServer = http.createServer((request, response) => {
    request.resume();
    request.once('end', () => response.end('response-body-value'));
  });
  const tlsSink = net.createServer((socket) => socket.destroy());
  const httpPort = await listen(httpServer);
  const tlsPort = await listen(tlsSink);
  const directory = __dirname;

  try {
    await fetch(
      `http://127.0.0.1:${httpPort}/fetch/root?fetch-query=fetch-query-value#fetch-fragment`,
      {
        method: 'POST',
        headers: {
          authorization: 'Bearer fetch-header-value',
          cookie: 'session=fetch-cookie-value',
        },
        body: 'fetch-request-body-value',
      },
    ).then((response) => response.text());
    await runHttps(tlsPort);
    await spawnNode(path.join(directory, 'child.cjs'), httpPort);
    await spawnNode(path.join(directory, 'module.mjs'), httpPort);
    await runWorker(path.join(directory, 'worker.cjs'), httpPort);
  } finally {
    await Promise.all([close(httpServer), close(tlsSink)]);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
