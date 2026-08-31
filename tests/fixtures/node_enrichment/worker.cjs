'use strict';

const { workerData } = require('node:worker_threads');

if (!String(process.env.NODE_OPTIONS).includes('--no-warnings')) {
  throw new Error('NODE_OPTIONS was not inherited by the worker');
}
void process.env.EXECWAKE_NODE_WORKER_PROBE;

fetch(`http://127.0.0.1:${workerData.port}/fetch/worker?worker-query=worker-query-value`)
  .then((response) => response.text())
  .catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
