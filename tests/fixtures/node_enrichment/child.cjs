'use strict';

if (!String(process.env.NODE_OPTIONS).includes('--no-warnings')) {
  throw new Error('NODE_OPTIONS was not inherited by the CommonJS child');
}
void process.env.EXECWAKE_NODE_CHILD_PROBE;

fetch(`http://127.0.0.1:${process.argv[2]}/fetch/child?child-query=child-query-value`)
  .then((response) => response.text())
  .catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
