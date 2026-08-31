if (!String(process.env.NODE_OPTIONS).includes('--no-warnings')) {
  throw new Error('NODE_OPTIONS was not inherited by the ESM child');
}
void process.env.EXECWAKE_NODE_ESM_PROBE;

await fetch(`http://127.0.0.1:${process.argv[2]}/fetch/module?esm-query=esm-query-value`)
  .then((response) => response.text());
