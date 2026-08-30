# ExecWake

ExecWake records the observable side effects of a command and compares them across runs.

## Development

```sh
(cd web && npm ci && npm run check && npm run build)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```
