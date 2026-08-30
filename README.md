# ExecWake

ExecWake records the observable side effects of a command and compares them across runs.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --features conformance-fixture -- -D warnings
cargo test --all-targets --features conformance-fixture
```
