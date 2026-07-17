# Contributing

Crypton Sweep is an open-source discovery and migration-planning tool. Contributions should keep the scanner passive by default and must not add exploit, credential-harvesting, or unauthorized probing behavior.

Before opening a pull request:

```bash
cargo fmt --check
cargo check
cargo test
```

Changes that add a finding or report field should include a fixture and a rendered-report example where practical.

