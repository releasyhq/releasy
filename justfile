set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

fmt:
  cargo fmt --all

pre-commit:
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all

openapi:
  mkdir -p docs
  cargo run -p releasy-server --bin openapi --quiet > docs/openapi.json

coverage:
  cargo llvm-cov --workspace --all-features --html
