set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

fmt:
  cargo fmt --all

pre-commit:
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all

coverage:
  cargo llvm-cov --workspace --all-features --html
