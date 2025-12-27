# Contributing to Releasy

Thanks for your interest in contributing to Releasy. We welcome issues and
pull requests from the community.

## Code of Conduct

This project follows the Code of Conduct in CODE_OF_CONDUCT.md. By
participating, you agree to uphold it.

## Support

Community support is provided via GitHub Issues only. There is no SLA or
direct support for OSS users.

## How to Contribute

- Search existing issues before opening a new one.
- For substantial changes, open an issue first to discuss scope and approach.
- Keep pull requests focused and small when possible.

## Development Setup

- Install the Rust toolchain (stable) and cargo.
- Optional: install `just` to run common tasks.

Common commands:

- `cargo test --all`
- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `just fmt` and `just pre-commit` (if you have `just` installed)

## Pull Request Process

1. Create a branch from `main`.
2. Make changes with tests for any behavior change.
3. Run formatting and tests.
4. Open a pull request with a clear description and rationale.

## Security

If you discover a security issue, do not open a public issue. Follow
SECURITY.md for reporting instructions.
