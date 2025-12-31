set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

fmt:
  cargo fmt --all

pre-commit: docs-lint
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all

openapi:
  mkdir -p docs
  cargo run -p releasy-server --bin openapi --quiet > docs/openapi.json

dev-server:
  RELEASY_BIND_ADDR="0.0.0.0:8080" \
  RELEASY_DATABASE_URL="sqlite:///tmp/releasy.db?mode=rwc" \
  RELEASY_ADMIN_API_KEY="$$(openssl rand -hex 32)" \
  cargo run -p releasy-server --bin releasy-server

dev-db-postgres:
  if docker ps -a --filter "name=^releasy-db$" --quiet | grep -q .; then \
    docker start releasy-db >/dev/null; \
  else \
    docker run -d --name releasy-db \
      -e POSTGRES_USER=releasy \
      -e POSTGRES_PASSWORD=releasy \
      -e POSTGRES_DB=releasy \
      -p 5432:5432 \
      postgres:16 >/dev/null; \
  fi
  until docker exec releasy-db pg_isready -U releasy >/dev/null 2>&1; do \
    sleep 1; \
  done

dev-server-postgres: dev-db-postgres
  RELEASY_BIND_ADDR="0.0.0.0:8080" \
  RELEASY_DATABASE_URL="postgres://releasy:releasy@127.0.0.1:5432/releasy" \
  RELEASY_ADMIN_API_KEY="$$(openssl rand -hex 32)" \
  cargo run -p releasy-server --bin releasy-server

coverage:
  cargo llvm-cov --workspace --all-features --html

docs-lint:
  npm run lint:md
