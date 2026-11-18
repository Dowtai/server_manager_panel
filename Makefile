.PHONY: test installer-test integration build web generate check

test:
	go test -race ./...

installer-test:
	python3 scripts/test_installer.py

integration:
	@test -n "$$TEST_DATABASE_URL" || (echo 'Set TEST_DATABASE_URL to a dedicated empty database'; exit 1)
	go test -race ./internal/application -run TestPostgresDurabilityAndWorkerRecovery -v

build:
	go build ./cmd/...

web:
	cd web && npm ci --ignore-scripts --no-audit --no-fund && npm run build

generate:
	sqlc generate

check:
	go vet ./...
	go test -race ./...
	cd web && npm run build
	python3 scripts/test_installer.py
