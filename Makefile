.PHONY: up validate tidy test down
up:
	docker compose up -d
validate:
	zed validate validation.yaml
tidy:
	go mod tidy
test: up tidy
	SPICEDB_ENDPOINT=localhost:50051 SPICEDB_KEY=devkey go test ./... -v
down:
	docker compose down
