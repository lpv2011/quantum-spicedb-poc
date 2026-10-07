# quantum-spicedb-poc

Proof of concept: keep FileBrowser Quantum's path-based allow/deny rules in SpiceDB so
inheritance and denial are decided in one place instead of per endpoint.

Targets two public issues in gtsteffaniak/filebrowser:
- #1282 deny rules not applied to nested folders
- #1903 allowing a deep path does not make its parents navigable

## Status (be honest)

| Piece | Status |
|---|---|
| `schema.zed`, `validation.yaml` | Written. **Not yet run through `zed validate`** (author's sandbox had no network) |
| `authz/` Go adapter + tests | Written. **Not yet compiled or run** |
| Wiring into Quantum's real endpoints | Not started |

## Run it

    brew install authzed/tap/zed
    make validate                         # zed validate validation.yaml
    make test                             # docker compose up + go test

Fix whatever `make validate` / `go test` report and update the table above.

## Model

- `folder.parent` mirrors the path; `reader`/`writer`/`denied` mirror Quantum's rules
- `blocked = denied + parent->blocked` makes a deny inherit down the tree
- `traverser` is written on every ancestor of a deep allow; `browse = (view + traverser) - blocked`

## Open questions (need the maintainer or Quantum's source)

1. Precedence: here any ancestor deny beats any allow. Does Quantum agree?
2. `denyAll` and `denyByDefault` are not modeled yet (default-deny is simply no grant).
3. Shares: a share must never exceed its creator's own access (v1.5.2 advisory); not modeled.
4. Datastore: Quantum defaults to SQLite, which SpiceDB does not list. Needs a sidecar,
   or SpiceDB's embedded mode (unverified).
5. Postgres run: see `docker-compose.postgres.yaml` in the authzed/spicedb repo.
