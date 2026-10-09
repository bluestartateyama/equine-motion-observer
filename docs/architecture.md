# Architecture

One Python application uses Tkinter, Pillow and cryptography. There is no Node
component, database or background service.

```text
Selected local JPEG/PNG ──> immutable original bytes + hash + manifest
                    ├──> Pillow display-only preview
                    └──> manual observation form ──> strict validation ──> JSON file

Optional explicit connection:
UI action ──> local loopback ──> official SIWC ──> DPAPI account registrations
UI send confirmation ──> selected OAuth session ──> formal model discovery
 ──> durable one-attempt ledger ──> public Responses HTTPS/SSE
 ──> completed output guard ──> observation/evidence validation
 ──> human review ──> independent local JSON file
```

| Module | Responsibility |
|---|---|
| `images.py` | JPEG/PNG integrity, dimensions, immutable original bytes, preview |
| `observation.py` | Independent descriptive schema, null rules, evidence binding |
| `storage.py` | Local atomic files, OS locks, Windows DPAPI and owner ACL |
| `auth.py` | PKCE, loopback, OIDC validation, registrations, rotation, logout |
| `transport.py` | Fixed public HTTPS endpoints, TLS validation, single attempt |
| `sse.py` | Chunk-safe UTF-8 events and terminal completion guard |
| `provider.py` | Account-bound catalog, request construction and dispatch ledger |
| `ui.py` | Local notebook, explicit consent, account selection, human review |

All source, prompts, schema, configuration, runtime dependencies, authentication,
image input, storage and network code are independently defined here. No external
research repository is imported, copied, called or watched. There is no production
DB connection, scheduler, event feed or result forwarding. Results remain under
the app's local data directory and are not converted to numerical performance
scores. User-entered confidence describes observation certainty only.

Each inference task may make at most one client POST. Reserved, interrupted and
terminal ledger entries cannot be reset by the UI. A task ID is not a server
idempotency guarantee. Data loss or manual ledger deletion invalidates that guard.
