# HTTP API

All endpoints require `Authorization: Bearer <token>` (the `SENTINEL_API_TOKEN`) except for the public health and metrics paths. Tenant scope is selected with the `X-Tenant-Id` header (defaults to `default`).

A complete OpenAPI 3.1 specification is served at `GET /openapi.json` and a Swagger UI at `GET /docs` when the service is running.

## Conventions

- All bodies are JSON.
- All timestamps are RFC 3339 UTC.
- All IDs are UUIDv4 unless otherwise noted.
- Error responses use the shape `{ "error": "<code>", "detail": "<string>" }`.

## Endpoints

### `POST /v1/evaluate`
Evaluate an action and return a typed `Decision`.

Request body — `Action`:

```json
{
  "type": "tool_call",
  "agent_did": "did:web:agents.example.com:agent-42",
  "tool": "filesystem.write",
  "intent": "save quarterly report",
  "arguments": { "path": "/tmp/report.pdf", "content": "..." }
}
```

Response — `Decision`:

```json
{
  "verdict": "deny",
  "action_id": "8b...e2",
  "explanation": "intent_mismatch: declared 'save quarterly report' but tool 'filesystem.write' targets a system path",
  "risk_factors": [
    { "code": "INTENT_MISMATCH", "detector": "intent_classifier", "severity": 0.82 }
  ],
  "matched_rule_ids": ["fs.no_system_paths"],
  "degraded": false
}
```

### `GET /v1/policies`
Return the active `PolicyBundle` for the tenant.

### `POST /v1/policies/reload`
Reload the bundle from the configured source. Verifies the Ed25519 signature.

### `GET /v1/identities/{did}`
Return the identity record. `did` may include slashes (path parameter).

### `POST /v1/identities`
Upsert an identity. Request body is an `Identity` object.

### `GET /v1/audit?limit=&cursor=&verdict=`
Return audit records for the tenant. Supports forward pagination via `cursor`.

### `GET /v1/approvals`
Return pending approvals (escalated actions awaiting human review).

### `POST /v1/approvals/{id}/resolve?verdict=allow|deny&reviewer=&note=`
Resolve an approval.

### `GET /healthz`, `/livez`, `/readyz`
Health probes. Public, no auth required.

### `GET /metrics`
Prometheus exposition. Public, no auth required.

## Rate limits

Per-tenant token bucket. Defaults: `1200 rpm` sustained, `240` burst. Configurable via `SENTINEL_RATE_LIMIT_RPM` / `SENTINEL_RATE_LIMIT_BURST`. Rate-limited responses are HTTP `429` with `Retry-After`.

## Authentication

Bearer-token middleware compares `Authorization: Bearer <token>` against `SENTINEL_API_TOKEN` using a constant-time comparison. When the env var is unset, the service fails closed and returns HTTP `503`.

## Versioning

The HTTP surface is versioned under `/v1/`. Breaking changes ship under a new prefix; `/v1/` is supported through the next two minor releases of any successor.
