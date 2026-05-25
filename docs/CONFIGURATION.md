# Configuration

Every configuration option is set via an environment variable. Boolean values accept `true`/`false` (case-insensitive). Durations are integer seconds.

## Service identity

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_ENV` | `development` | One of `development`, `staging`, `production`. Controls default log format and safety toggles. |
| `SENTINEL_SERVICE_NAME` | `osl-agent-sentinel` | Service name reported to logs and observability. |
| `SENTINEL_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `SENTINEL_LOG_FORMAT` | `json` | `json` or `console`. |

## HTTP API

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_API_HOST` | `0.0.0.0` | Bind address. |
| `SENTINEL_API_PORT` | `8080` | Bind port. |
| `SENTINEL_API_TOKEN` | _unset_ | Bearer token required for all non-public endpoints. |
| `SENTINEL_API_CORS_ORIGINS` | _empty_ | Comma-separated allow-list. Empty means no CORS. |

## Policy engine

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_POLICY_PATH` | `config/policies/default.yaml` | Path to the active policy bundle. |
| `SENTINEL_POLICY_PUBLIC_KEY` | _unset_ | Path to the Ed25519 public key used to verify bundle signatures. When unset, signatures are accepted but not required. |
| `SENTINEL_POLICY_CACHE_PATH` | `/var/lib/sentinel/policy-cache.json` | Local cache used for fail-closed degradation. |
| `SENTINEL_POLICY_RELOAD_SECONDS` | `60` | Hot-reload interval. Set to `0` to disable. |

## Identity

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_IDENTITY_BACKEND` | `memory` | `memory` or `http`. |
| `SENTINEL_IDENTITY_URL` | _unset_ | Identity resolver URL when backend is `http`. |
| `SENTINEL_REQUIRE_SIGNED_ACTIONS` | `false` | When `true`, unsigned actions are denied. |

## Observability

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_METRICS_ENABLED` | `true` | Expose `/metrics`. |
| `SENTINEL_SIEM_BACKEND` | `stdout` | `stdout` or `http`. |
| `SENTINEL_SIEM_URL` | _unset_ | Required when backend is `http`. |
| `SENTINEL_SIEM_BATCH_SIZE` | `100` | Maximum records per HTTP push. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _unset_ | OTLP traces endpoint. When unset, tracing is disabled. |

## Tenancy and rate limits

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_DEFAULT_TENANT` | `default` | Tenant used when the `X-Tenant-Id` header is absent. |
| `SENTINEL_RATE_LIMIT_RPS` | `100` | Per-tenant evaluations per second. |
| `SENTINEL_RATE_LIMIT_BURST` | `200` | Per-tenant burst capacity. |

## Approval workflow

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_APPROVAL_TTL_SECONDS` | `3600` | Time a pending approval lives before auto-deny. |

## Sandbox

| Variable | Default | Description |
| --- | --- | --- |
| `SENTINEL_DEFAULT_RING` | `r1_namespaced` | One of `r0_trusted`, `r1_namespaced`, `r2_microvm`, `r3_network_only`. |
