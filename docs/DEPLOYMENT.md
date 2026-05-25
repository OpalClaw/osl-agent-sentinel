# Deployment Guide

Three reference paths: Docker Compose, Kubernetes, and AWS (ECS Fargate / Lambda authorizer).

## Prerequisites

- Linux x86_64 host (production).
- Python 3.11+ if running outside containers.
- An Ed25519 keypair for policy bundle signing (generated separately and stored in a secrets manager).
- A SIEM endpoint, or an stdout sidecar that forwards logs.

## Required environment variables

See `.env.example` and `docs/CONFIGURATION.md` for the full list. At minimum:

```env
SENTINEL_ENV=production
SENTINEL_API_TOKEN=<32+ random bytes>
SENTINEL_POLICY_PATH=/etc/sentinel/policies/default.yaml
SENTINEL_POLICY_PUBLIC_KEY=/etc/sentinel/keys/policy.pub
SENTINEL_CACHE_DIR=/var/lib/sentinel/cache
```

## Docker Compose (single-host)

```bash
docker compose -f docker/docker-compose.prod.yml up -d
```

Brings up the sentinel control plane plus a Prometheus + Loki + Grafana stack for local observability.

## Kubernetes (Helm)

A Helm chart is intentionally out of scope for this repo; a minimal manifest is published in `docs/k8s/` and is a 1-to-1 translation of the compose file. We recommend:

- Run sentinel as a `Deployment` with at least 3 replicas behind a `Service` of type `ClusterIP`.
- Mount the policy bundle and public key from a `Secret`.
- Run a sidecar that tails stdout and forwards to your SIEM.
- Set readiness probe to `GET /readyz` and liveness probe to `GET /livez`.
- Configure `HorizontalPodAutoscaler` against CPU and the `sentinel_decision_latency_ms` histogram.

## AWS ECS Fargate

- Build the image: `make docker-build`.
- Push to ECR.
- Run as a Fargate service behind an ALB with a target group on `/readyz`.
- Mount the policy bundle and key from AWS Secrets Manager via `secrets` task definition fields.
- Forward stdout to CloudWatch Logs; ship from there to your SIEM of choice.

## AWS API Gateway Lambda authorizer

For securing existing HTTP APIs without running sentinel as a full service, deploy `sentinel.adapters.aws_apigw.AWSAPIGatewayAdapter` as a Lambda authorizer. The adapter wraps an embedded interceptor and returns a policy document API Gateway interprets directly.

## Backups and DR

- The audit log is append-only; back up the SIEM stream, not the in-process buffer.
- Snapshot the local policy cache directory hourly; sentinel can boot from cache when the upstream policy source is unavailable.
- Identity store is pluggable. For production, point at a durable backend (PostgreSQL, DynamoDB) instead of the bundled in-memory store.

## Rolling upgrades

- Sentinel is stateless except for the local cache. Rolling upgrades are safe.
- The HTTP surface is versioned (`/v1/`); upgrade clients first, then the service.
