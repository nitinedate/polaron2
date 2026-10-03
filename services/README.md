# Aetheris isolated forensic services

Aetheris now runs Disk, Android, iOS, and Vulnerability workflows as independent products. Android and iOS do **not** share a PostgreSQL database, Celery broker, MinIO evidence bucket, worker queue, or UI route with each other or with Disk forensics.

| Product | Compose file | UI | API | Job/worker namespace |
|---|---|---:|---:|---|
| Host capacity coordinator | `services/capacity/docker-compose.yml` | — | Redis `127.0.0.1:6389` | semaphore leases only |
| Disk Forensics | `services/forensic/docker-compose.yml` | gateway `:3000/:3001` | `:8083` | `disk-*` / forensic queues |
| Android Forensics | `services/mobile-android/docker-compose.yml` | `:3002` | `:8081` | `android-*` |
| iOS Forensics | `services/mobile-ios/docker-compose.yml` | `:3004` | `:8084` | `ios-*` |
| Vulnerabilities | `services/vuln/docker-compose.yml` | gateway | `:8082` | scanner queues |
| Legacy mobile migration | `services/mobile-extract/docker-compose.yml` | — | legacy `:8081` | `mobile-*` |

The capacity coordinator is the **only intentional cross-product runtime dependency**. It stores short-lived CPU/GPU semaphore leases; it does not store jobs, credentials, evidence, reports, RAG chunks, or acquisition state. This lets the server process several jobs at once while all products negotiate against the same physical CPU/RAM/GPU/thermal capacity.

## Start all current products on Windows

From the repository root:

```powershell
.\scripts\start-stack.ps1 -Service all
```

This starts the capacity coordinator first, then Disk Forensics, Android Forensics, iOS Forensics, Vulnerabilities, and the gateway. The dedicated mobile UIs remain separate at ports 3002 and 3004.

Start one product:

```powershell
.\scripts\start-stack.ps1 -Service forensic
.\scripts\start-stack.ps1 -Service mobile-android
.\scripts\start-stack.ps1 -Service mobile-ios
.\scripts\start-stack.ps1 -Service vuln
```

Linux/manual Compose example:

```bash
docker compose -f services/capacity/docker-compose.yml --project-directory . up -d
docker compose -f services/forensic/docker-compose.yml --project-directory . up -d --build
docker compose -f services/mobile-android/docker-compose.yml --project-directory . up -d --build
docker compose -f services/mobile-ios/docker-compose.yml --project-directory . up -d --build
docker compose -f services/vuln/docker-compose.yml --project-directory . --profile vuln-scanners up -d --build
```

## CUDA policy

All Aetheris Python forensic/mobile API and Celery microservices use the CUDA-enabled backend image and receive NVIDIA GPU visibility. CPU-oriented services may never execute a CUDA kernel; visibility is provided for capacity telemetry and future GPU stages. Heavy OCR/RAG/model work must acquire the shared adaptive GPU semaphore before loading models. PostgreSQL, Redis, MinIO, Nginx and third-party vulnerability engines are infrastructure/vendor services and are deliberately not converted into CUDA containers.

The legacy `mobile-extract` stack remains only to drain/migrate older deployments. New work should use `mobile-android` or `mobile-ios`.
