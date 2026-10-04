# V45 updated project — what changed (2026-10-04)

Full details: `POLARON_EXPERT_REVIEW_V45_20261004.md`. Unified diffs: `patches_v45/`.

## Backend (disk / mobile / OCR)
| File | Change |
|---|---|
| `backend/app/services/extract_shard_v45.py` | NEW — streaming, DB-free, semaphore-gated shard worker (replaces `_shard_worker`) |
| `backend/app/services/extract_os_vendor_noise.py` | NEW — AXIOM-aligned OS/vendor tree exclusion (`EXTRACT_OS_VENDOR_TREES=skip`) |
| `backend/app/services/extracted_disk.py` | wires V45 worker, event bus drained by the flusher, source-aware reader cap, vendor filter hook, `vd_plan`/`part_prefix` in payloads |
| `backend/app/services/virtual_disk.py` | `open_virtual_disk_from_paths()` (no DB) + `vd_plan()` |
| `backend/app/services/ocr_gpu.py` | evicts Ollama before GLM-OCR load (`GPU_THERMAL_UNLOAD_OLLAMA_BEFORE_OCR`) |
| `backend/app/services/dual_rag_index.py` | **V45.1** — takes the GPU lane only when `RAG_EMBEDDING_ENABLED=true`; CPU chunking no longer collides with OCR ("RAG deferred — GPU slot busy … after 0s") |
| `backend/app/services/job_locks.py` | **V45.1** — `describe_gpu_lane_state()`: lock-timeout message now says who holds the lane (reason/pid/age), thermal pause, or stale lease |
| `backend/app/services/mobile_forensic/whatsapp_crypt.py` | REPLACED — correct key offset (126), crypt15 HKDF, crypt14/15 header walk, diagnostics |
| `backend/app/services/mobile_forensic/parsers/whatsapp_modern.py` | NEW — modern msgstore resolver, JID joins, media, revoked/quoted/FTS deleted recovery, calls |
| `backend/app/services/mobile_forensic/parsers/messaging.py` | routes modern DBs to the resolver; freelist carve on decrypted bytes; decrypt-failure artifact |
| `backend/app/parsers/emlx_sidecar.py` | NEW — Apple Mail plist flags/dates + `Attachments/` sidecars |
| `backend/app/parsers/email_mime_parser.py` | preview includes `emlx` block + sidecar attachments |
| `backend/tests/test_whatsapp_crypt.py` | fixed: test had encoded the wrong key offset |
| `backend/tests/test_whatsapp_crypt_v45.py` | NEW — 9 tests |

## Deployment
| File | Change |
|---|---|
| `docker-compose.yml` | worker DB pool 2+2 → 4+8 / 90 s; `/scratch` bind mount on `worker-disk` (`EXTRACT_SCRATCH_HOST_DIR`) |
| `.env` | **V45.1:** `DEFER_BACKGROUND_RAG_WHILE_OCR=true`, `GPU_HEAVY_LOCK_WAIT_SEC=180`. V45: extraction tunables (`EXTRACT_READ_SEMAPHORE=8`, HDD readers/chunks, scratch, vendor filter), GPU admission (`GPU_HEAVY_MAX_CONCURRENT=1`, OCR 0.80 / RAG 0.35), pool vars. **Create `F:/PolaronBackup/forensic-data/scratch` (or change `EXTRACT_SCRATCH_HOST_DIR`) before `docker compose up`.** |

## Laptop scanner (vuln)
The copies that lived inside this repo (`scanner-agent/` = 1.0.0, `laptop-scanner/` = 1.2.19) were
older than the deployed standalone `laptop-scanner.zip` (1.5.1). Both have been **synced to the
V45-patched 1.5.1 agent** so `Pack-Laptop-Zip.cmd` ships the fix from now on.
| File | Change |
|---|---|
| `scanner-agent/agent/*`, `laptop-scanner/scanner-agent/agent/*` | v1.5.1 + V45: Greenbone default NVT budgets (320 / 36 000 s), `GVM_MAX_CHECKS` honoured |
| `laptop-scanner/docker-compose.yml` | `configure-openvas` writes env-driven timeouts/retries + `safe_checks`, `expand_vhosts`, `test_empty_vhost`, `report_host_details`; `SCAN_IP_MAX_PARALLELISM` default 8 |
| `laptop-scanner/.env` | `PORT_PROFILE=full`, `UDP_PROFILE=priority`, `GVM_OPTIMIZE_TEST=no`, 8 IP workers, watchdog (`MAX_SCAN_RUNTIME_SEC=5400`, `STALL_SEC=1500`), realistic SLO |

Not changed (see review §6): multi-partition mount, NSRL index, downgrade-backup acquisition.
