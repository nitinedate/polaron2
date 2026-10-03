# Aetheris site scanner (Persistent Edge appliance or Portable laptop)

Deploy this folder on a **Windows laptop** (Portable Assessment) or an **always-on box left on the customer LAN** (Persistent Edge). Register the matching role in **Service 3 (Vulnerabilities) → Scanners**. The agent talks **only** to the vuln API (`/health` role `vuln-api`). It does not use the forensic or mobile-extraction stacks.

```text
Browser / central UI
        |
        v
https://122.170.114.36:443
        |
        | Nginx /api/* -> central api:8080
        v
Central API  <--- outbound HTTPS poll / upload ---  Scanner Agent (this laptop)
                                                       |
                                                  Local OpenVAS
                                                       |
                                                  Client LAN targets
```

## Prerequisites (laptop)

1. Windows 10/11
2. Docker Desktop installed (WSL2 backend)
3. 8 GB+ RAM free; laptop plugged in
4. Laptop connected to the network that can reach the authorized scan targets
5. Central HTTPS API reachable from the laptop:

```powershell
curl.exe https://122.170.114.36/api/health
```

Expected response contains `"status":"ok"`, `"service":"aetheris"`, and `"role":"vuln-api"` (legacy `"central-api"` is still accepted). Local split: `http://host.docker.internal:3003/api/health`.

## One-time setup

1. On any Aetheris login page, request an **access token** for a firm admin that can manage scanners (`scan:policy_manage`).
   The same token is emailed once and works on Forensic, Mobile extract, and this laptop. Start-Laptop asks for that token and binds it as `AGENT_TOKEN`.

2. On the laptop, copy `.env.example` to `.env` if `.env` is absent. The package is preconfigured for the production HTTPS gateway:

```env
CENTRAL_API_URL=https://122.170.114.36
TENANT_SLUG=aetheris
AGENT_TOKEN=<paste token>
VERIFY_TLS=true
# persistent_edge for an always-on site box; portable for a roaming laptop
SCANNER_ROLE=portable
```

Important: `CENTRAL_API_URL` is the **site root**, not `/api`. The agent automatically calls `/api/scanner-agent/...`. The client also tolerates a manually entered trailing `/api` and normalizes it.

3. Double-click **`Start-Laptop.cmd`**. Paste the **access token from the login email**. The laptop links only after that token is accepted.

The startup script first validates `https://122.170.114.36/api/health`, requires the emailed token, binds it as the agent token, starts Docker Desktop when necessary, and then starts Local OpenVAS + the scanner agent.

First Greenbone/OpenVAS startup downloads images and feeds and can take a long time.

## Why port 8080 is not discovered anymore

The hardened central deployment binds FastAPI as `127.0.0.1:8080` and exposes the application through Nginx on TCP 443. Therefore another laptop should use:

```text
https://122.170.114.36
```

not:

```text
http://<central-lan-ip>:8080
```

The old `CENTRAL_API_URL=AUTO` + `CENTRAL_API_PORT=8080` LAN discovery is retained only as an explicit legacy fallback for deployments that intentionally expose 8080 on the LAN. Do **not** expose 8080 merely to make discovery work.

## Daily use

**Persistent Edge:** leave the appliance on the customer LAN. Set `SCANNER_ROLE=persistent_edge` in `.env` to match the scanner role in the UI. There is no roam abort; do not move the box between sites while a job is running.

**Portable Assessment:** stay on the original LAN until the job completes. `Start-Laptop.cmd` writes `.lan-fingerprint` from the Windows default gateway. If the laptop moves to another network mid-scan, the agent stops OpenVAS and fails the job — it does **not** scan the new network under the same job. Resume the same job after you return.

1. Join the client/target Wi-Fi or Ethernet.
2. Confirm the central API if needed:

```powershell
curl.exe https://122.170.114.36/api/health
```

3. Double-click **`Start-Laptop.cmd`** and paste the **access token from the login email**. The laptop uses the same token as the three web products.
4. On the central UI, launch a scan, select this edge scanner, enter the authorized client target IPs, and launch.

Target IPs are entered in the **central browser UI**, not on the laptop.

## Useful commands

```powershell
cd <this-folder>
docker compose ps
docker compose logs -f scanner-agent
docker compose logs --tail=100 gvmd ospd-openvas
```

To stop services without deleting containers or volumes:

```powershell
docker compose stop
```

## Troubleshooting

If startup says the central API is unreachable, test:

```powershell
curl.exe -v https://122.170.114.36/api/health
Test-NetConnection 122.170.114.36 -Port 443
```

If the HTTPS URL works in a browser but not from this scanner laptop, check the laptop's proxy/firewall/DNS/network route and, when both machines are on the same LAN, the router's NAT loopback/hairpin-NAT support.

If the token is rejected with HTTP 401, create or rotate the `edge_agent` scanner token in the central UI and update `AGENT_TOKEN` in `.env`.

If OpenVAS logs `Unable to check signature /var/lib/openvas/plugins/sha256sums.asc`, recreate `openvasd` so it mounts the NASL feed volume (`gvm_vt_data`). The hourly warning is openvasd checking plugins even in `service_notus` mode; it is not itself a laptop LAN-move failure. `neither api-key nor mTLS configured` is expected on the internal Docker network.

## Notes

- No inbound firewall rule to the laptop is required for central communication; the agent initiates outbound HTTPS.
- First OpenVAS feed sync may take 30-90+ minutes.
- Do not run two edge jobs against the same host at once.
- Only scan systems and networks you are authorized to assess.


## High-performance per-IP semaphore (50+ IP jobs)

The scanner runs **one OpenVAS task per IP**. `SCAN_IP_PARALLELISM=auto` keeps a five-IP operational floor and scales to `SCAN_IP_MAX_PARALLELISM` (10 by default) when CPU/RAM/temperature allow it. Warm or hot hosts remain at five; a critical thermal/RAM condition pauses only **new** IP admissions while current tasks finish.

Before OpenVAS, quick reachability probes run concurrently. A closed/error port is logged and the probe continues to the next configured port. If all quick-probe ports fail, that IP is marked unreachable and omitted. During OpenVAS, a start error, poll error, failed task, or stopped task affects only that IP: its permit is released immediately and the next pending IP uses the free slot. The other IPs continue.

Per-IP audit logs are stored on the laptop under `./logs/ip/<job-id>/<ip>.jsonl`, with a combined `all-ips.jsonl`. The same `IP_EVENT` records are sent through the existing central scanner log shipper. Events include queueing, reachability/port failures, task start/task id, progress, terminal state, elapsed time, and finding count.
