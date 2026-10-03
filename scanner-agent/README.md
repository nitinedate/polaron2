# Scanner Agent (on-site laptop)

Outbound HTTPS agent that polls the central Aetheris API for edge scan jobs, runs them on **local OpenVAS**, and uploads findings.

Full engagement steps: [`docs/ON_SITE_OPENVAS_LAPTOP.md`](../docs/ON_SITE_OPENVAS_LAPTOP.md).

```bash
cp .env.example .env
# set CENTRAL_API_URL, TENANT_SLUG, AGENT_TOKEN, GVM_* 
docker compose up -d --build
```
