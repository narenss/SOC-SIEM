# DIY SIEM (final project)

Lightweight SIEM stack: **Graylog** for log management, **Python correlation**, **PostgreSQL**, local **Ollama** explanations, and a **Flask + Chart.js** dashboard.

This repo ships a **Docker Compose** lab (Graylog + Postgres) and the **`diy_siem`** Python package.

## Prerequisites

- Docker Desktop (or Docker Engine + Compose v2) — on Apple Silicon, images are multi-arch.
- Optional (macOS): Docker **Memory** ~10–12 GB in *Settings → Resources* on 16 GB machines.

## Quick start

```bash
cd "/Users/Naren/Desktop/final project - soc siem"
cp -n .env.example .env   # skip if .env already exists
docker compose up -d
```

Wait until Graylog responds (first start can take **2–5 minutes**). Check containers: `docker compose ps` and logs: `docker compose logs -f graylog` (stop with Ctrl+C).

- **Web UI:** http://127.0.0.1:9000  
- **Default login:** `admin` / `admin` (change after first login; hash is set via `GRAYLOG_ROOT_PASSWORD_SHA2` in `.env`)

### Host tuning (Linux only)

OpenSearch may require `vm.max_map_count` on bare-metal Linux:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Docker Desktop on macOS usually handles this; only apply on native Linux.

### macOS: `docker-credential-osxkeychain` not found

If `docker compose pull` / `up` fails with **executable file not found** for `docker-credential-osxkeychain`, your shell can see `docker` but not Docker Desktop’s helper binaries. Either:

- Run **`bash scripts/fix_docker_cli_macos.sh`** (links `docker` and **credential helpers** into `/usr/local/bin`), then open a **new** terminal, or  
- Prepend Docker’s bin once: `export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"` and retry.

## Ports (published to localhost)

| Port | Protocol | Purpose |
|------|----------|---------|
| 9000 | TCP | Graylog web UI + REST API |
| 5044 | TCP | Beats (e.g. Winlogbeat / Filebeat) |
| 5140 | TCP/UDP | Syslog |
| 12201 | TCP/UDP | GELF |
| 5555 | TCP/UDP | Raw / plaintext |
| 13301–13302 | TCP | Forwarder (optional) |
| 5432 | TCP | PostgreSQL (alerts / explanations) |
| 5000 | TCP | Flask dashboard (default; see `FLASK_PORT`) |

OpenSearch is **not** exposed to the host by default; Graylog uses it on the internal Docker network (`http://opensearch:9200`).

## PostgreSQL + correlation CLI

After `docker compose up -d`, Postgres listens on **127.0.0.1:5432** with credentials from `.env` (`POSTGRES_*`). Tables are created automatically on **first** database init via [`db/init.sql`](db/init.sql).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m diy_siem test-db          # insert one test alert row
python -m diy_siem poll             # query Graylog, insert alert + optional Ollama explanation
python -m diy_siem list-alerts      # show recent rows
python -m diy_siem explain 2        # generate/store AI text for alert id 2 (Ollama must be running)
python -m diy_siem serve            # dashboard at http://127.0.0.1:5000/
python -m diy_siem graylog-bootstrap  # Syslog UDP extractors + DIY-SIEM streams (idempotent)
```

Send a test syslog first (`./scripts/send_test_syslog.sh`) so `poll` has something to match (`diy-siem` in the message). The demo rule deduplicates for **10 minutes** per run.

For **structured fields** (`src_ip`, `user`, `event`, `win_event_id`) and **stream routing**, run `graylog-bootstrap` after inputs exist, then send `./scripts/send_auth_sample_syslog.sh` and confirm fields under **Search** → message details.

### Ollama (local LLM)

Install [Ollama](https://ollama.com/) on the same machine and pull a model (names must match `OLLAMA_MODEL` in `.env`):

```bash
ollama pull llama3.2
```

Ensure Ollama is running (`ollama serve` is usually automatic). If Ollama is offline, set `OLLAMA_ENABLED=false` in `.env` so `poll` still creates alerts without calling the LLM.

### Flask dashboard

`python -m diy_siem serve` serves a light-themed UI with **Chart.js** charts (alerts by rule / severity) and a table showing each alert’s **AI explanation** when present. APIs: `/api/stats`, `/api/alerts`. The page **auto-refreshes every 30 seconds** (and when you return to the tab), so after you run `poll` new alerts show up without restarting Flask or clicking **Refresh**. Use **Download PDF** (or `GET /api/report.pdf`) to save the same summary and alert table as a PDF. Optional **HTTP Basic Auth** for local `serve` uses the same `DASHBOARD_*` variables in `.env` (see below).

**Run the dashboard without a local `python -m diy_siem serve`:** after `cp .env.example .env` and `docker compose up -d` for the stack, start the optional dashboard container with:

```bash
docker compose --profile dashboard up -d --build
```

Then open http://127.0.0.1:5000/ . The container uses `POSTGRES_HOST=postgres` and `GRAYLOG_API_URL=http://graylog:9000` on the Compose network. For Ollama on the host, `OLLAMA_BASE_URL` defaults to `http://host.docker.internal:11434` in that service (Docker Desktop Mac/Windows); on Linux, set `OLLAMA_BASE_URL` in `.env` to your host IP or gateway.

**Dashboard HTTP Basic Auth (optional):** set `DASHBOARD_AUTH_ENABLED=true` in `.env` with `DASHBOARD_USER` and `DASHBOARD_PASSWORD`. When enabled, the browser prompts for credentials before `/`, `/api/stats`, `/api/alerts`, `/api/report.pdf`, and `/static/*`. The same username and password apply to every client (shared lab login). Use HTTPS or localhost-only binding in real deployments; Basic Auth over plain HTTP on a network is weak.

If auth stays off: set `DASHBOARD_AUTH_ENABLED=true` in the **`.env` file in your project root** (not only `.env.example`), then **restart** `serve`. Run `python -m diy_siem serve` from the **repository directory** so `.env` is found, or export the variables in your shell.

Use **one hostname consistently** in the browser (`http://127.0.0.1:5000` *or* `http://localhost:5000`). Mixing them treats Basic Auth as two different sites, so the password may not apply to API calls.

**Note:** If you already had an empty Postgres volume and add Postgres later, either remove the volume (`docker compose down -v` — **wipes Graylog data too**) or apply `db/init.sql` manually with `psql`.

## Prove ingestion (Graylog inputs → extractors → streams)

1. **Create inputs in Graylog** (one-time): **System → Inputs** → choose **Syslog UDP** → **Launch new input** → bind `0.0.0.0`, port **5140**, save.  
   Or run `./scripts/bootstrap_inputs.sh` after the API is up (creates **Syslog UDP 5140**, **GELF TCP 12201**, and **Beats TCP 5044** if missing).

2. **Extractors + streams (automated):** after inputs exist and Graylog API answers, run:

   ```bash
   python -m diy_siem graylog-bootstrap
   ```

   This attaches **regex extractors** on the Syslog UDP input (port **5140**) for `src_ip=…`, `user=…`, `username=…`, `event=…`, and Windows-style `EventID=…`, then creates/resumes three streams:

   - **DIY-SIEM Lab** — `message` **contains** `diy-siem` (matches hello + auth samples + GELF tests whose `short_message` includes the marker).  
   - **DIY-SIEM Authentication** — `message` **contains** `diy-siem auth`.
   - **DIY-SIEM Web** — `message` **contains** `diy-siem web`.

   Implementation: [`diy_siem/graylog_setup.py`](diy_siem/graylog_setup.py) (idempotent; safe to re-run).

3. **Send a test message** (either path):

   ```bash
   ./scripts/send_test_syslog.sh
   ./scripts/send_auth_sample_syslog.sh   # structured key=value + Windows-style line for extractors
   ./scripts/send_realistic_linux_sshd.sh   # sshd-like failed/success lines (brute-force + login demos)
   ./scripts/send_realistic_apache_nginx.sh # Apache/nginx combined log-style lines (web stream)
   ./scripts/send_realistic_windows_events.sh # Windows EventID-style syslog (4625/4624/4672)
   ./scripts/send_all_demo_logs.sh          # runs the above plus hello + GELF samples
   # or, after GELF input exists:
   ./scripts/send_test_gelf.sh
   ./scripts/send_winlogbeat_style_gelf.sh  # GELF with Winlogbeat-like fields
   ```

4. In the UI: **Search** → set time range to **Last 5 minutes** → open a message → confirm extracted fields. **Streams** → open **DIY-SIEM Lab** / **DIY-SIEM Authentication** / **DIY-SIEM Web** → **Manage stream** → **Test stream** with a recent message id if you want to verify routing.

### Log sources (Linux, Windows, web)

| Source | Path into Graylog | Example in this repo |
|--------|-------------------|----------------------|
| Linux (`rsyslog`, etc.) | Syslog UDP/TCP **5140** | [`examples/rsyslog-forward-graylog.conf`](examples/rsyslog-forward-graylog.conf) (commented template) |
| Filebeat (Apache/nginx files) | Beats **5044** | [`examples/filebeat-graylog.yml`](examples/filebeat-graylog.yml) (`output.logstash.hosts`) |
| Winlogbeat (Security channel) | Beats **5044** | [`examples/winlogbeat-graylog.yml`](examples/winlogbeat-graylog.yml) |

Run `./scripts/bootstrap_inputs.sh` so **Beats TCP 5044** exists before starting Filebeat or Winlogbeat. Scripted demos use **Syslog** and **GELF** because the Beats wire protocol requires a real Beat agent; the YAML files are for attaching actual hosts or VMs to the lab stack.

**REST examples (Graylog 6.x):**

- **Relative search** (same API the correlator uses — see [`diy_siem/graylog.py`](diy_siem/graylog.py)):

  `GET /api/search/universal/relative?query=diy-siem&range=300&limit=50&sort=timestamp:desc`

- **Create a stream** (what `graylog-bootstrap` does under the hood): `POST /api/streams` with JSON body  
  `title`, `index_set_id` (from `GET /api/system/indices/index_sets`, pick the set with `"default": true`), `matching_type` (`OR` / `AND`), `remove_matches_from_default_stream`, and `rules` entries with `type` **6** = *contain*, `field`, `value`, `inverted`. Then `POST /api/streams/{streamId}/resume` to start processing.

- **Create an extractor**: `POST /api/system/inputs/{inputId}/extractors` with `extractor_type` `regex`, `source_field` `message`, `target_field`, `cursor_strategy` `copy`, `extractor_config` `{ "regex_value": "..." }`, `converters` `[]`, `condition_type` `none`, `condition_value` `""`, `order`.

**Optional — native Graylog alert (Event definition + notification):** in the UI, use **Alerts → Event definitions → Create event definition** (for example an **aggregation** on stream **DIY-SIEM Authentication**, count ≥ 1 in 1 minute). Under **Notifications**, add an **HTTP Notification** (e.g. POST to a local test listener or a disposable webhook URL) and attach it to the definition. That path is separate from the Python `poll` job and shows Graylog’s own alerting in a viva or report.

## Credentials summary

| Item | Value / location |
|------|------------------|
| Graylog UI | `admin` / `admin` (default; from `GRAYLOG_ROOT_PASSWORD_SHA2` for `admin`) |
| `GRAYLOG_PASSWORD_SECRET` | Long random string in `.env` (not the user password) |
| OpenSearch initial admin | `OPENSEARCH_INITIAL_ADMIN_PASSWORD` in `.env` (container bootstrap; security disabled in this demo compose) |
| PostgreSQL | `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` in `.env` |
| Graylog API (Python) | `GRAYLOG_API_URL`, `GRAYLOG_USERNAME`, `GRAYLOG_PASSWORD` |
| Ollama | `OLLAMA_BASE_URL` (default `http://127.0.0.1:11434`), `OLLAMA_MODEL`, `OLLAMA_ENABLED` |
| Flask | `FLASK_HOST`, `FLASK_PORT` |

## Python venv

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Branding: “Amrita” vs Graylog UI

- **Your Flask dashboard** (`python -m diy_siem serve`) is fully yours: set **`SIEM_BRAND_NAME`** and **`SIEM_BRAND_TAGLINE`** in `.env`, and put a file named **`logo.png`**, **`logo.svg`**, or **`logo.webp`** in [`diy_siem/static/`](diy_siem/static/) (see [`diy_siem/static/README.txt`](diy_siem/static/README.txt)). A default `logo.svg` ships as a placeholder—replace it with your institute logo.
- **Inside Graylog’s own web UI**, full **custom logo / global theme** is a **Graylog Enterprise** feature ([docs](https://go2docs.graylog.org/current/setting_up_graylog/custom_themes_and_notifications.html)). On **Graylog Open** (this project’s `graylog/graylog` image), the product name/logo stay Graylog. For your report/viva, describe **Amrita SIEM** as your system with **Graylog as the log backbone**; screenshots can label “log backend (Graylog)” vs “Amrita dashboard (Flask)”.

## Where logs are collected (ingress)

Anything that sends data to a **Graylog input** you have started appears in **Search**. With the default Compose port map, typical paths are:

| Path | What sends | Compose host port |
|------|------------|-------------------|
| **Syslog UDP** | Scripts, `rsyslog`, network devices, apps | **5140/udp** |
| **Syslog TCP** | Same, over TCP | **5140/tcp** |
| **GELF TCP/UDP** | Apps, containers, structured logs | **12201** |
| **Beats** | **Winlogbeat**, Filebeat, etc. | **5044** |
| **Raw/plaintext** | Quick tests | **5555** |

In Graylog: **System → Inputs** lists each input, its bind address, and throughput—use that screen to prove **what is listening** and **which node** is receiving. **Streams** then route subsets of those messages to indexes or dashboards.

**PostgreSQL** in this project stores **alerts + AI text**, not full raw log retention (that lives in **Graylog/OpenSearch**).

## Alerts inside Graylog (native)

Graylog can raise its own alerts without Python:

1. **Alerts** (or **Alerts & Events** in newer menus) → **Event definitions** → **Create event definition**.
2. Choose a **condition** (e.g. filter + aggregation: count of messages, group by field, threshold in a time window).
3. Add a **notification** (e.g. **HTTP notification** to a webhook, email if configured).
4. Optionally add **Event notifications** under **System → Notifications**.

Use this for **in-Graylog** alerting; use **Python `poll`** + Postgres for **correlation + Ollama** on top of the same data via the REST API.

## Test messages with higher syslog severity

[`scripts/send_test_syslog.sh`](scripts/send_test_syslog.sh) uses **local0** and a configurable **severity** (RFC5424-style numeric mapping in the PRI):

```bash
./scripts/send_test_syslog.sh 127.0.0.1 5140 crit
SEND_TEST_SYSLOG_SEVERITY=error SEND_TEST_SYSLOG_MESSAGE="sshd: Failed password for root from 192.0.2.10" ./send_test_syslog.sh
```

Severities: `emerg` `alert` `crit` `err` `warn` `notice` `info` `debug`. Graylog may still map **level** fields differently for GELF vs syslog—check the **message fields** in the UI.

## More correlation rules you can add (Python + Graylog search)

Build rules as new functions (like `run_demo_rule`) that run **Graylog searches** and insert **Postgres** alerts with appropriate **`severity`** and **`mitre_technique`**:

| Rule idea | Graylog / field hint | Notes |
|-----------|----------------------|--------|
| **Brute force logins** | Many `failed` / `failure` / Windows 4625 in a window, group by source IP | Needs auth logs + optional extractors |
| **Credential stuffing** | Burst of failures then success for same user/source | Two-phase search or pipeline |
| **After-hours admin** | Success logins outside business hours | Parse time + user/group |
| **Port scan** | Many distinct `destination_port` from one source (firewall/syslog) | Firewall or Zeek-style logs |
| **Privilege escalation** | Linux `sudo`, Windows 4672 / membership changes | OS-specific event IDs |
| **Lateral movement** | Same user/session, new internal host, rare tools (PsExec, WMI) | Noisy; tune carefully |
| **Web anomalies** | HTTP 4xx/5xx spikes, suspicious paths (`/.env`, `/wp-admin`) | Apache/nginx in Graylog |

Start with **one rule** and **clear thresholds** to control false positives; add **MITRE** IDs (e.g. `T1110`) in `mitre_technique` for the report.

## References

- [Graylog Docker + OpenSearch](https://go2docs.graylog.org/current/downloading_and_installing_graylog/docker_installation_os.htm)
- [Graylog REST API](https://go2docs.graylog.org/current/interacting_with_graylog/rest_api.html)
