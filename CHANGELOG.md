# Changelog — PowerScale Migration Collector

All notable changes are documented here.

---

## [v4.0] — 2026-04-28  *(Current)*

### 🔐 Auth — Complete Rewrite
- **Replaced Basic auth with correct OneFS PAPI session-cookie mechanism**
- `POST /session/1/session` → `isisessid` cookie + `isicsrf` CSRF token
- All subsequent requests carry `X-CSRF-Token` + `Referer` headers
- Passwords sent as JSON body — all special characters fully supported
- Credentials exist in Python server memory only — never written to disk, logs, or browser storage

### ✅ Confirmed Working PAPI Paths (OneFS 9.10.1.3)
The following paths are verified and the only ones used — all 404 paths removed:

| Endpoint | PAPI Path |
|---|---|
| Cluster Identity | `/platform/3/cluster/identity` |
| Cluster Config | `/platform/3/cluster/config` |
| Node List + Detail | `/platform/3/cluster/nodes` + `/platform/3/cluster/nodes/{lnn}` |
| Node Time | `/platform/3/cluster/time` (timestamps only — no NTP config via PAPI) |
| Events | `/platform/3/event/eventlists` |
| Jobs | `/platform/3/job/jobs` |
| Licenses | `/platform/5/license/licenses` |
| NFS Exports | `/platform/2/protocols/nfs/exports` |
| SMB Shares | `/platform/4/protocols/smb/shares` |
| Quotas | `/platform/1/quota/quotas` |
| Snapshots | `/platform/1/snapshot/snapshots` |
| SyncIQ Policies | `/platform/3/sync/policies` |
| Storage Pools | `/platform/7/storagepool/nodepools` |
| Auth Providers | `/platform/3/auth/providers/summary` |
| Auth Roles | `/platform/3/auth/roles` |
| Statistics Keys | `/platform/1/statistics/keys` |
| Statistics Current | `/platform/1/statistics/current` |

### ❌ Confirmed 404 on OneFS 9.10.1.3 — Removed
- `/platform/x/cluster/time/settings` — NTP config not exposed via PAPI
- `/platform/x/cluster/time/settings/servers` — same
- `/platform/x/ntp/servers` — same
- `/platform/1/session/1/privileges` — use `/platform/3/auth/roles` instead

### 🗂 Data Collection — New Domains
Added 12 new API endpoints mapped from the **Migration Plan** (8 sheets analysed):

| Domain | Endpoint | Migration Plan Reference |
|---|---|---|
| Critical Events | `/api/events` | Checklist #3, #10 |
| Cluster Jobs | `/api/jobs` | Checklist #9 |
| Feature Licenses | `/api/licenses` | Checklist #1, Risk R-12 |
| NTP / Time Sync | `/api/ntp` | Checklist #8, Risk R-11 |
| Auth Providers | `/api/auth/providers` | Checklist #19, Risk R-08 |
| Performance Baseline | `/api/statistics/current` | Checklist #22-23, Post-val #18-20 |
| Network Pools | `/api/network/pools` | Checklist #15 |
| Upgrade Status | `/api/upgrade/status` | Runbook #5-10 |
| Snapshot Schedules | `/api/snapshots/schedules` | Checklist #11 |
| SyncIQ Reports | `/api/synciq/reports` | Runbook #3 |
| Storage Pool Health | `/api/storagepool/health` | Post-val #3-4 |
| Statistics Clients | `/api/statistics/clients` | Checklist #23 |

### 🔢 Node Inventory — Two-Step Fetch
- List endpoint returns shallow stubs only
- Per-LNN detail fetch: `GET /platform/3/cluster/nodes/{lnn}` for full hardware
- Extracts: `hardware.configuration_id`, `hardware.serial_number`, `hardware.cpu{model,proc}`, `hardware.memory_size`, `drives[].{blocks, logical_block_length, media_type, ui_state}`, `status.{batterystatus, nvram, powersupplies, release, capacity}`, `state.{readonly.status, smartfail.dead}`

### 📊 Statistics — Key Auto-Discovery
- Fetches `/statistics/keys?limit=500` first to discover valid key names
- Pattern-matches IOPS keys (`ops` + `total/read/write` + `rate`) automatically
- Computes `iops_total = iops_read + iops_write` when no explicit total key exists
- Falls back to `/statistics/summary/protocol` if keys unavailable

### ⏱ NTP — Manual Server Entry
- `/cluster/time/settings` returns 404 on this cluster — NTP servers not in PAPI
- Node timestamps (`/cluster/time`) used for drift detection across all 4 nodes
- Manual NTP server entry via UI: `POST /api/ntp/manual` stores in session memory
- Node drift table shows sync status with 5-second threshold

### 📋 Excel Export (openpyxl) — 11 Sheets
Added **Migration Health** sheet, fixed all field extraction issues:

| Sheet | Status |
|---|---|
| Summary | ✅ Collection status per domain |
| Cluster | ✅ Identity + config |
| Nodes | ✅ Fixed: Memory, Disk, CPU, Status, Model all populated |
| NFS Exports | ✅ Fixed: Map Root `nobody` (was `{"id":"USER:nobody"}`) |
| SMB Shares | ✅ |
| Quotas | ✅ |
| Snapshots | ✅ |
| SyncIQ Policies | ✅ Always created (even if 0 policies) |
| Storage Pools | ✅ Fixed: Protection from `data_protection.requested_protection` |
| Access Zones | ✅ |
| **Migration Health** | ✅ **New** — Events, Jobs, Licenses, NTP, Auth, Perf baseline |

### 🌐 HTML Report — Complete Rewrite
- Node Status: parsed from `state.readonly.status` dict (was `[object Object]`)
- Node columns: 10 columns including CPU, Memory, Disk, Drives, Release
- NFS Map Root: `nobody` (was `[object Object]` — `map_root.user.id` nested dict)
- Storage Pools: Protection from `data_protection.requested_protection`
- Collection Date: local readable format (was UTC ISO string)
- All boolean fields: `Read-Write`/`Read-Only`, `Browsable`/`Hidden` (was `true`/`false`)

### 🔧 Bug Fixes
| Bug | Fix |
|---|---|
| `&#10003;` showing literally in sidebar badges | `setBadge()` switched to `innerHTML` |
| `&#9654; Re-run Collection` on button | Button resets use `innerHTML` not `textContent` |
| `Connected · AMGPSFS` showing `&#183;` | Replaced with literal `·` Unicode character |
| Statistics 400 error | Fixed `&key=` embedded in URL string — now proper query params |
| Memory always `—` | Exhaustive key scan across `hardware{}`, `status{}`, node root |
| CPU showing raw dict | Extracts `cpu.model` + `cpu.proc`, builds `Intel @ 2.19GHz (10-core)` |
| Disk Capacity (HDD) always `—` | Renamed to `Total Disk Cap.` — SSD = total on all-flash F200 |
| `[object Object]` in NFS Map Root | Three-level extraction: `map_root.user.id` → strip `USER:` → `nobody` |
| Pool protection `—` | Now checks `data_protection.requested_protection` fallback |
| Duplicate Migration Health sheet | Removed duplicate from partial fix |

### 🔒 Offline / Air-Gap Ready
- Removed Google Fonts CDN link (`fonts.googleapis.com`)
- System font stacks: `Consolas` / `Segoe UI` (Windows), `SF Pro` (macOS)
- Zero external internet dependencies — only connects to OneFS cluster and `127.0.0.1:5050`

---

## [v3.0] — 2026-04-27

- Switched from Basic auth to session-cookie auth (initial implementation)
- Added Excel export with openpyxl
- Added migration health domains (Events, Jobs, Licenses, NTP, Stats, Auth)
- Added two-step node detail fetch

---

## [v2.0] — 2026-04-26

- Switched from `urllib` to `requests.Session()`
- Added API version fallback chains
- Added `/api/rawtest` diagnostic endpoint
- Added graceful `_privilege_denied` handling

---

## [v1.0] — 2026-04-25

- Initial Flask proxy + embedded HTML dashboard
- Basic auth (deprecated — did not work for data endpoints)
- JSON / CSV / HTML export
