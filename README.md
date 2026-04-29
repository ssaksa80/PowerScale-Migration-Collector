# 🔷 PowerScale / Isilon OneFS — Migration Data Collector  v4.0

> **Developer:** SHAIKH SHOAIB · Sr. Advisor Delivery Specialist  
> **Target:** Dell PowerScale / Isilon OneFS 9.10.1.3  
> **Auth:** `POST /session/1/session` → `isisessid` + `isicsrf` CSRF

---

## 🚀 Quick Start

```bash
pip install flask requests urllib3 openpyxl
python powerscale_collector.py
# Open: http://localhost:5050
```

## 🔑 Role Setup (OneFS CLI)

```bash
isi auth roles create --name MigrationCapture --description "Read-only migration data collection"
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_LOGIN_PAPI
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_CLUSTER
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_DEVICES
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_NETWORK
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_NFS
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SMB
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_QUOTA
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SNAPSHOT
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SYNCIQ
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SMARTPOOLS
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SMARTPOOLS_STORAGEPOOL
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SMARTPOOLS_STORAGEPOOL_NODEPOOLS
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SMARTPOOLS_STORAGEPOOL_POOLDETAILS
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SMARTPOOLS_STORAGEPOOL_POOLDETAILS_USAGE
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SMARTPOOLS_STORAGEPOOL_TIERS
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_SMARTPOOLS_STATUS
isi auth roles modify MigrationCapture --add-priv-read ISI_PRIV_AUTH
isi auth roles modify MigrationCapture --add-user admin
isi auth roles view MigrationCapture
```

> `ISI_PRIV_STORAGEPOOL` does not exist — use `ISI_PRIV_SMARTPOOLS_*` variants

## ❌ Paths that return 404 on OneFS 9.10.1.3

```
/platform/x/cluster/time/settings    NTP config not in PAPI
/platform/x/ntp/servers              same
/platform/1/session/1/privileges     use /platform/3/auth/roles
```

**NTP servers:** CLI only — `isi ntp servers list` — enter manually in tool UI.

## 🔁 Update Repository

```bash
cd PowerScal_Isilon
git add powerscale_collector.py README.md CHANGELOG.md
git commit -m "Release v4.0 — clean rewrite, all 404 paths removed, Excel/HTML fixes"
git tag -a v4.0 -m "PowerScale Migration Collector v4.0"
git push && git push origin v4.0
```

## 🗂 What It Collects

Cluster · Nodes (2-step per-LNN) · NFS Exports · SMB Shares · Quotas · Snapshots · SyncIQ · Storage Pools · Access Zones · Events · Jobs · Licenses · NTP Drift · Auth Providers · Performance Baseline

## 📊 Exports

| Format | Contents |
|--------|---------|
| Excel (.xlsx) | 11 sheets — Summary, Cluster, Nodes, NFS, SMB, Quotas, Snapshots, SyncIQ, Storage Pools, Access Zones, **Migration Health** |
| HTML Report | Full self-contained assessment document |
| JSON | Complete structured dataset |
| CSV | Per-domain tabular data |

## 👤 Author

**SHAIKH SHOAIB** · Sr. Advisor Delivery Specialist · Dell Technologies  
*OneFS 9.10.1.3 · Offline/air-gap ready · No external dependencies*
