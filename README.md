# SharePointAgent

> **Documents found. Teams notified.** Automated SharePoint site indexing,
> intelligent document search, and a Microsoft Teams bridge for multi-tenant
> environments.

[![License: MIT](https://img.shields.io/badge/License-MIT-success.svg)](LICENSE)
[![Part of TenantFleet](https://img.shields.io/badge/TenantFleet-Body-2e7d32)](https://t-granlund.github.io/tenantfleet/)
[![Live demo](https://img.shields.io/badge/demo-live-1f6feb)](https://t-granlund.github.io/sharepoint-agent/)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft-Graph%20API-0078d4)](#architecture)

SharePointAgent is a **Body**-pillar member of the
[TenantFleet](https://t-granlund.github.io/tenantfleet/) ecosystem. It brings
document intelligence to multi-tenant Microsoft 365 estates: crawl SharePoint
sites, search across libraries, audit permissions against Entra group
membership, and bridge document lifecycle events into Microsoft Teams.

---

## Why it exists

In a multi-brand estate, documents and their permissions sprawl across dozens of
SharePoint sites. Nobody can answer "who can see this folder?" or "where did
that document go?" without a manual slog. SharePointAgent makes site contents
and permissions **enumerable, searchable, and auditable**.

## What it delivers

| Capability | What it does |
| --- | --- |
| **Site indexing** | Crawl SharePoint sites across tenants with delta sync and metadata extraction. |
| **Document search** | Full-text search across libraries with filters for site, author, date, and content type. |
| **Teams notifications** | Push document alerts, approvals, and lifecycle events directly to Teams channels. |
| **Permission audit** | Map and audit SharePoint permissions against Entra group membership and guest access. |
| **Lifecycle management** | Retention, archival, and deletion policies based on document age and sensitivity labels. |
| **Graph API integration** | Built on Microsoft Graph with retry logic, batching, and delta query support. |

**At a glance:** ∞ sites indexed · ∞ documents processed · ∞ Teams channels ·
&lt; 2s search latency.

## Install

```bash
git clone https://github.com/t-granlund/sharepoint-agent.git
cd sharepoint-agent
pip install requests        # the audit scripts use requests + the Azure CLI
```

The permission-audit scripts authenticate via a Graph token (`GRAPH_TOKEN`) and
the Azure CLI (`az account get-access-token`) for the SharePoint REST resource:

```bash
export GRAPH_TOKEN="$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)"
```

## Usage

### TypeScript client (indexing + search)

```ts
import { GraphClient } from "@tenantfleet/sharepoint-agent";

const client = new GraphClient({
  tenantId: process.env.TENANT_ID,
  clientId: process.env.CLIENT_ID,
  credential: new ClientSecretCredential(/* ... */),
});

// Index all sites for a tenant
const sites = await client.sites.deltaQuery({
  filter: "createdDateTime ge 2026-01-01",
});
await indexer.syncDocuments(sites);
```

### Permission-audit pipeline (Python, in `scripts/`)

The repo ships a real three-phase SharePoint permission audit you can run today:

```bash
# Phase A — durable Graph enumeration of a site's document tree
python scripts/audit_phaseA_enum.py        # → audit_output/phaseA_enumeration.json

# Phase B — per-item unique-permission (HasUniqueRoleAssignments) audit via SPO REST
python scripts/audit_phaseB_inheritance.py # → audit_output/phaseB_inheritance.json

# Phase C — reporting: CSV, tree markdown, and risk analysis
python scripts/audit_phaseC_report.py      # → CSV + markdown reports
```

## Architecture

```
Phase A: Microsoft Graph ──► durable enumeration (checkpointed, atomic writes)
              │                       │
              ▼                       ▼
   audit_output/phaseA_enumeration.json
              │
Phase B: SharePoint REST ──► HasUniqueRoleAssignments per item (token auto-refresh)
              │                       │
              ▼                       ▼
   audit_output/phaseB_inheritance.json
              │
Phase C: report generator ──► CSV flat report + tree markdown + risk analysis
```

- **Phase A — enumeration.** Walks the site's document tree via Microsoft Graph
  with checkpointing and atomic JSON writes, so a long crawl survives
  interruption.
- **Phase B — inheritance.** Calls the SharePoint REST API
  (`HasUniqueRoleAssignments`) for every item to find where permission
  inheritance is broken, refreshing the SPO access token as needed.
- **Phase C — reporting.** Consumes Phase B output and emits a flat CSV, a tree
  markdown view, a permissions CSV, and a risk-analysis report.

The TypeScript `GraphClient` covers the indexing/search/Teams product surface;
the Python scripts are the concrete, runnable audit pipeline.

## Security

- **Least privilege** — read-oriented Graph + SPO scopes for enumeration/audit.
- **No long-lived secrets in the audit path** — tokens come from `az` / Graph
  and are refreshed in-process.
- **Auditable by design** — the whole point is producing an evidence trail.

## Part of the TenantFleet ecosystem

| Repo | Pillar | Focus |
| --- | --- | --- |
| [TenantFleet](https://t-granlund.github.io/tenantfleet/) | — | Root governance framework |
| [HubForge](https://t-granlund.github.io/hubforge/) | Mind | Azure SWA + Entra deployment templates |
| [EntraGroups](https://t-granlund.github.io/entragroups/) | Body | Group lifecycle + persona RBAC |
| [TenantForge](https://t-granlund.github.io/tenantforge/) | Mind | Terraform tenant provisioning |
| [DNSGuard](https://t-granlund.github.io/dnsguard/) | Spirit | Domain + DMARC intelligence |
| [RampGuard](https://t-granlund.github.io/rampguard/) | Mind | Finance compliance + spend |
| **SharePointAgent** | Body | SharePoint indexing + Teams |

See the full ecosystem on the portfolio:
[tylergranlund.com/work#ecosystem](https://tylergranlund.com/work#ecosystem).

## License

MIT — see [LICENSE](LICENSE). Fork it, deploy it, make it yours.
