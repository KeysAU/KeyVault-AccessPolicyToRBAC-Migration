# Key Vault Audit workbook

`KeyVault-Audit.workbook.json` is an Azure Monitor workbook over Key Vault `AuditEvent` diagnostics. It gives near-real-time and historical visibility of who touches which vault, and its RBAC Migration tab is the evidence base for the plan CSV and the post-flip soak period.

## Tabs

| Tab | What it answers |
|---|---|
| Overview | Ingestion health per vault (are all vaults logging?), ARM inventory versus ingestion, filtered KPI tiles. |
| Activity Explorer | Timeline of every operation: caller, object, vault, client app, authorisation path (`AccessPolicy`, `RBAC`, `Both`). |
| What Changed | Data plane writes, deletes and purges; vault configuration changes; control plane changes from the Activity Log (role assignments, access policies, diagnostic settings). |
| Who & How Often | Cadence per caller, drill-down to daily pattern, objects touched and exact operations used (least-privilege evidence). |
| Failures & Anomalies | 403s with the Key Vault deny reason, first-seen callers, off-hours user access, sensitive operations, source IPs per caller. |
| RBAC Migration | Permission model per subscription (ARG), authorisation path per vault, identities active on access policy vaults before the flip, which role assignment granted access after the flip, `ForbiddenByRbac` denials since the flip, permission model changes. |

## Prerequisites

1. Diagnostic settings on every vault sending the `AuditEvent` category to one Log Analytics workspace in **Azure Diagnostics** (legacy table) mode. All 31 queries read `AzureDiagnostics`; the resource-specific `AZKVAuditLogs` table is not used.
2. Activity Log export to the same workspace (`AzureActivity`) for the control plane grid on the What Changed tab. Everything else works without it.
3. Reader on the subscriptions holding the vaults, for the Azure Resource Graph grids (`resources`, `resourcecontainers`, `authorizationresources`).
4. Optional: Microsoft Sentinel UEBA (`IdentityInfo`). Department and job title columns on the Who & How Often tab resolve only when it exists; the query uses `union isfuzzy=true` so the tab works without it.

Key Vault only evaluates RBAC when the vault is on the RBAC permission model. On an access policy vault every successful call logs `isAccessPolicyMatch = true` and no RBAC evidence, whatever role assignments exist. `AuthPath = RBAC` therefore appears only after a vault flips, which is what makes the RBAC Migration tab a reliable before/after signal.

## Import

Portal: Azure Monitor > Workbooks > New > Advanced Editor (`</>`), paste the JSON, Apply, Save into the workspace's resource group. The portal rewrites `fallbackResourceIds` with the workspace you save into.

Script (idempotent, redeploys update the same workbook):

```powershell
Connect-AzAccount -Tenant <tenantId>
.\Deploy-KeyVaultAuditWorkbook.ps1 `
  -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>" `
  -TimeZone "Australia/Sydney"
```

`fallbackResourceIds` in the shipped JSON is a placeholder and must be replaced by one of the two methods above.

## Parameters worth knowing

- `Time_Zone` (default `UTC`): IANA time zone used by the off-hours analysis. Set it in the filter bar, or bake a default in with `-TimeZone` on the deploy script.
- `Resource Group (contains)` and `Caller (contains)`: comma separated partial matches, compiled into a regex by hidden parameters. Blank or `*` means all.
- `Time Range`: 5 to 30 minutes with auto refresh for live monitoring during a flip; 30 to 90 days for access reviews and plan evidence.

## Using it during the migration

- Before consolidation: RBAC Migration > "Before the flip: identities active on access policy vaults" over 90 days is the usage cross-check for the `Action` decision on every plan row.
- Before the flip: Overview > ingestion grid confirms every in-scope vault is logging, so a gap will actually show up.
- During the soak: Failures & Anomalies > Forbidden, filtered to `ForbiddenByRbac`, with a 30 minute auto-refreshing time range. Any row is a plan gap; fix with `Invoke-KvRbacMigration.ps1 -Action Assign` or roll back.
- After the flip: RBAC Migration > "After the flip: which role assignment granted each identity's access" proves the group assignments are the ones doing the work.
