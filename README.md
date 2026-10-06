# Key Vault: access policies to Azure RBAC

A CSV-driven toolkit for migrating every Azure Key Vault in a tenant from the legacy access policy permission model to Azure RBAC, without losing anyone's access along the way. Two PowerShell scripts, an Azure Monitor workbook, pipeline definitions for Azure DevOps and GitHub Actions, and a runbook. Used to migrate a multi-subscription production tenant in waves with zero access incidents.

## How it works

```
1 Export --> 2 Consolidate --> 3 Plan + Groups --> 4 Assign --> 5 Verify --> 6 Flip
```

1. **Export** every access policy on every vault in the tenant to CSV. Identities are resolved through Microsoft Graph, legacy `all` permissions are expanded, the least-privileged built-in role that covers each entry is suggested from the live role definitions, and 90 days of real usage from Key Vault `AuditEvent` logs is joined on.
2. **Consolidate** in a spreadsheet: decide per identity whether it joins an admin group (`Group`), gets a direct role (`Direct`), is dropped (`Drop`) or is out of scope (`Skip`), and assign a wave.
3. **Plan** prints exactly what will change. **Groups** creates the Entra security groups and members.
4. **Assign** creates the role assignments at vault or resource group scope. On an access policy vault these are inert, so this step has no user impact.
5. **Verify** re-reads live state, expands transitive group membership, and proves every access policy identity keeps its data actions after the flip. Exit code 1 on any gap.
6. **Flip** sets `EnableRbacAuthorization = true`, one wave at a time. Access policies stay on the vault, so **Rollback** is a single property write.

Everything is idempotent and every state change honours `-WhatIf`. Full detail in [docs/runbook.md](docs/runbook.md).

## Quick start

```powershell
Connect-AzAccount -Tenant <tenantId>

# 1. Inventory (Reader + directory read; workspace ID optional)
.\scripts\Export-KvAccessPolicyInventory.ps1 -OutputFolder .\KvInventory -LogAnalyticsWorkspaceId <workspace customer ID>

# 2. Fill TargetGroupName / TargetRole / Action / Wave in Excel, save as KvPlan-<tenant>.csv
#    (see data/KvPlan-sample.csv and docs/plan-csv-reference.md)

# 3 to 6. Execute wave 1 with resource group scoped admin groups
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Plan   -GroupScope ResourceGroup -Wave 1
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Groups -Wave 1
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Assign -GroupScope ResourceGroup -Wave 1
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Verify -Wave 1
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Flip   -Wave 1 -WhatIf
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Flip   -Wave 1

# If the soak period shows ForbiddenByRbac denials
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Rollback -VaultName <vault>
```

## Repository layout

| Path | Contents |
|---|---|
| `scripts/Export-KvAccessPolicyInventory.ps1` | Step 1. Inventory of access policies, vault-scope role assignments and usage. |
| `scripts/Invoke-KvRbacMigration.ps1` | Steps 3 to 6 plus Rollback, driven by the plan CSV. |
| `data/KvPlan-sample.csv` | Fictional plan showing every `Action`, multi-role rows, `TargetScope` overrides and platform groups. |
| `data/AccessPolicyRBACMapping.csv` | Access policy permission to RBAC data action mapping (from Microsoft's compare tool). Also embedded in both scripts. |
| `workbooks/` | `KeyVault-Audit.workbook.json` (six tabs, including RBAC Migration), a deploy script and ARM template. [Details](workbooks/README.md). |
| `pipelines/` | Azure DevOps pipeline with approval-gated state changes. |
| `.github/workflows/` | GitHub Actions equivalent, plus CI (PSScriptAnalyzer + Pester). |
| `docs/` | [Runbook](docs/runbook.md), [plan CSV reference](docs/plan-csv-reference.md), [group naming convention](docs/group-naming-convention.md), [permissions](docs/permissions.md), [pipelines](docs/pipelines.md), [change record template](docs/change-record-template.md), [rollback](docs/rollback.md). |
| `tests/` | Pester structure tests (no Azure connection needed). |

## The plan CSV in one table

| Column | You set it to |
|---|---|
| `Action` | `Group` (add identity to an Entra group that holds the role), `Direct` (role straight on the identity), `Drop` (do not carry over), `Skip` (out of scope; a vault whose rows are all Skip is never touched). |
| `TargetGroupName` | For `Group` rows. Suggested standard: `RBAC_RG_<ResourceGroup>_KVAdmin` for one RG, `RBAC_KV_<Platform>_Admin` for a platform spanning several RGs, with the scope rule in `TargetGroupDescription`. |
| `TargetRole` | One or more role names, `;` separated. Start from the exported `SuggestedRole`. |
| `TargetScope` | Optional resource group or subscription ID that overrides the scope for that row. |
| `Wave` | Any label; `-Wave` filters on it. |

Scope choice: `-GroupScope ResourceGroup` assigns group roles once per resource group, covering current and future vaults in it. The script warns when an RG assignment also reaches vaults outside the run and whether those are already live (RBAC) or inert (access policy). `TargetScope` does the same per row.

## Safety properties

- Nothing changes until `Groups`. `Export`, `Plan` and `Verify` are read only.
- Role assignments are created before the flip and are ignored by access policy vaults, so `Assign` cannot break anything on an unflipped vault.
- `Verify` compares the mapped data actions of every live access policy against the effective RBAC coverage (direct, inherited and via transitive group membership) and refuses to pass with a `GAP` or `NO-ROLE`.
- `Flip` never removes access policies. `Rollback` restores the previous model instantly.
- Orphaned and foreign-tenant identities are never added to groups or given assignments, whatever the plan says.
- Every run writes a CSV log (verify report, flip and rollback change logs) for the change record.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 with `Az.Accounts`, `Az.Resources`, `Az.KeyVault`, `Az.Monitor` (and `Az.OperationalInsights` for usage). Az 16.3.0 or later recommended.
- Rights per step in [docs/permissions.md](docs/permissions.md). Export needs Reader plus directory read; Flip needs Owner-level rights on the vaults because the Key Vault resource provider demands unrestricted `roleAssignments/write` to change the permission model.
- For usage enrichment and the workbook: diagnostic settings on the vaults sending `AuditEvent` to a Log Analytics workspace in Azure Diagnostics mode.

## Attribution

The access policy to RBAC data action mapping comes from Microsoft's [Azure/KeyVault-AccessPolicyToRBAC-CompareTool](https://github.com/Azure/KeyVault-AccessPolicyToRBAC-CompareTool) (MIT, now archived). That tool compares one vault interactively; this toolkit takes the same mapping and applies it tenant-wide with a plan, a gate and a rollback.

## Licence

[MIT](LICENSE).
