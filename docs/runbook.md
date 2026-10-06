# Runbook: access policy to Azure RBAC, one tenant at a time

Six steps. Steps 1 and 2 produce the plan, steps 3 to 6 execute it in waves. Every command is idempotent and every state change honours `-WhatIf`, so re-running after a partial failure is safe.

```
1 Export --> 2 Consolidate --> 3 Plan + Groups --> 4 Assign --> 5 Verify --> 6 Flip
   (read)      (spreadsheet)     (Entra groups)     (RBAC, inert)  (gate)     (per wave)
                                                                                 |
                                                                  Rollback <-----+ (if the soak shows gaps)
```

## Before you start

| Item | Detail |
|---|---|
| PowerShell | Windows PowerShell 5.1 or PowerShell 7. |
| Modules | `Az.Accounts`, `Az.Resources`, `Az.KeyVault`, `Az.Monitor`; `Az.OperationalInsights` only for usage enrichment. Az 16.3.0 or later recommended. |
| Rights | See [permissions.md](permissions.md). Export needs only Reader plus directory read; Flip needs Owner-level rights on the vaults. |
| Logging | Diagnostic settings on every vault sending `AuditEvent` to one Log Analytics workspace, in Azure Diagnostics mode. Needed for the usage columns and for the [workbook](../workbooks/README.md). |
| Change control | A change record per tenant or per wave. Template in [change-record-template.md](change-record-template.md). |
| Time | Allow 15 minutes between Assign and Verify for role assignment propagation, and a soak of 24 to 48 hours per wave before the next one. |

Connect once per tenant. Rows for other tenants in the plan CSV are ignored automatically.

```powershell
Connect-AzAccount -Tenant <tenantId>
```

## Step 1: Export the inventory

```powershell
.\scripts\Export-KvAccessPolicyInventory.ps1 -OutputFolder .\KvInventory -LogAnalyticsWorkspaceId <workspace customer ID> -UsageDays 90
```

Outputs, all stamped with tenant ID and time:

- `KvAccessPolicies-<tenant>-<stamp>.csv`: one row per vault access policy entry (one placeholder row for vaults with none). Identities are resolved through Graph, legacy `all` permissions are expanded, a least-privilege built-in role is suggested from the live role definitions, and 90 days of usage is joined when a workspace ID is given. Orphaned identities are pre-set to `Action = Drop`.
- `KvRoleAssignments-<tenant>-<stamp>.csv`: every role assignment visible at vault scope, direct and inherited, flagged where the role carries Key Vault data actions. Use it to spot vaults that already have working RBAC.
- `KvUsage-<tenant>-<stamp>.csv`: raw usage query output.

Read the log summary at the end: vault count, how many are already on RBAC, principal type breakdown and the suggested role distribution. `REVIEW` in `SuggestedRole` means no scoped built-in role covers that permission set; those rows need a human decision.

## Step 2: Consolidate into the plan CSV

Open `KvAccessPolicies-<tenant>-<stamp>.csv` in Excel, fill the trailing columns, and save as `KvPlan-<tenant>.csv`. Column meanings are in [plan-csv-reference.md](plan-csv-reference.md); the naming standard is in [group-naming-convention.md](group-naming-convention.md).

Decision per row:

| Situation | Action | Notes |
|---|---|---|
| Human administrator or owner of the vault | `Group` | `TargetGroupName` per convention, `TargetRole` usually `Key Vault Administrator`. One group per resource group, or one platform group across many. |
| Service principal or managed identity | `Direct` | Keep the role least-privileged (`SuggestedRole` is a good start). Stays at vault scope unless `TargetScope` says otherwise. |
| Existing security group in the access policy | `Direct` | The group gets its own role assignment; no need to nest it. |
| Orphaned, foreign tenant, unused for 90 days and confirmed not needed | `Drop` | The identity is not carried over. The vault still flips. |
| Vault already on RBAC, or handled by another team or plan | `Skip` | Out of scope for every action. A vault whose rows are all `Skip` is never verified or flipped. |

Then assign a `Wave` to every non-Skip row. Group by blast radius: a low-risk resource group first, production platforms last. Vaults in the same resource group should share a wave when you use resource group scope, otherwise the RG assignment goes live for the later vaults as soon as they flip anyway (the script warns about this).

Keep the plan CSV out of the public repo. It holds object IDs, UPNs and vault names.

## Step 3: Plan, then create the groups

```powershell
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Plan -GroupScope ResourceGroup -Wave 1
```

`Plan` changes nothing. It prints the groups (with whether they exist), the distinct role assignments with their scope, direct assignments, drops, skipped vaults and any row still needing a `TargetRole`. It also lists, per resource group scope, vaults outside this wave that the RG assignment will also cover, split into "already on RBAC, group gets the role immediately" and "inert until flipped". Read that section carefully.

```powershell
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Groups -Wave 1 -WhatIf
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Groups -Wave 1
```

Creates missing Entra security groups (mail nickname derived from the name, description from `TargetGroupDescription` or `-DefaultGroupDescription`) and adds the planned members. Re-runs add only missing members and re-sync descriptions. Record the created groups and their descriptions in the change record.

## Step 4: Assign roles

```powershell
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Assign -GroupScope ResourceGroup -Wave 1
```

Creates missing role assignments at the planned scope. On an access policy vault these are inert: Key Vault ignores RBAC until the permission model flips, so this step carries no user impact. New groups sometimes take a minute to replicate; the script retries `PrincipalNotFound` three times, 30 seconds apart. Only assignments at the target scope or above count as present; an existing vault-scope assignment does not satisfy a resource group scope plan.

## Step 5: Verify (the gate)

```powershell
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Verify -Wave 1
```

Re-reads the live access policies and role assignments per vault, expands transitive group membership through Graph `checkMemberGroups`, and compares the data actions each access policy identity has today with what RBAC will give it after the flip.

| Status | Meaning | Flip? |
|---|---|---|
| `OK` | Every mapped data action is covered by a role reaching the vault. | Yes |
| `DROPPED` | Not covered, and the plan says `Drop`. | Yes, intentional |
| `SKIPPED` | Not covered, and the plan says `Skip` for this identity on an in-scope vault. | Your call |
| `NO-ROLE` | No role with Key Vault data actions reaches this identity at all. | No |
| `GAP` | Some data actions covered, some missing. `MissingDataActions` lists them. | No |

Exit code is 1 on any `GAP` or `NO-ROLE`. Fix the plan, re-run Assign, wait for propagation, and Verify again until it is clean. The report is written to `KvMigration\KvVerify-<tenant>-<stamp>.csv`; attach it to the change record.

## Step 6: Flip

```powershell
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Flip -Wave 1 -WhatIf
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Flip -Wave 1
```

Sets `EnableRbacAuthorization = true` on every in-scope vault. The access policies stay on the vault, ignored, which is what makes [rollback](rollback.md) instant. A change log goes to `KvMigration\KvPermissionModel-Flip-<tenant>-<stamp>.csv`.

Open the workbook with a 30 minute auto-refreshing range and watch Failures & Anomalies > Forbidden for `ForbiddenByRbac`. Any row is a gap the Verify step could not see (typically an identity that was never in an access policy but relied on a broken one, or a cross-tenant caller). Add the assignment with `-Action Assign` or roll the vault back.

Soak for 24 to 48 hours, then start the next wave from Step 3.

## Afterwards

- Leave the access policies in place until every wave has soaked; `Rollback` depends on them.
- Once stable, remove the access policies out of band and enforce `enableRbacAuthorization = true` with Azure Policy (built-in: "Azure Key Vault should use RBAC permission model").
- Keep the RG admin groups under review: Access Reviews on the `RBAC_RG_*_KVAdmin` and `RBAC_KV_*_Admin` groups replace the per-vault access policy audit you used to do.
