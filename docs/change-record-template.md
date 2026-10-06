# Change record template

Copy into your ITSM tool (ServiceNow, Jira Service Management, whatever runs CAB) once per tenant or per wave. Placeholders are in angle brackets.

---

**Title:** Key Vault permission model: migrate `<n>` vaults in `<tenant name>` from access policies to Azure RBAC (wave `<w>`)

**Change type:** Standard / Normal (pre-approved after wave 1 if the runbook is followed unchanged)

**Risk:** Low. Role assignments are created ahead of time and are inert until the flip. The flip is a single property change per vault, verified beforehand, reversible in seconds, and the access policies stay on the vault untouched.

**Implementation window:** `<date>` `<start>` to `<end>` `<time zone>`. Soak period `<24 to 48 h>` before the next wave.

## Scope

| Item | Value |
|---|---|
| Tenant | `<tenant name>` (`<tenant ID>`) |
| Subscriptions | `<list>` |
| Vaults in this wave | `<n>` (list attached: `KvPlan-<tenant>.csv` filtered to Wave `<w>`) |
| Identities carried over | `<n>` via groups, `<n>` direct |
| Identities dropped | `<n>` (orphaned `<n>`, foreign tenant `<n>`, unused and confirmed `<n>`) |
| Vaults skipped | `<n>` already on RBAC |

## Entra groups created

| Group | Role | Scope | Members | Description |
|---|---|---|---|---|
| `RBAC_RG_<rg>_KVAdmin` | Key Vault Administrator | `/subscriptions/<sub>/resourceGroups/<rg>` | `<n>` | `<description text>` |
| `RBAC_KV_<Platform>_Admin` | Key Vault Administrator | `<n>` resource groups matching `<rule>` | `<n>` | `<description text>` |

## Pre-implementation checks (attach evidence)

- [ ] `Export-KvAccessPolicyInventory.ps1` run within the last `<7>` days; plan CSV reviewed by vault owners.
- [ ] `Invoke-KvRbacMigration.ps1 -Action Plan` output reviewed, including the "RG scope also covers" warnings.
- [ ] `-Action Groups` and `-Action Assign` completed; role assignment propagation wait observed.
- [ ] `-Action Verify` exit code 0. Report `KvVerify-<tenant>-<stamp>.csv` attached: `<n>` OK, `<n>` DROPPED, 0 GAP, 0 NO-ROLE.
- [ ] Workbook Overview tab shows `AuditEvent` ingestion for every vault in the wave in the last 24 hours.
- [ ] Vault owners notified of the window and the rollback path.

## Implementation steps

1. `Connect-AzAccount -Tenant <tenant ID>` as `<account>`; PIM activate `<Owner on RGs / Groups Administrator>`.
2. `Invoke-KvRbacMigration.ps1 -PlanCsv <path> -Action Verify -Wave <w>` (final gate; stop if exit code 1).
3. `Invoke-KvRbacMigration.ps1 -PlanCsv <path> -Action Flip -Wave <w> -WhatIf`, confirm the vault list.
4. `Invoke-KvRbacMigration.ps1 -PlanCsv <path> -Action Flip -Wave <w>`.
5. Attach `KvPermissionModel-Flip-<tenant>-<stamp>.csv`.

## Verification

- Workbook RBAC Migration tab: every flipped vault shows `AuthPath = RBAC` for new calls within 15 minutes.
- Workbook Failures & Anomalies tab, filter `ForbiddenByRbac`: zero rows for the flipped vaults over the soak period.
- Application owners confirm `<named smoke tests>`.

## Rollback

`Invoke-KvRbacMigration.ps1 -PlanCsv <path> -Action Rollback -Wave <w>` (or `-VaultName <vault>` for one vault). Restores `EnableRbacAuthorization = false`; access policies were never removed, so access is restored immediately. Role assignments are left in place, inert. Details in [rollback.md](rollback.md).

## Communications

- Before: vault owners in this wave, `<date>`.
- After: summary with Verify and flip logs to `<security lead / CISO>`.

---
