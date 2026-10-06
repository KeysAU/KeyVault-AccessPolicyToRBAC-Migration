# Rollback

## What Rollback does

```powershell
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Rollback -Wave 1
.\scripts\Invoke-KvRbacMigration.ps1 -PlanCsv .\KvPlan-<tenant>.csv -Action Rollback -VaultName kv-payments-prod-01
```

Sets `EnableRbacAuthorization = false` on every in-scope vault (or the named ones). The flip never touched the access policies, so the vault returns to exactly its previous authorisation state the moment the property write completes. There is no propagation delay on the Key Vault side; callers succeed on their next request.

A change log is written to `KvMigration\KvPermissionModel-Rollback-<tenant>-<stamp>.csv` with the before and after state per vault. `-WhatIf` lists the vaults without changing them.

## What Rollback leaves behind

- Role assignments created by `Assign` stay in place. On an access policy vault they are inert, and they are exactly what you need for the next attempt. Remove them by hand only if the migration is abandoned.
- Entra groups and their members stay in place.
- Diagnostic logs show the flip and the rollback as `VaultPatch` operations with `enableRbacAuthorization` in the payload; the workbook's RBAC Migration tab lists them under "Permission model changes seen in the window".

## When to roll back versus fix forward

| Symptom | Response |
|---|---|
| One identity `ForbiddenByRbac` on one vault, low impact | Fix forward: add the row to the plan, `-Action Assign`, wait a few minutes. Access policy identities that Verify said were covered rarely fail; the usual case is a caller that was never in an access policy at all. |
| Multiple identities or a business-critical application failing | Roll back the vault immediately, then investigate with the workbook's Forbidden grid and the Verify report. |
| Cross-tenant caller (`ForeignTenant`) failing | Roll back. RBAC cannot grant a foreign identity; the application needs a multi-tenant or managed identity design change first. |
| Compound identity (object ID plus application ID) failing | Roll back if critical. Decide whether the object ID alone may hold the role, then re-verify. |

## When Rollback is not enough

Rollback relies on the access policies still being present. If they were removed after the flip (out-of-band clean-up, or a template redeploy that omitted them), Rollback restores the permission model but not the policies. Recreate them from the export:

```powershell
$rows = Import-Csv .\KvInventory\KvAccessPolicies-<tenant>-<stamp>.csv | Where-Object { $_.VaultName -eq "<vault>" -and $_.ObjectId }
foreach ($r in $rows) {
  $p = @{ VaultName = $r.VaultName; ResourceGroupName = $r.ResourceGroup; ObjectId = $r.ObjectId }
  if ($r.KeyPermissions)         { $p.PermissionsToKeys         = $r.KeyPermissions.Split(";") }
  if ($r.SecretPermissions)      { $p.PermissionsToSecrets      = $r.SecretPermissions.Split(";") }
  if ($r.CertificatePermissions) { $p.PermissionsToCertificates = $r.CertificatePermissions.Split(";") }
  if ($r.StoragePermissions)     { $p.PermissionsToStorage      = $r.StoragePermissions.Split(";") }
  Set-AzKeyVaultAccessPolicy @p
}
```

This is one more reason to keep the export CSVs for the life of the project, and to leave access policies in place until every wave has soaked.
