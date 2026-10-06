# Security

## What this repository contains

Scripts, a workbook definition, pipeline definitions and documentation. No tenant, subscription, workspace, group or vault identifiers from any real environment; every GUID is either a placeholder (`00000000-...`, `11111111-...`) or a public Microsoft first-party application ID used to label client apps in the workbook.

## What must never be committed

- Plan CSVs (`KvPlan-*.csv`) and any export or verify output. They hold object IDs, UPNs, application IDs and vault names. `.gitignore` excludes them; keep them in your ITSM change record or a private repository.
- Pipeline artifacts downloaded for evidence.
- Credentials of any kind. The pipelines use workload identity federation and have no secret inputs beyond IDs.

## Blast radius of the tooling

- `Export`, `Plan`, `Verify`: read only.
- `Groups`: creates Entra security groups and adds members. An identity holding `Group.ReadWrite.All` can add members to any group in the tenant; keep it dedicated and time-boxed.
- `Assign`: creates role assignments. Inert on access policy vaults until the flip, live immediately on any vault in the same resource group that is already on RBAC (the script warns about these).
- `Flip` / `Rollback`: one property write per vault. Reversible.

## Reporting a problem

Open a GitHub issue for behaviour that could cause an unintended access grant or loss, or a documentation error that could lead someone there. Do not include identifiers from your own environment in the issue; a redacted log excerpt is enough.
