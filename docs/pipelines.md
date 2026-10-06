# Running the migration from a pipeline

Two ready-made definitions, one per platform. Both take the same inputs (action, wave, vault filter, group scope, WhatIf, plan location), publish the CSV outputs as build artifacts, and put the state-changing actions (Groups, Flip, Rollback) behind an approval gate. Nothing about the tenant is hard-coded; it all comes from variables and secrets.

| Platform | File | Approval gate |
|---|---|---|
| Azure DevOps | [`pipelines/azure-pipelines.yml`](../pipelines/azure-pipelines.yml) + [`pipelines/templates/migration-steps.yml`](../pipelines/templates/migration-steps.yml) | Environment `kv-rbac-migration-gated` with an Approvals check |
| GitHub Actions | [`.github/workflows/kv-rbac-migration.yml`](../.github/workflows/kv-rbac-migration.yml) | Environment `kv-rbac-gated` with required reviewers |

## Identity

Create one app registration (or user-assigned managed identity for Azure DevOps) dedicated to this migration and set up workload identity federation to your Azure DevOps service connection or GitHub repository. No client secrets. Grant the rights in [permissions.md](permissions.md); the Graph permissions (`Directory.Read.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`) need admin consent.

`Invoke-AzRestMethod` obtains Graph tokens from the same Az session, so a single `AzurePowerShell@5` task or `azure/login` step covers both ARM and Graph calls.

## Azure DevOps set-up

1. Library > Variable groups > `kv-rbac-migration`:
   - `serviceConnection`: name of the ARM service connection.
   - `logAnalyticsWorkspaceId`: workspace (customer) ID, or empty to skip usage enrichment on Export.
2. Pipelines > Environments > `kv-rbac-migration-gated` > Approvals and checks > Approvals: add the change approvers.
3. Library > Secure files: upload `KvPlan.csv` (the plan CSV for the tenant). Grant the pipeline access when prompted on first use. Alternatively set `planSource = Repo` and keep the plan in a private repository at `planRepoPath`.
4. Create the pipeline from `pipelines/azure-pipelines.yml`. Every run is manual (`trigger: none`) and asks for the parameters.

Run order per wave: `Plan` (WhatIf irrelevant) > `Groups` with WhatIf on, then off > `Assign` with WhatIf off > wait 15 minutes > `Verify` > `Flip` with WhatIf on, then off. `Verify` fails the run on any `GAP` or `NO-ROLE`, which is the gate you want.

## GitHub Actions set-up

1. Settings > Secrets and variables > Actions: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, optional `LOG_ANALYTICS_WORKSPACE_ID`.
2. Settings > Environments: `kv-rbac` (no rules) and `kv-rbac-gated` (required reviewers). The federated credential on the app registration must include the environment subject for both, e.g. `repo:<org>/<repo>:environment:kv-rbac-gated`.
3. Plan CSV: keep it out of a public repository. Use a private fork of this repo with the plan at `plans/KvPlan.csv`, or add a step before the run that downloads it from a storage account the workflow identity can read (`azcopy` or `Get-AzStorageBlobContent`).
4. Actions > Key Vault RBAC migration > Run workflow, pick the action and filters.

The `concurrency` group serialises runs so two operators cannot flip and roll back at the same time.

## Outputs

Each run publishes an artifact (`kv-rbac-<Action>-<run>`) holding `KvInventory/` or `KvMigration/`. Download the Verify report and the Flip change log and attach them to the change record. Artifacts contain object IDs and UPNs; set the retention to match your evidence policy (the GitHub workflow uses 90 days).

## Scheduling Export

Export is safe to run on a schedule (weekly is plenty) to catch new vaults and drifted access policies. Add a `schedules:` block to the Azure DevOps pipeline or an `on: schedule:` trigger to a copy of the GitHub workflow with the action fixed to `Export`; both are deliberately absent from the shipped definitions so a scheduled run can never perform a state change.
