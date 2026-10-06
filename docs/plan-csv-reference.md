# Plan CSV reference

The plan CSV is the export from `Export-KvAccessPolicyInventory.ps1` with the consolidation columns filled in. `Invoke-KvRbacMigration.ps1` reads it for every action. A worked example with every pattern is in [`data/KvPlan-sample.csv`](../data/KvPlan-sample.csv).

One row = one identity on one vault. Vaults with no access policies get a single row with empty identity columns and `Notes = No access policies`.

## Columns written by the export (do not edit)

| Column | Meaning |
|---|---|
| `TenantId` | Tenant the vault lives in. The migration script only processes rows matching its Az context tenant. |
| `SubscriptionId`, `SubscriptionName` | Subscription of the vault. |
| `ResourceGroup`, `VaultName`, `VaultId`, `Location` | Vault identity. `VaultId` is the resource ID used for all scope logic. |
| `RbacEnabled` | Current permission model. `True` means the vault is already on RBAC; mark those rows `Skip`. |
| `EnabledForDeployment`, `EnabledForTemplateDeployment`, `EnabledForDiskEncryption` | Vault flags, for context. Template deployment access is unaffected by the permission model. |
| `PublicNetworkAccess`, `DiagnosticSettings`, `Tags` | Context for wave planning. `DiagnosticSettings = 0` means no usage data and no workbook visibility for that vault. |
| `ApTenantId` | Tenant ID recorded on the access policy entry. Differs from `TenantId` for cross-tenant identities (`PrincipalType = ForeignTenant`). |
| `ObjectId`, `ApplicationId`, `CompoundIdentity` | Access policy identity. `CompoundIdentity = True` (object ID plus application ID) has no RBAC equivalent; decide on the object ID alone. |
| `PrincipalType` | `User`, `Group`, `ServicePrincipal`, `ManagedIdentity`, `Orphaned` (not found in the directory), `ForeignTenant`. |
| `DisplayName`, `AppId`, `UserPrincipalName` | Resolved from Graph. |
| `KeyPermissions`, `SecretPermissions`, `CertificatePermissions`, `StoragePermissions` | Effective permissions, semicolon separated, lower case, with legacy `all` expanded. |
| `HadLegacyAll` | `True` when any category used the legacy `all` keyword. |
| `SuggestedRole` | Least-privileged built-in role (or per-category combination) covering the mapped data actions, computed against the live role definitions. `REVIEW: ...` or `NONE` needs a decision. |
| `UsageOps`, `UsageFailed`, `UsageLastSeen`, `UsageOperations` | 90-day usage from `AuditEvent` logs, matched on object ID then app ID. Blank when no workspace ID was given or the identity made no calls. |

## Columns you fill in

| Column | Required | Values | Notes |
|---|---|---|---|
| `TargetGroupName` | For `Action = Group` | Entra security group display name | Created if missing. Must be unique in the tenant; the script stops on an ambiguous name. See [group-naming-convention.md](group-naming-convention.md). |
| `TargetGroupDescription` | Optional | Free text | Written to the group description on creation and re-synced on later `Groups` runs. Use it to record the scope rule of platform groups, e.g. `Scope: RG name contains "shared-platform"`. Rows without it get `-DefaultGroupDescription`. |
| `TargetRole` | For `Group` and `Direct` | One or more built-in or custom role names, `;` separated | Start from `SuggestedRole`. `Key Vault Administrator` for admin groups; least-privilege data roles for workloads. Rows still holding `REVIEW` or `NONE` are skipped with a warning. |
| `TargetScope` | Optional | Resource group or subscription resource ID | Overrides the scope for that row only, for `Group` and `Direct` alike. Blank follows `-GroupScope` (Group rows) or the vault (Direct rows). |
| `Action` | Yes | `Group`, `Direct`, `Drop`, `Skip` | Blank is treated as `Group`. Anything else stops the run. |
| `Wave` | Yes for non-Skip rows | Any string, typically `1`, `2`, `3` | `-Wave` filters on exact match. |
| `Notes` | Optional | Free text | Your audit trail. Carried through unchanged. |

## What each Action does

| Action | Groups | Assign | Verify | Flip / Rollback |
|---|---|---|---|---|
| `Group` | `ObjectId` added to `TargetGroupName` | `TargetRole` to the group at `-GroupScope` or `TargetScope` | Identity must be covered, via group membership or otherwise | Vault in scope |
| `Direct` | Nothing | `TargetRole` to `ObjectId` on the vault or `TargetScope` | Identity must be covered | Vault in scope |
| `Drop` | Nothing | Nothing | Reported as `DROPPED`, not a failure | Vault in scope |
| `Skip` | Nothing | Nothing | `SKIPPED` if the vault is in scope through other rows; otherwise not evaluated | Vault out of scope if all its rows are `Skip` |

`Orphaned` and `ForeignTenant` identities are never added to groups or given direct assignments, whatever the `Action` column says.

## Scope rules

- `-GroupScope Vault` (default): group roles are assigned on each vault. Most granular, most assignments.
- `-GroupScope ResourceGroup`: group roles are assigned once on the vault's resource group. Covers every vault in the group, current and future, which is what a "vault administrators for this RG" group should mean. The script warns when an RG scope also covers vaults outside the current run and says whether those are live now (already RBAC) or inert (access policy mode).
- `TargetScope`: per-row override. Use a resource group ID to lift a `Direct` assignment (a backup agent that needs every vault in the RG) or to pin a group to a specific RG. A subscription ID works but is warned about: it covers every vault in the subscription.
- Assignments already present at or above the target scope count as done. A vault-level assignment does not satisfy an RG-level plan row and the RG assignment will be created.

## Housekeeping

- Keep one plan CSV per tenant. The script ignores other tenants' rows, so a combined file also works, but per-tenant files make change records simpler.
- Do not commit plan CSVs to a public repository. `.gitignore` excludes `KvPlan-*.csv` and the output folders for that reason.
- After a re-export, diff on `VaultId` + `ObjectId` to carry your decisions across; the trailing columns are yours, the rest is regenerated.
