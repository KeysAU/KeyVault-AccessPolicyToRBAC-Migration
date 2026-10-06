# Group naming convention

A suggested standard for the Entra security groups the migration creates. Adapt the prefixes to your own naming policy; the scripts do not depend on the pattern, only on `TargetGroupName` being unique in the tenant.

## Two group shapes

| Shape | Pattern | When | Example |
|---|---|---|---|
| Exact match | `RBAC_RG_<ResourceGroupName>_KVAdmin` | One team owns one resource group. Group gets `Key Vault Administrator` at that RG's scope. | `RBAC_RG_rg-payments-prod_KVAdmin` |
| Platform (wildcard) | `RBAC_KV_<Platform>_Admin` | One team owns many resource groups that share a naming fragment. Group gets `Key Vault Administrator` on each of those RGs. The rule lives in the group description. | `RBAC_KV_SharedPlatform_Admin` with description `Scope: RG name contains "shared-platform"` |

Rules that make the names machine-readable:

1. Underscore is the delimiter. The target fragment (`<ResourceGroupName>`, `<Platform>`) may contain dashes but never underscores, so a name always splits into exactly four parts.
2. `RBAC_` prefix marks the group as an Azure RBAC assignment group, as opposed to application or mail groups.
3. The role suffix (`KVAdmin`, `Admin`) says what the group grants. Add other suffixes only when a group carries a different role, e.g. `RBAC_RG_rg-data-prod_KVSecretsUser`.
4. The mail nickname is derived by stripping every non-alphanumeric character and truncating to 64 characters; the script does this for you.

## Descriptions

`TargetGroupDescription` in the plan CSV becomes the group description and is kept in sync on every `Groups` run. Put three things in it:

- What the group grants and where: `Key Vault Administrator at resource group scope.`
- The scope rule for platform groups: `Scope: RG name contains "shared-platform".`
- The owning team: `Owner: Platform Engineering.`

Anyone reading the group in the Entra portal then knows what membership means without opening Azure.

## Membership

- Humans only. Service principals and managed identities get `Direct` assignments; putting them in an admin group hides what they can do.
- Existing security groups from access policies keep their own `Direct` assignment rather than being nested. Nesting works for RBAC, but Access Reviews and the Verify output are clearer without it.
- Put the groups under Access Reviews. They replace the per-vault access policy audits, so they need the same cadence.

## Scope choice

`Key Vault Administrator` at resource group scope through these groups is the recommended end state for human administrators: one assignment per RG instead of one per vault, new vaults in the RG inherit it, and the workbook's "granted by" grid shows the group name on every call. Use vault scope (`-GroupScope Vault`) only where a resource group mixes ownership.
