# Rights required

Everything runs under a single Az context (`Connect-AzAccount`) and calls Microsoft Graph with the same token through `Invoke-AzRestMethod`, so the identity needs both Azure RBAC rights and Entra directory rights. Least privilege per step:

| Step | Azure RBAC | Entra / Graph |
|---|---|---|
| Export | `Reader` on every subscription in scope. `Log Analytics Reader` on the workspace for usage enrichment. | Directory read: `Directory Readers` role (interactive) or `Directory.Read.All` application permission (service principal). Used for `directoryObjects/getByIds`. |
| Plan | Same as Export (reads vaults and group existence). | Directory read. |
| Groups | None. | `Groups Administrator` role (interactive) or `Group.ReadWrite.All` plus `GroupMember.ReadWrite.All` application permissions (service principal). Creates groups, patches descriptions, adds members. |
| Assign | `Key Vault Data Access Administrator`, `User Access Administrator` or `Owner` at every target scope (vault or resource group). | Directory read to resolve group names. |
| Verify | `Reader` on the vaults. | Directory read. Uses `directoryObjects/{id}/checkMemberGroups`. |
| Flip / Rollback | `Microsoft.KeyVault/vaults/write` plus **unrestricted** `Microsoft.Authorization/roleAssignments/write`: `Owner`, or `User Access Administrator` together with `Key Vault Contributor`. | None. |

## Why Key Vault Data Access Administrator cannot flip

`Key Vault Data Access Administrator` is the right role for the Assign step: it can create role assignments, constrained by an ABAC condition to the Key Vault data plane roles only. Changing the permission model, however, is a vault property write (`Microsoft.KeyVault/vaults/write`), and the Key Vault resource provider additionally checks for an unconstrained `roleAssignments/write` before it lets you turn RBAC on. Neither is included in that role, so the Flip step needs Owner-level rights on the vault or its resource group.

## Service principal set-up for pipelines

Use workload identity federation (OIDC) rather than a client secret. Grant:

1. Azure RBAC: `Reader` at the management group or subscriptions for Export and Verify; `Key Vault Data Access Administrator` at the same scope for Assign; `Owner` on the in-scope vaults' resource groups for Flip, ideally activated through PIM for Groups or a time-boxed assignment for the change window.
2. Graph application permissions with admin consent: `Directory.Read.All`, `Group.ReadWrite.All`, `GroupMember.ReadWrite.All`. Drop the two write permissions once the groups exist if the pipeline will only ever run Assign, Verify and Flip afterwards.
3. Optional: `Log Analytics Reader` on the workspace for the Export usage columns.

A pipeline identity that owns `Group.ReadWrite.All` can add anyone to any group. Keep that identity separate from general-purpose deployment identities, and gate the Groups and Flip actions behind an environment approval (see [pipelines.md](pipelines.md)).

## Interactive runs

For a one-off migration run by a person, the practical combination is: `Reader` on the subscriptions, `Groups Administrator` (PIM-activated), `Key Vault Data Access Administrator` at the subscription, and `Owner` on the resource groups being flipped, PIM-activated for the change window only.
