<#
.SYNOPSIS
  Executes the Key Vault access policy to Azure RBAC migration from the consolidated plan CSV (steps 3 to 6 of the process).

.DESCRIPTION
  Plan CSV = output of Export-KvAccessPolicyInventory.ps1 with TargetGroupName / TargetRole / Action / Wave filled in.
    Action = Group   : ObjectId is added to TargetGroupName; TargetRole is assigned to the group at -GroupScope (vault or resource group)
    Action = Direct  : TargetRole is assigned to ObjectId itself on the vault (recommended for managed identities and service principals)
    Action = Drop    : identity is intentionally not carried over (orphaned, unused, no longer required); the vault still flips
    Action = Skip    : row is out of scope for every action. Use for vaults already on RBAC or handled outside this plan.
                       A vault whose rows are all Skip is never verified or flipped; a skipped identity on an in-scope vault shows as SKIPPED in Verify.
  TargetRole may hold several roles separated by ";" (e.g. "Key Vault Secrets User;Key Vault Certificate User").
  -GroupScope Vault (default) assigns group roles on each vault. -GroupScope ResourceGroup assigns them once on the vault's
  resource group, which covers every vault in that RG, current and future. Direct rows always stay at vault scope.
  Optional TargetGroupDescription column: text written to the Entra group description on creation and kept in sync on
  later Groups runs. Use it to record the scope rule for platform groups (e.g. Scope: RG name contains "shared-platform").
  Rows without it get -DefaultGroupDescription.
  Optional TargetScope column: a resource group or subscription resource ID that overrides both for that row
  (e.g. /subscriptions/<id>/resourceGroups/<rg>). Blank = follow -GroupScope. Verify evaluates per vault and sees inherited assignments.

  -Action:
    Plan      - prints groups, memberships, role assignments and vaults that would be touched. No changes.
    Groups    - creates missing Entra security groups and adds members. Idempotent.
    Assign    - creates missing role assignments at the planned scope. Idempotent. Assignments are inert until Flip.
                Warns where a resource group scope also covers vaults that are not in the plan.
    Verify    - re-reads live access policies and role assignments, expands transitive group membership via Graph
                checkMemberGroups, and reports OK / GAP / NO-ROLE / DROPPED / SKIPPED per identity. Exit code 1 on GAP or NO-ROLE.
    Flip      - sets EnableRbacAuthorization = true on the vaults in scope.
    Rollback  - sets EnableRbacAuthorization = false. The vault retains its access policies, so this restores the previous state.
  -Wave and -VaultName limit every action to matching rows. -WhatIf is honoured by Groups, Assign, Flip and Rollback.

.PARAMETER PlanCsv
  Path to the consolidated plan CSV (see docs/plan-csv-reference.md).
.PARAMETER Action
  Plan, Groups, Assign, Verify, Flip or Rollback. See DESCRIPTION.
.PARAMETER Wave
  One or more Wave values to include. Default is every wave.
.PARAMETER VaultName
  One or more vault names to include. Default is every vault in the selected waves.
.PARAMETER GroupScope
  Vault (default) or ResourceGroup. Scope for Action=Group role assignments; Direct rows always use the vault.
.PARAMETER OutputFolder
  Folder for the Verify report and Flip / Rollback change logs. Created if missing.
.PARAMETER DefaultGroupDescription
  Description set on newly created Entra groups when the plan row has no TargetGroupDescription.

.NOTES
  Run per tenant with an Az context in that tenant. Rows for other tenants are skipped.
  Rights: Groups   = Groups Administrator (or Group.ReadWrite.All)
          Assign   = Key Vault Data Access Administrator, User Access Administrator or Owner at vault or RG scope
          Verify   = Reader on the vaults, directory read for Graph
          Flip     = Microsoft.KeyVault/vaults/write plus unrestricted Microsoft.Authorization/roleAssignments/write
                     (Owner, or User Access Administrator + Key Vault Contributor). Key Vault Data Access Administrator cannot flip.
  Modules: Az.Accounts, Az.Resources, Az.KeyVault (Az 16.3.0 or later recommended). Windows PowerShell 5.1 compatible.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][string]$PlanCsv,
  [Parameter(Mandatory = $true)][ValidateSet("Plan","Groups","Assign","Verify","Flip","Rollback")][string]$Action,
  [string[]]$Wave,
  [string[]]$VaultName,
  [ValidateSet("Vault","ResourceGroup")][string]$GroupScope = "Vault",
  [string]$OutputFolder = ".\KvMigration",
  [string]$DefaultGroupDescription = "Key Vault RBAC access group. Created by the Key Vault access policy to RBAC migration toolkit."
)

#region TESTING
# $PlanCsv = "C:\Temp\KvInventory\KvAccessPolicies-consolidated.csv"
# $Action = "Plan"
# $Wave = @("1")
# $GroupScope = "ResourceGroup"
#endregion TESTING

$ErrorActionPreference = "Stop"
$script:exitCode = 0

if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
  function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Host ("{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message)
  }
}

$context = Get-AzContext
if (-not $context) { throw "No Az context. Run Connect-AzAccount -Tenant <tenantId> first." }
$tenantId = $context.Tenant.Id
$stamp = Get-Date -Format "yyyyMMdd-HHmm"
New-Item -Path $OutputFolder -ItemType Directory -Force -WhatIf:$false | Out-Null
Write-Log "Tenant $tenantId, account $($context.Account.Id), action $Action, group scope $GroupScope"

#region Access policy to RBAC data action mapping (Azure/KeyVault-AccessPolicyToRBAC-CompareTool)
$mappingCsv = @"
Access Policy Permission,RBAC Data Action
Key Get,Microsoft.KeyVault/vaults/keys/read
Key List,Microsoft.KeyVault/vaults/keys/read
Key Update,Microsoft.KeyVault/vaults/keys/update/action
Key Create,Microsoft.KeyVault/vaults/keys/create/action
Key Import,Microsoft.KeyVault/vaults/keys/import/action
Key Delete,Microsoft.KeyVault/vaults/keys/delete
Key Recover,Microsoft.KeyVault/vaults/keys/recover/action
Key Backup,Microsoft.KeyVault/vaults/keys/backup/action
Key Restore,Microsoft.KeyVault/vaults/keys/restore/action
Key Decrypt,Microsoft.KeyVault/vaults/keys/decrypt/action
Key Encrypt,Microsoft.KeyVault/vaults/keys/encrypt/action
Key UnwrapKey,Microsoft.KeyVault/vaults/keys/unwrap/action
Key WrapKey,Microsoft.KeyVault/vaults/keys/wrap/action
Key Verify,Microsoft.KeyVault/vaults/keys/verify/action
Key Sign,Microsoft.KeyVault/vaults/keys/sign/action
Key Purge,Microsoft.KeyVault/vaults/keys/purge/action
Key Release,Microsoft.KeyVault/vaults/keys/release/action
Key Rotate,Microsoft.KeyVault/vaults/keys/rotate/action
Key GetRotationPolicy,Microsoft.KeyVault/vaults/keyrotationpolicies/read
Key SetRotationPolicy,Microsoft.KeyVault/vaults/keyrotationpolicies/write
Certificate Get,Microsoft.KeyVault/vaults/certificates/read
Certificate List,Microsoft.KeyVault/vaults/certificates/read
Certificate Update,Microsoft.KeyVault/vaults/certificates/update/action
Certificate Create,Microsoft.KeyVault/vaults/certificates/create/action
Certificate Import,Microsoft.KeyVault/vaults/certificates/import/action
Certificate Delete,Microsoft.KeyVault/vaults/certificates/delete
Certificate Recover,Microsoft.KeyVault/vaults/certificates/recover/action
Certificate Backup,Microsoft.KeyVault/vaults/certificates/backup/action
Certificate Restore,Microsoft.KeyVault/vaults/certificates/restore/action
Certificate ManageContacts,Microsoft.KeyVault/vaults/certificatecontacts/write
Certificate ManageIssuers,Microsoft.KeyVault/vaults/certificatecas/write
Certificate GetIssuers,Microsoft.KeyVault/vaults/certificatecas/read
Certificate ListIssuers,Microsoft.KeyVault/vaults/certificatecas/read
Certificate SetIssuers,Microsoft.KeyVault/vaults/certificatecas/write
Certificate DeleteIssuers,Microsoft.KeyVault/vaults/certificatecas/delete
Certificate Purge,Microsoft.KeyVault/vaults/certificates/purge/action
Secret Get,Microsoft.KeyVault/vaults/secrets/getSecret/action
Secret List,Microsoft.KeyVault/vaults/secrets/readMetadata/action
Secret Set,Microsoft.KeyVault/vaults/secrets/setSecret/action;Microsoft.KeyVault/vaults/secrets/update/action
Secret Delete,Microsoft.KeyVault/vaults/secrets/delete
Secret Recover,Microsoft.KeyVault/vaults/secrets/recover/action
Secret Backup,Microsoft.KeyVault/vaults/secrets/backup/action
Secret Restore,Microsoft.KeyVault/vaults/secrets/restore/action
Secret Purge,Microsoft.KeyVault/vaults/secrets/purge/action
Storage Get,Microsoft.KeyVault/vaults/storageaccounts/read
Storage List,Microsoft.KeyVault/vaults/storageaccounts/read
Storage Delete,Microsoft.KeyVault/vaults/storageaccounts/delete
Storage Set,Microsoft.KeyVault/vaults/storageaccounts/set/action
Storage Update,Microsoft.KeyVault/vaults/storageaccounts/set/action
Storage RegenerateKey,Microsoft.KeyVault/vaults/storageaccounts/regeneratekey/action
Storage GetSas,Microsoft.KeyVault/vaults/storageaccounts/sas/read
Storage ListSas,Microsoft.KeyVault/vaults/storageaccounts/sas/read
Storage DeleteSas,Microsoft.KeyVault/vaults/storageaccounts/sas/delete
Storage SetSas,Microsoft.KeyVault/vaults/storageaccounts/sas/set/action
Storage Recover,Microsoft.KeyVault/vaults/storageaccounts/recover/action
Storage Backup,Microsoft.KeyVault/vaults/storageaccounts/backup/action
Storage Restore,Microsoft.KeyVault/vaults/storageaccounts/restore/action
Storage Purge,Microsoft.KeyVault/vaults/storageaccounts/purge/action
"@

$apToDataActions = @{}
$allKvDataActions = @{}
foreach ($m in ($mappingCsv | ConvertFrom-Csv)) {
  $actions = @($m.'RBAC Data Action'.ToLower().Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  $apToDataActions[$m.'Access Policy Permission'.ToLower()] = $actions
  foreach ($a in $actions) { $allKvDataActions[$a] = $true }
}

$allPermissions = @{
  key         = @("get","list","update","create","import","delete","recover","backup","restore","decrypt","encrypt","unwrapkey","wrapkey","verify","sign","purge","release","rotate","getrotationpolicy","setrotationpolicy")
  secret      = @("get","list","set","delete","recover","backup","restore","purge")
  certificate = @("get","list","update","create","import","delete","recover","backup","restore","managecontacts","manageissuers","getissuers","listissuers","setissuers","deleteissuers","purge")
  storage     = @("get","list","delete","set","update","regeneratekey","getsas","listsas","deletesas","setsas","recover","backup","restore","purge")
}

function Expand-ApPermission {
  param([string[]]$Permissions, [string]$Category)
  $out = New-Object System.Collections.Generic.List[string]
  if (-not $Permissions) { return $out.ToArray() }
  foreach ($p in $Permissions) {
    if (-not $p) { continue }
    $p = $p.ToLower().Trim()
    if ($p -eq "all") {
      foreach ($a in $allPermissions[$Category]) { if (-not $out.Contains($a)) { $out.Add($a) } }
    }
    elseif (-not $out.Contains($p)) { $out.Add($p) }
  }
  return $out.ToArray()
}

function Get-CoveredDataActions {
  param([string[]]$DataActions, [string[]]$NotDataActions)
  $covered = @{}
  foreach ($da in @($DataActions)) {
    if (-not $da) { continue }
    $da = $da.ToLower()
    if ($da -eq "*" -or $da -eq "microsoft.keyvault/*" -or $da -eq "microsoft.keyvault/vaults/*") {
      foreach ($k in $allKvDataActions.Keys) { $covered[$k] = $true }
    }
    elseif ($da.Contains("*")) {
      $pattern = "^" + [regex]::Escape($da).Replace("\*", ".*") + "$"
      foreach ($k in $allKvDataActions.Keys) { if ($k -match $pattern) { $covered[$k] = $true } }
    }
    elseif ($allKvDataActions.ContainsKey($da)) { $covered[$da] = $true }
  }
  foreach ($nda in @($NotDataActions)) {
    if (-not $nda) { continue }
    $pattern = "^" + [regex]::Escape($nda.ToLower()).Replace("\*", ".*") + "$"
    foreach ($k in @($covered.Keys)) { if ($k -match $pattern) { $covered.Remove($k) } }
  }
  return $covered
}

# Role definition via ARM REST rather than Get-AzRoleDefinition: the JSON shape (properties.permissions[].dataActions)
# is stable across Az.Resources versions, whereas the cmdlet's output object has changed between releases.
$roleCoveredCache = @{}
function Get-RoleCovered {
  param([string]$RoleDefinitionId, [string]$SubscriptionId)
  $roleGuid = $RoleDefinitionId
  if ($RoleDefinitionId -match "([0-9a-fA-F-]{36})\s*$") { $roleGuid = $Matches[1] }
  if (-not $roleCoveredCache.ContainsKey($roleGuid)) {
    $covered = @{}
    try {
      $path = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/${roleGuid}?api-version=2022-04-01"
      $resp = Invoke-AzRestMethod -Method GET -Path $path
      if ($resp.StatusCode -ne 200) { throw "HTTP $($resp.StatusCode): $($resp.Content)" }
      $def = ConvertFrom-Json $resp.Content
      $dataActions = New-Object System.Collections.Generic.List[string]
      $notDataActions = New-Object System.Collections.Generic.List[string]
      foreach ($perm in @($def.properties.permissions)) {
        foreach ($v in @($perm.dataActions)) { if ($v) { $dataActions.Add("$v") } }
        foreach ($v in @($perm.notDataActions)) { if ($v) { $notDataActions.Add("$v") } }
      }
      $covered = Get-CoveredDataActions -DataActions $dataActions.ToArray() -NotDataActions $notDataActions.ToArray()
      if ($covered.Count -gt 0 -or "$($def.properties.roleName)" -like "Key Vault*") {
        Write-Log ("  role '{0}' ({1}): {2} data action(s) declared, {3} Key Vault data action(s) covered" -f $def.properties.roleName, $roleGuid, $dataActions.Count, $covered.Count)
      }
    }
    catch { Write-Log "Role definition $roleGuid lookup failed: $($_.Exception.Message)" "WARN" }
    $roleCoveredCache[$roleGuid] = $covered
  }
  return $roleCoveredCache[$roleGuid]
}
#endregion

#region Graph helpers
function Invoke-GraphGet {
  param([string]$Uri)
  $items = New-Object System.Collections.Generic.List[object]
  $next = $Uri
  while ($next) {
    $resp = Invoke-AzRestMethod -Method GET -Uri $next
    if ($resp.StatusCode -ne 200) { throw "Graph GET failed ($($resp.StatusCode)): $next : $($resp.Content)" }
    $json = ConvertFrom-Json $resp.Content
    foreach ($v in @($json.value)) { if ($v) { $items.Add($v) } }
    $next = $json.'@odata.nextLink'
  }
  return $items
}

# Transitive membership check: which of $GroupIds is $ObjectId a member of. Max 20 group IDs per Graph call.
function Get-TransitiveGroupHits {
  param([string]$ObjectId, [string[]]$GroupIds)
  $hits = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $GroupIds.Count; $i += 20) {
    $chunk = @($GroupIds[$i..([Math]::Min($i + 19, $GroupIds.Count - 1))])
    $payload = @{ groupIds = $chunk } | ConvertTo-Json -Depth 3
    $resp = Invoke-AzRestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$ObjectId/checkMemberGroups" -Payload $payload
    if ($resp.StatusCode -eq 404) { Write-Log "checkMemberGroups: object $ObjectId not found in the directory" "WARN"; return $hits.ToArray() }
    if ($resp.StatusCode -ne 200) { throw "Graph checkMemberGroups failed ($($resp.StatusCode)) for $ObjectId : $($resp.Content)" }
    foreach ($id in @((ConvertFrom-Json $resp.Content).value)) { if ($id) { $hits.Add("$id".ToLower()) } }
  }
  return $hits.ToArray()
}

$groupCache = @{}
function Get-TargetGroup {
  param([string]$Name)
  if ($groupCache.ContainsKey($Name)) { return $groupCache[$Name] }
  $filter = [uri]::EscapeDataString("displayName eq '" + $Name.Replace("'", "''") + "'")
  $hits = @(Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=$filter&`$select=id,displayName,description,securityEnabled,mailEnabled")
  if ($hits.Count -gt 1) { throw "Group name '$Name' is ambiguous ($($hits.Count) matches). Rename or use a unique name." }
  $g = $null
  if ($hits.Count -eq 1) { $g = $hits[0] }
  $groupCache[$Name] = $g
  return $g
}
#endregion

#region Load and validate plan
$requiredColumns = @("TenantId","SubscriptionId","ResourceGroup","VaultName","VaultId","ObjectId","PrincipalType","DisplayName","TargetGroupName","TargetRole","Action","Wave")
$plan = @(Import-Csv -Path $PlanCsv)
if ($plan.Count -eq 0) { throw "Plan CSV is empty: $PlanCsv" }
$missingCols = @($requiredColumns | Where-Object { $_ -notin $plan[0].PSObject.Properties.Name })
if ($missingCols.Count -gt 0) { throw "Plan CSV is missing column(s): $($missingCols -join ', ')" }

$rows = @($plan | Where-Object { $_.TenantId -eq $tenantId -and $_.VaultId })
Write-Log "$($plan.Count) plan row(s), $($rows.Count) in this tenant"
if ($Wave)      { $rows = @($rows | Where-Object { $Wave -contains $_.Wave }) }
if ($VaultName) { $rows = @($rows | Where-Object { $VaultName -contains $_.VaultName }) }
foreach ($r in $rows) {
  $r.Action = "$($r.Action)".Trim()
  if (-not $r.Action) { $r.Action = "Group" }
  $r.TargetGroupName = "$($r.TargetGroupName)".Trim()
  $r.TargetRole = "$($r.TargetRole)".Trim()
}
$badAction = @($rows | Where-Object { $_.Action -notin @("Group","Direct","Drop","Skip") })
if ($badAction.Count -gt 0) { throw "Invalid Action value(s): $(@($badAction | Select-Object -ExpandProperty Action -Unique) -join ', '). Use Group, Direct, Drop or Skip." }

# Skip rows are out of scope for every action. A vault whose rows are all Skip is never verified or flipped.
$skipRows = @($rows | Where-Object { $_.Action -eq "Skip" })
$rows = @($rows | Where-Object { $_.Action -ne "Skip" })

$vaults = @{}
foreach ($r in $rows) {
  if (-not $vaults.ContainsKey($r.VaultId)) {
    $vaults[$r.VaultId] = [PSCustomObject]@{ VaultId = $r.VaultId; SubscriptionId = $r.SubscriptionId; ResourceGroup = $r.ResourceGroup; VaultName = $r.VaultName }
  }
}
$skippedVaults = @($skipRows | Where-Object { -not $vaults.ContainsKey($_.VaultId) } | Select-Object -ExpandProperty VaultName -Unique)
Write-Log "$($rows.Count) row(s) and $($vaults.Count) vault(s) in scope; $($skipRows.Count) row(s) skipped ($($skippedVaults.Count) vault(s) entirely skipped)"
if ($rows.Count -eq 0) { Write-Log "Nothing to do" "WARN"; return }

# Distinct planned role assignments. AssigneeKey is group:<name> or principal:<objectId>; group IDs resolved later.
function Get-PlannedAssignments {
  $planned = @{}
  foreach ($r in $rows) {
    if ($r.Action -eq "Drop" -or -not $r.ObjectId) { continue }
    if (-not $r.TargetRole -or $r.TargetRole -eq "NONE") { Write-Log "No TargetRole for $($r.VaultName) / $($r.DisplayName), skipping" "WARN"; continue }
    foreach ($roleName in @($r.TargetRole.Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
      if ($roleName -like "*REVIEW*") { Write-Log "Unresolved role '$roleName' for $($r.VaultName) / $($r.DisplayName), skipping" "WARN"; continue }
      if ($r.Action -eq "Group") {
        if (-not $r.TargetGroupName) { Write-Log "Action=Group but no TargetGroupName for $($r.VaultName) / $($r.DisplayName), skipping" "WARN"; continue }
        $assigneeKey = "group:$($r.TargetGroupName)"
        $assigneeName = $r.TargetGroupName
      }
      else {
        if ($r.PrincipalType -in @("Orphaned","ForeignTenant")) { Write-Log "Action=Direct on $($r.PrincipalType) identity $($r.ObjectId), skipping" "WARN"; continue }
        $assigneeKey = "principal:$($r.ObjectId.ToLower())"
        $assigneeName = "$($r.DisplayName) ($($r.PrincipalType))"
      }
      # Scope: vault by default. -GroupScope ResourceGroup moves Action=Group rows to the vault's resource group.
      # An optional TargetScope column (RG or subscription resource ID) overrides both for that row.
      $scope = $r.VaultId
      if ($r.Action -eq "Group" -and $GroupScope -eq "ResourceGroup") {
        $scope = $r.VaultId -replace "(?i)/providers/microsoft\.keyvault/vaults/[^/]+$", ""
      }
      if ($r.PSObject.Properties.Name -contains "TargetScope" -and "$($r.TargetScope)".Trim()) { $scope = "$($r.TargetScope)".Trim() }
      $scopeLabel = $scope.Split("/")[-1]
      if ($scope -match "(?i)^/subscriptions/[^/]+$") { $scopeLabel = "sub:$scopeLabel" }
      elseif ($scope -match "(?i)/resourcegroups/[^/]+$") { $scopeLabel = "rg:$scopeLabel" }
      $key = "$($scope.ToLower())|$assigneeKey|$roleName"
      if (-not $planned.ContainsKey($key)) {
        $planned[$key] = [PSCustomObject]@{
          SubscriptionId = $r.SubscriptionId
          Scope          = $scope
          ScopeLabel     = $scopeLabel
          AssigneeKey    = $assigneeKey
          AssigneeName   = $assigneeName
          RoleName       = $roleName
        }
      }
    }
  }
  return $planned
}

# Warn where a resource group or subscription scope also covers vaults that are not in this run's plan
function Write-ScopeCoverageWarning {
  param($Planned)
  $rgScopes = @($Planned.Values | Where-Object { $_.Scope -match "(?i)^/subscriptions/[^/]+/resourcegroups/[^/]+$" } | Select-Object -ExpandProperty Scope -Unique)
  foreach ($scope in $rgScopes) {
    $parts = $scope.Split("/")
    $subId = $parts[2]
    $rgName = $parts[4]
    Set-AzContext -SubscriptionId $subId -TenantId $tenantId -WhatIf:$false | Out-Null
    $rgVaults = @(Get-AzKeyVault -ResourceGroupName $rgName | Select-Object -ExpandProperty VaultName)
    $planVaults = @($vaults.Values | Where-Object { $_.SubscriptionId -eq $subId -and $_.ResourceGroup -eq $rgName } | Select-Object -ExpandProperty VaultName)
    $extra = @($rgVaults | Where-Object { $_ -notin $planVaults })
    if ($extra.Count -eq 0) { Write-Log "RG scope $rgName covers $($rgVaults.Count) vault(s), all in this run"; continue }
    # An RG-scope assignment is live on any vault already on RBAC, and inert on access policy vaults until they flip
    $liveNow = New-Object System.Collections.Generic.List[string]
    $inert = New-Object System.Collections.Generic.List[string]
    foreach ($name in $extra) {
      $label = $name
      if ($name -in $skippedVaults) { $label = "$name (Skip)" }
      $rbac = $null
      try { $rbac = [bool](Get-AzKeyVault -VaultName $name -ResourceGroupName $rgName).EnableRbacAuthorization } catch { }
      if ($rbac -eq $true) { $liveNow.Add($label) } else { $inert.Add($label) }
    }
    Write-Log "RG scope $rgName also covers $($extra.Count) vault(s) outside this run"
    if ($liveNow.Count -gt 0) { Write-Log "  Already on RBAC, group gets the role immediately: $($liveNow -join ', ')" "WARN" }
    if ($inert.Count -gt 0) { Write-Log "  Access policy mode, assignment inert until flipped: $($inert -join ', ')" }
  }
  $subScopes = @($Planned.Values | Where-Object { $_.Scope -match "(?i)^/subscriptions/[^/]+$" } | Select-Object -ExpandProperty Scope -Unique)
  foreach ($scope in $subScopes) { Write-Log "Subscription scope $scope covers every vault in the subscription, current and future" "WARN" }
}
#endregion

if ($Action -eq "Plan") {
  #region Plan
  $groupRows = @($rows | Where-Object { $_.Action -eq "Group" -and $_.TargetGroupName })
  $groupNames = @($groupRows | Select-Object -ExpandProperty TargetGroupName -Unique | Sort-Object)
  Write-Log "Groups ($($groupNames.Count)):"
  foreach ($name in $groupNames) {
    $members = @($groupRows | Where-Object { $_.TargetGroupName -eq $name } | Select-Object -ExpandProperty ObjectId -Unique)
    $exists = "to be created"
    if (Get-TargetGroup -Name $name) { $exists = "exists" }
    Write-Log ("  {0,-60} {1,4} member(s)  {2}" -f $name, $members.Count, $exists)
  }
  $planned = Get-PlannedAssignments
  Write-Log "Role assignments ($($planned.Count)):"
  foreach ($a in ($planned.Values | Sort-Object ScopeLabel, RoleName, AssigneeName)) {
    Write-Log ("  {0,-40} {1,-42} {2}" -f $a.ScopeLabel, $a.RoleName, $a.AssigneeName)
  }
  Write-ScopeCoverageWarning -Planned $planned
  $direct = @($rows | Where-Object { $_.Action -eq "Direct" })
  $drop = @($rows | Where-Object { $_.Action -eq "Drop" })
  Write-Log "Direct assignments: $($direct.Count) row(s). Dropped identities: $($drop.Count) row(s). Skipped rows: $($skipRows.Count)."
  foreach ($d in $drop) { Write-Log ("  DROP {0,-40} {1} ({2})" -f $d.VaultName, $d.DisplayName, $d.PrincipalType) }
  foreach ($v in $skippedVaults) { Write-Log ("  SKIP {0,-40} vault entirely skipped" -f $v) }
  $review = @($rows | Where-Object { $_.Action -ne "Drop" -and ($_.TargetRole -like "*REVIEW*" -or $_.TargetRole -eq "NONE" -or -not $_.TargetRole) })
  if ($review.Count -gt 0) { Write-Log "$($review.Count) row(s) still need a TargetRole decision" "WARN" }
  Write-Log "Vaults ($($vaults.Count)):"
  foreach ($v in ($vaults.Values | Sort-Object VaultName)) { Write-Log ("  {0,-40} {1}" -f $v.VaultName, $v.ResourceGroup) }
  #endregion
}

elseif ($Action -eq "Groups") {
  #region Groups
  $groupRows = @($rows | Where-Object { $_.Action -eq "Group" -and $_.TargetGroupName })
  $groupNames = @($groupRows | Select-Object -ExpandProperty TargetGroupName -Unique | Sort-Object)
  $createdGroups = 0
  $addedMembers = 0
  foreach ($name in $groupNames) {
    # Optional TargetGroupDescription column: holds the scope rule for the group (e.g. Scope: RG name contains "shared-platform")
    $description = $DefaultGroupDescription
    $descRow = $groupRows | Where-Object { $_.TargetGroupName -eq $name -and $_.PSObject.Properties.Name -contains "TargetGroupDescription" -and "$($_.TargetGroupDescription)".Trim() } | Select-Object -First 1
    if ($descRow) { $description = "$($descRow.TargetGroupDescription)".Trim() }

    $g = Get-TargetGroup -Name $name
    if (-not $g) {
      if ($PSCmdlet.ShouldProcess($name, "Create Entra security group")) {
        $nick = ($name -replace "[^A-Za-z0-9]", "")
        if ($nick.Length -gt 64) { $nick = $nick.Substring(0, 64) }
        $new = New-AzADGroup -DisplayName $name -MailNickname $nick -SecurityEnabled -Description $description
        $g = [PSCustomObject]@{ id = $new.Id; displayName = $name; description = $description }
        $groupCache[$name] = $g
        $createdGroups++
        Write-Log "Created group $name ($($new.Id))"
      }
      else { continue }
    }
    elseif ($descRow -and "$($g.description)" -ne $description) {
      if ($PSCmdlet.ShouldProcess($name, "Update description")) {
        $resp = Invoke-AzRestMethod -Method PATCH -Uri "https://graph.microsoft.com/v1.0/groups/$($g.id)" -Payload (@{ description = $description } | ConvertTo-Json)
        if ($resp.StatusCode -eq 204) { Write-Log "Updated description on $name" }
        else { Write-Log "Description update failed on $name ($($resp.StatusCode)): $($resp.Content)" "WARN" }
      }
    }
    $wanted = @($groupRows | Where-Object { $_.TargetGroupName -eq $name -and $_.ObjectId -and $_.PrincipalType -notin @("Orphaned","ForeignTenant") } | Select-Object -ExpandProperty ObjectId -Unique)
    $existing = @{}
    foreach ($m in (Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/groups/$($g.id)/members?`$select=id")) { $existing[$m.id.ToLower()] = $true }
    $toAdd = @($wanted | Where-Object { -not $existing.ContainsKey($_.ToLower()) })
    Write-Log "$name : $($wanted.Count) wanted, $($existing.Count) existing, $($toAdd.Count) to add"
    foreach ($m in $toAdd) {
      if ($PSCmdlet.ShouldProcess("$name <- $m", "Add member")) {
        try { Add-AzADGroupMember -TargetGroupObjectId $g.id -MemberObjectId $m; $addedMembers++ }
        catch { Write-Log "Failed adding $m to $name : $($_.Exception.Message)" "WARN" }
      }
    }
  }
  Write-Log "Groups created: $createdGroups, members added: $addedMembers"
  #endregion
}

elseif ($Action -eq "Assign") {
  #region Assign
  $planned = Get-PlannedAssignments
  Write-Log "$($planned.Count) distinct role assignment(s) planned"
  $roleNames = @($planned.Values | Select-Object -ExpandProperty RoleName -Unique)
  foreach ($rn in $roleNames) { if (-not (Get-AzRoleDefinition -Name $rn)) { throw "Role definition '$rn' not found" } }

  # Resolve group names to IDs once
  $assigneeIds = @{}
  foreach ($a in $planned.Values) {
    if ($assigneeIds.ContainsKey($a.AssigneeKey)) { continue }
    if ($a.AssigneeKey -like "group:*") {
      $g = Get-TargetGroup -Name $a.AssigneeKey.Substring(6)
      if (-not $g) { Write-Log "Group '$($a.AssigneeKey.Substring(6))' does not exist. Run -Action Groups first." "ERROR"; $script:exitCode = 1; $assigneeIds[$a.AssigneeKey] = $null }
      else { $assigneeIds[$a.AssigneeKey] = $g.id }
    }
    else { $assigneeIds[$a.AssigneeKey] = $a.AssigneeKey.Substring(10) }
  }

  Write-ScopeCoverageWarning -Planned $planned

  $existingByScope = @{}
  $created = 0
  $present = 0
  $failed = 0
  foreach ($subId in @($planned.Values | Select-Object -ExpandProperty SubscriptionId -Unique)) {
    Set-AzContext -SubscriptionId $subId -TenantId $tenantId -WhatIf:$false | Out-Null
    foreach ($a in @($planned.Values | Where-Object { $_.SubscriptionId -eq $subId } | Sort-Object ScopeLabel, RoleName)) {
      $assigneeId = $assigneeIds[$a.AssigneeKey]
      if (-not $assigneeId) { continue }
      if (-not $existingByScope.ContainsKey($a.Scope)) {
        $set = @{}
        foreach ($ra in @(Get-AzRoleAssignment -Scope $a.Scope)) {
          if (-not $ra.ObjectId -or -not $ra.Scope) { continue }
          # Only an assignment at the target scope or above it satisfies the plan; child-scope (vault) assignments do not
          if (-not $a.Scope.ToLower().StartsWith($ra.Scope.ToLower())) { continue }
          $set["$($ra.ObjectId.ToLower())|$("$($ra.RoleDefinitionName)".ToLower())"] = $ra.Scope
        }
        $existingByScope[$a.Scope] = $set
      }
      $k = "$($assigneeId.ToLower())|$($a.RoleName.ToLower())"
      if ($existingByScope[$a.Scope].ContainsKey($k)) { $present++; continue }
      if (-not $PSCmdlet.ShouldProcess("$($a.ScopeLabel) : $($a.AssigneeName)", "Assign $($a.RoleName)")) { continue }
      $attempt = 0
      $done = $false
      while (-not $done -and $attempt -lt 3) {
        $attempt++
        try {
          New-AzRoleAssignment -ObjectId $assigneeId -RoleDefinitionName $a.RoleName -Scope $a.Scope -ErrorAction Stop | Out-Null
          $done = $true
          $created++
          Write-Log "Assigned $($a.RoleName) to $($a.AssigneeName) on $($a.ScopeLabel)"
        }
        catch {
          $msg = $_.Exception.Message
          if ($msg -match "already exists") { $done = $true; $present++ }
          elseif ($msg -match "PrincipalNotFound|does not exist in the directory" -and $attempt -lt 3) {
            Write-Log "$($a.AssigneeName) not replicated yet, retrying in 30s" "WARN"
            Start-Sleep -Seconds 30
          }
          else { $done = $true; $failed++; $script:exitCode = 1; Write-Log "Failed: $($a.ScopeLabel) / $($a.AssigneeName) / $($a.RoleName): $msg" "ERROR" }
        }
      }
    }
  }
  Write-Log "Assignments created: $created, already present: $present, failed: $failed"
  #endregion
}

elseif ($Action -eq "Verify") {
  #region Verify
  $results = New-Object System.Collections.Generic.List[object]
  $planByKey = @{}
  foreach ($r in ($rows + $skipRows)) { if ($r.ObjectId) { $planByKey["$($r.VaultId.ToLower())|$($r.ObjectId.ToLower())"] = $r } }

  foreach ($subId in @($vaults.Values | Select-Object -ExpandProperty SubscriptionId -Unique)) {
    Set-AzContext -SubscriptionId $subId -TenantId $tenantId -WhatIf:$false | Out-Null
    foreach ($v in @($vaults.Values | Where-Object { $_.SubscriptionId -eq $subId } | Sort-Object VaultName)) {
      $kv = Get-AzKeyVault -VaultName $v.VaultName -ResourceGroupName $v.ResourceGroup
      $ras = @(Get-AzRoleAssignment -Scope $kv.ResourceId)

      # Effective Key Vault data actions per assignee (direct and inherited)
      $effective = @{}
      $effectiveNames = @{}
      $groupAssignees = New-Object System.Collections.Generic.List[string]
      Write-Log "$($kv.VaultName): $($ras.Count) role assignment(s) at or above vault scope, permission model $(if ($kv.EnableRbacAuthorization) { 'RBAC' } else { 'access policy' })"
      foreach ($ra in $ras) {
        if (-not $ra.ObjectId) { continue }
        $oid = $ra.ObjectId.ToLower()
        $covered = Get-RoleCovered -RoleDefinitionId $ra.RoleDefinitionId -SubscriptionId $subId
        if ($covered.Count -eq 0) { continue }   # Owner, Contributor etc. carry no Key Vault data actions
        if (-not $effective.ContainsKey($oid)) {
          $effective[$oid] = @{}
          $effectiveNames[$oid] = New-Object System.Collections.Generic.List[string]
        }
        foreach ($k in $covered.Keys) { $effective[$oid][$k] = $true }
        $scopeLabel = "inherited"
        if ($ra.Scope -eq $kv.ResourceId) { $scopeLabel = "vault" }
        $effectiveNames[$oid].Add("$($ra.RoleDefinitionName)@$scopeLabel")
        Write-Log ("  {0,-40} {1,-16} {2} ({3}) @{4}, {5} data action(s)" -f $ra.RoleDefinitionName, $ra.ObjectType, $ra.DisplayName, $oid, $scopeLabel, $covered.Count)
        # Anything that is not a user or service principal is checked as a possible group (ObjectType can come back Unknown or blank)
        if ($ra.ObjectType -notin @("User", "ServicePrincipal") -and -not $groupAssignees.Contains($oid)) { $groupAssignees.Add($oid) }
      }
      if ($effective.Count -eq 0) {
        Write-Log "  No assignment with Key Vault data actions reaches this vault" "WARN"
        foreach ($ra in @($ras | Where-Object { "$($_.RoleDefinitionName)" -like "Key Vault*" })) {
          Write-Log ("  raw: role='{0}' roleDefinitionId='{1}' objectType='{2}' displayName='{3}' scope='{4}'" -f $ra.RoleDefinitionName, $ra.RoleDefinitionId, $ra.ObjectType, $ra.DisplayName, $ra.Scope) "WARN"
        }
      }

      foreach ($ap in @($kv.AccessPolicies)) {
        $oid = "$($ap.ObjectId)".ToLower()
        $perms = New-Object System.Collections.Generic.List[string]
        foreach ($p in (Expand-ApPermission -Permissions $ap.PermissionsToKeys -Category "key"))                 { $perms.Add("key $p") }
        foreach ($p in (Expand-ApPermission -Permissions $ap.PermissionsToSecrets -Category "secret"))           { $perms.Add("secret $p") }
        foreach ($p in (Expand-ApPermission -Permissions $ap.PermissionsToCertificates -Category "certificate")) { $perms.Add("certificate $p") }
        foreach ($p in (Expand-ApPermission -Permissions $ap.PermissionsToStorage -Category "storage"))          { $perms.Add("storage $p") }
        $required = @{}
        foreach ($p in $perms) { if ($apToDataActions.ContainsKey($p)) { foreach ($d in $apToDataActions[$p]) { $required[$d] = $true } } }

        $have = @{}
        $via = New-Object System.Collections.Generic.List[string]
        if ($effective.ContainsKey($oid)) {
          foreach ($k in $effective[$oid].Keys) { $have[$k] = $true }
          foreach ($n in $effectiveNames[$oid]) { $via.Add("direct:$n") }
        }
        if ($groupAssignees.Count -gt 0) {
          $hits = @(Get-TransitiveGroupHits -ObjectId $oid -GroupIds $groupAssignees.ToArray())
          Write-Log ("  {0} ({1}): member of {2} of {3} candidate group(s)" -f $ap.DisplayName, $oid, $hits.Count, $groupAssignees.Count)
          foreach ($gid in $hits) {
            if (-not $effective.ContainsKey($gid)) { continue }
            foreach ($k in $effective[$gid].Keys) { $have[$k] = $true }
            foreach ($n in $effectiveNames[$gid]) { $via.Add("group:$gid/$n") }
          }
        }
        $missing = @($required.Keys | Where-Object { -not $have.ContainsKey($_) } | Sort-Object)

        $planRow = $planByKey["$($kv.ResourceId.ToLower())|$oid"]
        $plannedAction = "NotInPlan"
        $displayName = $ap.DisplayName
        $principalType = ""
        if ($planRow) { $plannedAction = $planRow.Action; $displayName = $planRow.DisplayName; $principalType = $planRow.PrincipalType }

        if ($missing.Count -eq 0)          { $status = "OK" }
        elseif ($plannedAction -eq "Drop") { $status = "DROPPED" }
        elseif ($plannedAction -eq "Skip") { $status = "SKIPPED" }
        elseif ($have.Count -eq 0)         { $status = "NO-ROLE" }
        else                               { $status = "GAP" }

        $results.Add([PSCustomObject]@{
          VaultName          = $kv.VaultName
          RbacEnabled        = [bool]$kv.EnableRbacAuthorization
          ObjectId           = $oid
          DisplayName        = $displayName
          PrincipalType      = $principalType
          PlannedAction      = $plannedAction
          Status             = $status
          RequiredCount      = $required.Count
          MissingCount       = $missing.Count
          MissingDataActions = ($missing -join ";")
          CoveredVia         = ($via -join ";")
        })
        if ($status -ne "OK") {
          $level = "WARN"
          if ($status -in @("DROPPED", "SKIPPED")) { $level = "INFO" }
          Write-Log "$($kv.VaultName) | $displayName ($oid) | $status | missing: $($missing -join ', ')" $level
        }
      }
    }
  }

  $verifyFile = Join-Path $OutputFolder "KvVerify-$tenantId-$stamp.csv"
  $results | Export-Csv -Path $verifyFile -NoTypeInformation -Encoding UTF8 -WhatIf:$false
  foreach ($s in ($results | Group-Object Status | Sort-Object Name)) { Write-Log ("  {0,-8} {1,5}" -f $s.Name, $s.Count) }
  Write-Log "Verify report: $verifyFile"
  $gaps = @($results | Where-Object { $_.Status -in @("GAP","NO-ROLE") })
  if ($gaps.Count -gt 0) { $script:exitCode = 1; Write-Log "$($gaps.Count) identity/vault pair(s) would lose access on flip" "ERROR" }
  else { Write-Log "All access policy identities are covered by RBAC (or planned Drop)" }
  #endregion
}

elseif ($Action -in @("Flip","Rollback")) {
  #region Flip / Rollback
  $target = ($Action -eq "Flip")
  $changeLog = New-Object System.Collections.Generic.List[object]
  foreach ($subId in @($vaults.Values | Select-Object -ExpandProperty SubscriptionId -Unique)) {
    Set-AzContext -SubscriptionId $subId -TenantId $tenantId -WhatIf:$false | Out-Null
    foreach ($v in @($vaults.Values | Where-Object { $_.SubscriptionId -eq $subId } | Sort-Object VaultName)) {
      $kv = Get-AzKeyVault -VaultName $v.VaultName -ResourceGroupName $v.ResourceGroup
      $current = [bool]$kv.EnableRbacAuthorization
      $result = "unchanged"
      if ($current -eq $target) {
        Write-Log "$($v.VaultName): EnableRbacAuthorization already $target"
      }
      elseif ($PSCmdlet.ShouldProcess($v.VaultName, "Set EnableRbacAuthorization=$target")) {
        try {
          # Az.KeyVault 6.0.0 (Az 12) replaced -EnableRbacAuthorization with -DisableRbacAuthorization
          $updateParams = @{ VaultName = $v.VaultName; ResourceGroupName = $v.ResourceGroup }
          if ((Get-Command Update-AzKeyVault).Parameters.ContainsKey("DisableRbacAuthorization")) { $updateParams["DisableRbacAuthorization"] = (-not $target) }
          else { $updateParams["EnableRbacAuthorization"] = $target }
          Update-AzKeyVault @updateParams | Out-Null
          $result = "changed"
          Write-Log "$($v.VaultName): EnableRbacAuthorization $current -> $target"
        }
        catch { $result = "failed"; $script:exitCode = 1; Write-Log "$($v.VaultName): $($_.Exception.Message)" "ERROR" }
      }
      else { $result = "whatif" }
      $changeLog.Add([PSCustomObject]@{
        Timestamp      = (Get-Date -Format "s")
        Action         = $Action
        Account        = $context.Account.Id
        SubscriptionId = $subId
        ResourceGroup  = $v.ResourceGroup
        VaultName      = $v.VaultName
        VaultId        = $v.VaultId
        Before         = $current
        Target         = $target
        Result         = $result
      })
    }
  }
  $logFile = Join-Path $OutputFolder "KvPermissionModel-$Action-$tenantId-$stamp.csv"
  $changeLog | Export-Csv -Path $logFile -NoTypeInformation -Encoding UTF8 -WhatIf:$false
  Write-Log "Change log: $logFile"
  #endregion
}

if ($script:exitCode -ne 0) { exit $script:exitCode }
