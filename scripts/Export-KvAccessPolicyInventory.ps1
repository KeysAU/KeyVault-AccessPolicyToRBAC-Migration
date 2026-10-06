<#
.SYNOPSIS
  Key Vault access policy inventory for the Azure RBAC migration (step 1 of the process).

.DESCRIPTION
  Runs against every enabled subscription in the current tenant context and produces:
    1. KvAccessPolicies-<tenant>-<stamp>.csv  - one row per vault access policy entry. Identity resolved via Graph
       (User / Group / ServicePrincipal / ManagedIdentity / Orphaned / ForeignTenant), legacy "all" permissions expanded,
       least-privilege built-in role suggested from the live role definitions, optional 90-day usage joined from Key Vault
       AuditEvent logs. The trailing columns (TargetGroupName, TargetGroupDescription, TargetRole, TargetScope, Action,
       Wave, Notes) are the consolidation columns consumed by Invoke-KvRbacMigration.ps1.
    2. KvRoleAssignments-<tenant>-<stamp>.csv - every role assignment visible at vault scope (direct and inherited),
       flagged where the role carries Key Vault data actions.
    3. KvUsage-<tenant>-<stamp>.csv           - raw usage query output (only with -LogAnalyticsWorkspaceId).

.PARAMETER OutputFolder
  Folder for the CSV files. Created if missing.
.PARAMETER SubscriptionId
  Optional subscription filter. Default is every enabled subscription in the tenant.
.PARAMETER LogAnalyticsWorkspaceId
  Workspace (customer) ID of the Log Analytics workspace holding Key Vault AuditEvent diagnostics. Optional; without it
  the usage columns stay blank.
.PARAMETER UsageDays
  Usage lookback window in days. Default 90.

.NOTES
  Run once per tenant: Connect-AzAccount -Tenant <tenantId> (or the pipeline service connection), then run this script.
  Modules: Az.Accounts, Az.Resources, Az.KeyVault, Az.Monitor; Az.OperationalInsights when -LogAnalyticsWorkspaceId is used.
           Az 16.3.0 or later recommended (Key Vault control plane API 2026-02-01).
  Rights:  Reader on the subscriptions; directory read (Directory Readers or Directory.Read.All) for Graph getByIds;
           Log Analytics Reader on the workspace for usage.
  Windows PowerShell 5.1 compatible. Mapping table is the one shipped with Azure/KeyVault-AccessPolicyToRBAC-CompareTool.
#>
[CmdletBinding()]
param(
  [string]$OutputFolder = ".\KvInventory",
  [string[]]$SubscriptionId,
  [string]$LogAnalyticsWorkspaceId,
  [int]$UsageDays = 90
)

#region TESTING
# $OutputFolder = "C:\Temp\KvInventory"
# $LogAnalyticsWorkspaceId = "00000000-0000-0000-0000-000000000000"   # Log Analytics workspace (customer) ID
# $SubscriptionId = @("00000000-0000-0000-0000-000000000000")
#endregion TESTING

$ErrorActionPreference = "Stop"

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
New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
Write-Log "Tenant $tenantId, account $($context.Account.Id)"

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

$apToDataActions = @{}   # "key get" -> string[] of lowercase data actions
$allKvDataActions = @{}  # universe of mapped data actions (lowercase)
foreach ($m in ($mappingCsv | ConvertFrom-Csv)) {
  $actions = @($m.'RBAC Data Action'.ToLower().Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  $apToDataActions[$m.'Access Policy Permission'.ToLower()] = $actions
  foreach ($a in $actions) { $allKvDataActions[$a] = $true }
}
#endregion

#region Legacy "all" permission expansion
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
#endregion

#region Built-in role coverage (live role definitions, wildcards expanded against the mapping universe)
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

# Role definitions via ARM REST (properties.permissions[].dataActions is stable across Az.Resources versions).
# Looked up under the first subscription in scope ($roleScope); built-in roles are visible at any subscription.
function Get-RoleDefinitionJson {
  param([string]$RoleGuid, [string]$RoleName)
  if ($RoleGuid) { $path = "$roleScope/providers/Microsoft.Authorization/roleDefinitions/${RoleGuid}?api-version=2022-04-01" }
  else { $path = "$roleScope/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&`$filter=" + [uri]::EscapeDataString("roleName eq '$RoleName'") }
  $resp = Invoke-AzRestMethod -Method GET -Path $path
  if ($resp.StatusCode -ne 200) { throw "Role definition lookup failed (HTTP $($resp.StatusCode)): $($resp.Content)" }
  $json = ConvertFrom-Json $resp.Content
  if ($RoleGuid) { return $json }
  return @($json.value | Select-Object -First 1)[0]
}

function Get-RoleCoverageFromJson {
  param($RoleJson)
  $dataActions = New-Object System.Collections.Generic.List[string]
  $notDataActions = New-Object System.Collections.Generic.List[string]
  foreach ($perm in @($RoleJson.properties.permissions)) {
    foreach ($v in @($perm.dataActions)) { if ($v) { $dataActions.Add("$v") } }
    foreach ($v in @($perm.notDataActions)) { if ($v) { $notDataActions.Add("$v") } }
  }
  return Get-CoveredDataActions -DataActions $dataActions.ToArray() -NotDataActions $notDataActions.ToArray()
}


function Get-SuggestedRole {
  param([string[]]$ApPermissions)   # e.g. "secret get", "key wrapkey"
  if (-not $ApPermissions -or $ApPermissions.Count -eq 0) { return "NONE" }
  $required = @{}   # data action -> category
  foreach ($p in $ApPermissions) {
    if (-not $apToDataActions.ContainsKey($p)) { return "REVIEW: unmapped permission '$p'" }
    $cat = $p.Split(" ")[0]
    foreach ($d in $apToDataActions[$p]) { $required[$d] = $cat }
  }
  # 1. single least-privileged role that covers everything
  foreach ($r in $roleCoverage.Keys) {
    $ok = $true
    foreach ($d in $required.Keys) { if (-not $roleCoverage[$r].ContainsKey($d)) { $ok = $false; break } }
    if ($ok) { return $r }
  }
  # 2. one role per category
  $combo = New-Object System.Collections.Generic.List[string]
  foreach ($cat in @("key","secret","certificate","storage")) {
    $catActions = @($required.Keys | Where-Object { $required[$_] -eq $cat })
    if ($catActions.Count -eq 0) { continue }
    $found = $null
    foreach ($r in $roleCoverage.Keys) {
      $ok = $true
      foreach ($d in $catActions) { if (-not $roleCoverage[$r].ContainsKey($d)) { $ok = $false; break } }
      if ($ok) { $found = $r; break }
    }
    if (-not $found) { return "Key Vault Administrator (REVIEW: no scoped built-in role covers the $cat permissions)" }
    if (-not $combo.Contains($found)) { $combo.Add($found) }
  }
  return ($combo -join ";")
}
#endregion

#region Graph identity resolution
function Resolve-DirectoryObject {
  param([string[]]$ObjectIds)
  $resolved = @{}
  $ids = @($ObjectIds | Where-Object { $_ } | Select-Object -Unique)
  for ($i = 0; $i -lt $ids.Count; $i += 1000) {
    $chunk = @($ids[$i..([Math]::Min($i + 999, $ids.Count - 1))])
    $payload = @{ ids = $chunk; types = @("user", "group", "servicePrincipal") } | ConvertTo-Json -Depth 3
    $resp = Invoke-AzRestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/directoryObjects/getByIds" -Payload $payload
    if ($resp.StatusCode -ne 200) { throw "Graph getByIds failed ($($resp.StatusCode)): $($resp.Content)" }
    foreach ($o in @((ConvertFrom-Json $resp.Content).value)) {
      $type = $o.'@odata.type'
      switch ($type) {
        "#microsoft.graph.user"  { $type = "User" }
        "#microsoft.graph.group" { $type = "Group" }
        "#microsoft.graph.servicePrincipal" {
          if ($o.servicePrincipalType -eq "ManagedIdentity") { $type = "ManagedIdentity" } else { $type = "ServicePrincipal" }
        }
      }
      $resolved[$o.id.ToLower()] = [PSCustomObject]@{
        PrincipalType     = $type
        DisplayName       = $o.displayName
        AppId             = $o.appId
        UserPrincipalName = $o.userPrincipalName
      }
    }
  }
  return $resolved
}
#endregion

#region Enumerate vaults
$subs = @(Get-AzSubscription -TenantId $tenantId | Where-Object { $_.State -eq "Enabled" })
if ($SubscriptionId) { $subs = @($subs | Where-Object { $SubscriptionId -contains $_.Id }) }
Write-Log "$($subs.Count) subscription(s) in scope"
if ($subs.Count -eq 0) { throw "No enabled subscriptions in scope" }
$roleScope = "/subscriptions/$($subs[0].Id)"

# Least privileged first. Administrator is deliberately excluded and only suggested as a REVIEW fallback.
$candidateRoles = @(
  "Key Vault Reader",
  "Key Vault Secrets User",
  "Key Vault Crypto Service Encryption User",
  "Key Vault Certificate User",
  "Key Vault Crypto User",
  "Key Vault Secrets Officer",
  "Key Vault Certificates Officer",
  "Key Vault Crypto Officer"
)
$roleCoverage = [ordered]@{}
foreach ($r in $candidateRoles) {
  $def = $null
  try { $def = Get-RoleDefinitionJson -RoleName $r } catch { Write-Log "Built-in role '$r': $($_.Exception.Message)" "WARN" }
  if (-not $def) { Write-Log "Built-in role '$r' not found, skipping" "WARN"; continue }
  $roleCoverage[$r] = Get-RoleCoverageFromJson -RoleJson $def
  Write-Log ("  {0,-42} {1,3} Key Vault data action(s)" -f $r, $roleCoverage[$r].Count)
}
Write-Log "Loaded coverage for $($roleCoverage.Count) built-in Key Vault roles"
if (@($roleCoverage.Values | Where-Object { $_.Count -eq 0 }).Count -gt 0) { throw "One or more built-in roles resolved to zero data actions; suggestions would be wrong. Stopping." }


$apRows = New-Object System.Collections.Generic.List[object]
$raRows = New-Object System.Collections.Generic.List[object]
$roleIsKvData = @{}   # RoleDefinitionId -> bool
$vaultCount = 0
$rbacVaultCount = 0

foreach ($sub in $subs) {
  Set-AzContext -SubscriptionId $sub.Id -TenantId $tenantId | Out-Null
  $vaults = @(Get-AzKeyVault)
  Write-Log "$($sub.Name): $($vaults.Count) vault(s)"

  foreach ($v in $vaults) {
    try { $kv = Get-AzKeyVault -VaultName $v.VaultName -ResourceGroupName $v.ResourceGroupName }
    catch { Write-Log "Cannot read $($v.VaultName): $($_.Exception.Message)" "WARN"; continue }
    $vaultCount++
    if ($kv.EnableRbacAuthorization) { $rbacVaultCount++ }

    $diagCount = "n/a"
    try { $diagCount = @(Get-AzDiagnosticSetting -ResourceId $kv.ResourceId -ErrorAction Stop -WarningAction SilentlyContinue).Count } catch { }

    $tagString = ""
    if ($kv.Tags -and $kv.Tags.Count -gt 0) {
      $tagString = ($kv.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ";"
    }

    $base = [ordered]@{
      TenantId                     = $tenantId
      SubscriptionId               = $sub.Id
      SubscriptionName             = $sub.Name
      ResourceGroup                = $kv.ResourceGroupName
      VaultName                    = $kv.VaultName
      VaultId                      = $kv.ResourceId
      Location                     = $kv.Location
      RbacEnabled                  = [bool]$kv.EnableRbacAuthorization
      EnabledForDeployment         = [bool]$kv.EnabledForDeployment
      EnabledForTemplateDeployment = [bool]$kv.EnabledForTemplateDeployment
      EnabledForDiskEncryption     = [bool]$kv.EnabledForDiskEncryption
      PublicNetworkAccess          = $kv.PublicNetworkAccess
      DiagnosticSettings           = $diagCount
      Tags                         = $tagString
    }

    $aps = @($kv.AccessPolicies)
    if ($aps.Count -eq 0) {
      $h = [ordered]@{}
      foreach ($k in $base.Keys) { $h[$k] = $base[$k] }
      foreach ($k in @("ApTenantId","ObjectId","ApplicationId","CompoundIdentity","PrincipalType","DisplayName","AppId","UserPrincipalName","KeyPermissions","SecretPermissions","CertificatePermissions","StoragePermissions","HadLegacyAll","SuggestedRole","UsageOps","UsageFailed","UsageLastSeen","UsageOperations","TargetGroupName","TargetGroupDescription","TargetRole","TargetScope","Action","Wave")) { $h[$k] = "" }
      $h["Notes"] = "No access policies"
      $apRows.Add([PSCustomObject]$h)
    }

    foreach ($ap in $aps) {
      $keyPerms  = Expand-ApPermission -Permissions $ap.PermissionsToKeys -Category "key"
      $secPerms  = Expand-ApPermission -Permissions $ap.PermissionsToSecrets -Category "secret"
      $certPerms = Expand-ApPermission -Permissions $ap.PermissionsToCertificates -Category "certificate"
      $stoPerms  = Expand-ApPermission -Permissions $ap.PermissionsToStorage -Category "storage"

      $hadAll = $false
      foreach ($list in @($ap.PermissionsToKeys, $ap.PermissionsToSecrets, $ap.PermissionsToCertificates, $ap.PermissionsToStorage)) {
        if ($list -and (@($list | ForEach-Object { "$_".ToLower() }) -contains "all")) { $hadAll = $true }
      }

      $apPerms = New-Object System.Collections.Generic.List[string]
      foreach ($p in $keyPerms)  { $apPerms.Add("key $p") }
      foreach ($p in $secPerms)  { $apPerms.Add("secret $p") }
      foreach ($p in $certPerms) { $apPerms.Add("certificate $p") }
      foreach ($p in $stoPerms)  { $apPerms.Add("storage $p") }
      $suggested = Get-SuggestedRole -ApPermissions $apPerms.ToArray()

      $h = [ordered]@{}
      foreach ($k in $base.Keys) { $h[$k] = $base[$k] }
      $h["ApTenantId"]             = "$($ap.TenantId)"
      $h["ObjectId"]               = "$($ap.ObjectId)"
      $h["ApplicationId"]          = "$($ap.ApplicationId)"
      $h["CompoundIdentity"]       = [bool]$ap.ApplicationId
      $h["PrincipalType"]          = ""
      $h["DisplayName"]            = $ap.DisplayName
      $h["AppId"]                  = ""
      $h["UserPrincipalName"]      = ""
      $h["KeyPermissions"]         = ($keyPerms -join ";")
      $h["SecretPermissions"]      = ($secPerms -join ";")
      $h["CertificatePermissions"] = ($certPerms -join ";")
      $h["StoragePermissions"]     = ($stoPerms -join ";")
      $h["HadLegacyAll"]           = $hadAll
      $h["SuggestedRole"]          = $suggested
      $h["UsageOps"]               = ""
      $h["UsageFailed"]            = ""
      $h["UsageLastSeen"]          = ""
      $h["UsageOperations"]        = ""
      $h["TargetGroupName"]        = ""
      $h["TargetGroupDescription"] = ""
      $h["TargetRole"]             = $suggested
      $h["TargetScope"]            = ""
      $h["Action"]                 = "Group"
      $h["Wave"]                   = ""
      $h["Notes"]                  = ""
      $apRows.Add([PSCustomObject]$h)
    }

    foreach ($ra in @(Get-AzRoleAssignment -Scope $kv.ResourceId)) {
      $roleGuid = "$($ra.RoleDefinitionId)"
      if ($roleGuid -match "([0-9a-fA-F-]{36})\s*$") { $roleGuid = $Matches[1] }
      if (-not $roleIsKvData.ContainsKey($roleGuid)) {
        $isKv = $false
        try { $isKv = ((Get-RoleCoverageFromJson -RoleJson (Get-RoleDefinitionJson -RoleGuid $roleGuid)).Count -gt 0) }
        catch { Write-Log "Role definition $roleGuid lookup failed: $($_.Exception.Message)" "WARN" }
        $roleIsKvData[$roleGuid] = $isKv
      }
      $raRows.Add([PSCustomObject]@{
        TenantId           = $tenantId
        SubscriptionId     = $sub.Id
        SubscriptionName   = $sub.Name
        ResourceGroup      = $kv.ResourceGroupName
        VaultName          = $kv.VaultName
        VaultId            = $kv.ResourceId
        RbacEnabled        = [bool]$kv.EnableRbacAuthorization
        Scope              = $ra.Scope
        Inherited          = ($ra.Scope -ne $kv.ResourceId)
        RoleDefinitionName = $ra.RoleDefinitionName
        RoleDefinitionId   = $ra.RoleDefinitionId
        IsKvDataRole       = $roleIsKvData[$roleGuid]
        ObjectId           = $ra.ObjectId
        ObjectType         = $ra.ObjectType
        DisplayName        = $ra.DisplayName
        SignInName         = $ra.SignInName
        Condition          = $ra.Condition
      })
    }
  }
}
Write-Log "$vaultCount vault(s) read, $rbacVaultCount already on RBAC, $($apRows.Count) access policy row(s), $($raRows.Count) role assignment row(s)"
#endregion

#region Resolve identities
$localIds = @($apRows | Where-Object { $_.ObjectId -and $_.ApTenantId -eq $tenantId } | Select-Object -ExpandProperty ObjectId -Unique)
Write-Log "Resolving $($localIds.Count) unique object ID(s) via Graph"
$resolved = @{}
if ($localIds.Count -gt 0) { $resolved = Resolve-DirectoryObject -ObjectIds $localIds }
$orphaned = 0
foreach ($row in $apRows) {
  if (-not $row.ObjectId) { continue }
  if ($row.ApTenantId -and $row.ApTenantId -ne $tenantId) { $row.PrincipalType = "ForeignTenant"; continue }
  $hit = $resolved[$row.ObjectId.ToLower()]
  if ($hit) {
    $row.PrincipalType     = $hit.PrincipalType
    $row.DisplayName       = $hit.DisplayName
    $row.AppId             = $hit.AppId
    $row.UserPrincipalName = $hit.UserPrincipalName
  }
  else {
    $row.PrincipalType = "Orphaned"
    $row.Action = "Drop"
    $orphaned++
  }
}
Write-Log "$orphaned orphaned access policy row(s) (pre-set to Action=Drop)"
#endregion

#region Usage from Key Vault AuditEvent logs (optional)
if ($LogAnalyticsWorkspaceId) {
  $usageQuery = @"
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent"
| where isnotempty(identity_claim_oid_g) or isnotempty(identity_claim_appid_g)
| extend Vault = tolower(Resource), Oid = tolower(tostring(identity_claim_oid_g)), AppId = tolower(tostring(identity_claim_appid_g))
| summarize Ops = count(), Failed = countif(ResultType != "Success"), LastSeen = max(TimeGenerated), Operations = strcat_array(make_set(OperationName, 25), ";") by Vault, Oid, AppId
"@
  Write-Log "Querying Key Vault AuditEvent usage for the last $UsageDays day(s)"
  $usage = Invoke-AzOperationalInsightsQuery -WorkspaceId $LogAnalyticsWorkspaceId -Query $usageQuery -Timespan (New-TimeSpan -Days $UsageDays) -Wait 300
  $usageRows = @($usage.Results)
  $usageByOid = @{}
  $usageByApp = @{}
  foreach ($u in $usageRows) {
    if ($u.Oid) { $usageByOid["$($u.Vault)|$($u.Oid)"] = $u }
    elseif ($u.AppId) { $usageByApp["$($u.Vault)|$($u.AppId)"] = $u }
  }
  $matched = 0
  foreach ($row in $apRows) {
    if (-not $row.ObjectId) { continue }
    $vault = $row.VaultName.ToLower()
    $u = $usageByOid["$vault|$($row.ObjectId.ToLower())"]
    if (-not $u -and $row.AppId) { $u = $usageByApp["$vault|$($row.AppId.ToLower())"] }
    if ($u) {
      $row.UsageOps        = $u.Ops
      $row.UsageFailed     = $u.Failed
      $row.UsageLastSeen   = $u.LastSeen
      $row.UsageOperations = $u.Operations
      $matched++
    }
    elseif ($row.DiagnosticSettings -eq 0) { $row.Notes = "No diagnostic settings on vault, usage unknown" }
  }
  $usageFile = Join-Path $OutputFolder "KvUsage-$tenantId-$stamp.csv"
  $usageRows | Export-Csv -Path $usageFile -NoTypeInformation -Encoding UTF8
  Write-Log "$($usageRows.Count) usage row(s) returned, $matched access policy row(s) matched. Raw usage: $usageFile"
}
#endregion

#region Export
$apFile = Join-Path $OutputFolder "KvAccessPolicies-$tenantId-$stamp.csv"
$raFile = Join-Path $OutputFolder "KvRoleAssignments-$tenantId-$stamp.csv"
$apRows | Export-Csv -Path $apFile -NoTypeInformation -Encoding UTF8
$raRows | Export-Csv -Path $raFile -NoTypeInformation -Encoding UTF8
Write-Log "Access policies : $apFile"
Write-Log "Role assignments: $raFile"

$typeSummary = $apRows | Where-Object { $_.ObjectId } | Group-Object PrincipalType | Sort-Object Count -Descending
foreach ($t in $typeSummary) { Write-Log ("  {0,-18} {1,5}" -f $t.Name, $t.Count) }
$roleSummary = $apRows | Where-Object { $_.ObjectId } | Group-Object SuggestedRole | Sort-Object Count -Descending
foreach ($t in $roleSummary) { Write-Log ("  {0,-80} {1,5}" -f $t.Name, $t.Count) }
#endregion
