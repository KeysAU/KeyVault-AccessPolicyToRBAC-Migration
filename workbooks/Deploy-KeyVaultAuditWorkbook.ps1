<#
.SYNOPSIS
  Deploys KeyVault-Audit.workbook.json as a shared Azure Monitor workbook linked to your Log Analytics workspace.

.DESCRIPTION
  Reads the workbook JSON, points fallbackResourceIds at the workspace, optionally sets the Time_Zone parameter default,
  then deploys workbook.template.json with New-AzResourceGroupDeployment. The workbook resource name is a GUID derived
  from the workspace ID and display name, so running the script again updates the same workbook in place.

  The portal alternative needs no script: Monitor > Workbooks > New > Advanced Editor, paste the JSON, Apply, Save into
  the workspace. The portal overwrites fallbackResourceIds with the workspace you save into.

.PARAMETER WorkspaceResourceId
  Resource ID of the Log Analytics workspace that receives Key Vault AuditEvent diagnostics.
.PARAMETER ResourceGroupName
  Resource group to hold the workbook resource. Default is the workspace's resource group.
.PARAMETER DisplayName
  Gallery display name. Default "Key Vault Audit".
.PARAMETER TimeZone
  IANA time zone written into the workbook's Time_Zone parameter default (e.g. Australia/Sydney). Default leaves UTC.
.PARAMETER WorkbookFile
  Path to the workbook JSON. Default is KeyVault-Audit.workbook.json next to this script.

.EXAMPLE
  .\Deploy-KeyVaultAuditWorkbook.ps1 -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>" -TimeZone "Australia/Sydney"

.NOTES
  Rights: Workbook Contributor (or Contributor) on the target resource group. Modules: Az.Accounts, Az.Resources.
  Windows PowerShell 5.1 compatible.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][string]$WorkspaceResourceId,
  [string]$ResourceGroupName,
  [string]$DisplayName = "Key Vault Audit",
  [string]$TimeZone,
  [string]$WorkbookFile = (Join-Path $PSScriptRoot "KeyVault-Audit.workbook.json")
)

#region TESTING
# $WorkspaceResourceId = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-logging/providers/Microsoft.OperationalInsights/workspaces/law-central"
# $TimeZone = "Australia/Sydney"
#endregion TESTING

$ErrorActionPreference = "Stop"

if ($WorkspaceResourceId -notmatch "(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.OperationalInsights/workspaces/([^/]+)$") {
  throw "WorkspaceResourceId is not a Log Analytics workspace resource ID: $WorkspaceResourceId"
}
$workspaceSubscriptionId = $Matches[1]
if (-not $ResourceGroupName) { $ResourceGroupName = $Matches[2] }

$context = Get-AzContext
if (-not $context) { throw "No Az context. Run Connect-AzAccount first." }
if ($context.Subscription.Id -ne $workspaceSubscriptionId) {
  Set-AzContext -SubscriptionId $workspaceSubscriptionId -WhatIf:$false | Out-Null
}

if (-not (Test-Path $WorkbookFile)) { throw "Workbook file not found: $WorkbookFile" }
$workbook = Get-Content -Path $WorkbookFile -Raw -Encoding UTF8 | ConvertFrom-Json
$workbook.fallbackResourceIds = @($WorkspaceResourceId)

if ($TimeZone) {
  $tzParam = $workbook.items[0].content.parameters | Where-Object { $_.name -eq "Time_Zone" }
  if (-not $tzParam) { throw "Time_Zone parameter not found in the workbook JSON" }
  $tzParam.value = $TimeZone
  Write-Host "Time_Zone default set to $TimeZone"
}

# Deterministic workbook resource name so repeat deployments update in place
$md5 = [System.Security.Cryptography.MD5]::Create()
$hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($WorkspaceResourceId.ToLower())|$DisplayName"))
$workbookId = (New-Object System.Guid -ArgumentList (,$hash)).ToString()

$serialized = $workbook | ConvertTo-Json -Depth 100 -Compress
Write-Host ("Workbook JSON {0:N0} characters, resource name {1}, resource group {2}" -f $serialized.Length, $workbookId, $ResourceGroupName)

$templateFile = Join-Path $PSScriptRoot "workbook.template.json"
$parameters = @{
  workbookDisplayName = $DisplayName
  workbookSourceId    = $WorkspaceResourceId
  workbookContent     = $serialized
  workbookId          = $workbookId
}

if ($PSCmdlet.ShouldProcess("$ResourceGroupName / $DisplayName", "Deploy workbook")) {
  $deployment = New-AzResourceGroupDeployment -Name ("kv-audit-workbook-{0:yyyyMMddHHmm}" -f (Get-Date)) `
    -ResourceGroupName $ResourceGroupName -TemplateFile $templateFile -TemplateParameterObject $parameters -Mode Incremental
  if ($deployment.ProvisioningState -ne "Succeeded") { throw "Deployment ended in state $($deployment.ProvisioningState)" }
  Write-Host "Deployed: $($deployment.Outputs.workbookResourceId.Value)"
  [PSCustomObject]@{
    WorkbookResourceId = $deployment.Outputs.workbookResourceId.Value
    DisplayName        = $DisplayName
    Workspace          = $WorkspaceResourceId
  }
}
