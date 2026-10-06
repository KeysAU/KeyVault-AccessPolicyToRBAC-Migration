# Structure tests for the toolkit. No Azure connection needed; nothing here executes the migration scripts.
# Run: Invoke-Pester -Path .\tests -Output Detailed

BeforeDiscovery {
  $script:RepoRoot = Split-Path -Parent $PSScriptRoot
  $script:ScriptFiles = @(
    (Join-Path $RepoRoot "scripts/Export-KvAccessPolicyInventory.ps1"),
    (Join-Path $RepoRoot "scripts/Invoke-KvRbacMigration.ps1"),
    (Join-Path $RepoRoot "workbooks/Deploy-KeyVaultAuditWorkbook.ps1")
  )
}

BeforeAll {
  $script:RepoRoot = Split-Path -Parent $PSScriptRoot

  function Get-EmbeddedMappingCsv {
    param([string]$Path)
    $text = Get-Content -Path $Path -Raw
    if ($text -match '(?s)\$mappingCsv = @"\r?\n(.*?)\r?\n"@') { return $Matches[1].Trim() }
    return $null
  }
}

Describe "PowerShell scripts" {
  It "<_> parses without errors" -ForEach $ScriptFiles {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_, [ref]$tokens, [ref]$errors) | Out-Null
    $errors | Should -BeNullOrEmpty
  }

  It "<_> has comment-based help with SYNOPSIS and DESCRIPTION" -ForEach $ScriptFiles {
    $text = Get-Content -Path $_ -Raw
    $text | Should -Match '\.SYNOPSIS'
    $text | Should -Match '\.DESCRIPTION'
  }

  It "Invoke-KvRbacMigration.ps1 supports every documented action" {
    $text = Get-Content -Path (Join-Path $RepoRoot "scripts/Invoke-KvRbacMigration.ps1") -Raw
    $text | Should -Match 'ValidateSet\("Plan","Groups","Assign","Verify","Flip","Rollback"\)'
  }

  It "Invoke-KvRbacMigration.ps1 declares SupportsShouldProcess" {
    $text = Get-Content -Path (Join-Path $RepoRoot "scripts/Invoke-KvRbacMigration.ps1") -Raw
    $text | Should -Match 'SupportsShouldProcess\s*=\s*\$true'
  }
}

Describe "Access policy to RBAC mapping" {
  BeforeAll {
    $script:MappingFile = Join-Path $RepoRoot "data/AccessPolicyRBACMapping.csv"
    $script:MappingRows = @(Import-Csv -Path $MappingFile)
  }

  It "ships as data/AccessPolicyRBACMapping.csv with the expected columns" {
    $MappingRows.Count | Should -BeGreaterThan 50
    $MappingRows[0].PSObject.Properties.Name | Should -Contain "Access Policy Permission"
    $MappingRows[0].PSObject.Properties.Name | Should -Contain "RBAC Data Action"
  }

  It "covers every access policy category" {
    $categories = @($MappingRows | ForEach-Object { $_.'Access Policy Permission'.Split(" ")[0] } | Sort-Object -Unique)
    $categories | Should -Be @("Certificate", "Key", "Secret", "Storage")
  }

  It "maps only to Microsoft.KeyVault data actions" {
    foreach ($row in $MappingRows) {
      foreach ($action in $row.'RBAC Data Action'.Split(";")) {
        $action.Trim() | Should -Match '^Microsoft\.KeyVault/vaults/'
      }
    }
  }

  It "is identical to the copy embedded in <_>" -ForEach @("scripts/Export-KvAccessPolicyInventory.ps1", "scripts/Invoke-KvRbacMigration.ps1") {
    $embedded = Get-EmbeddedMappingCsv -Path (Join-Path $RepoRoot $_)
    $embedded | Should -Not -BeNullOrEmpty
    $expected = (Get-Content -Path $MappingFile -Raw).Trim() -replace "`r`n", "`n"
    ($embedded -replace "`r`n", "`n") | Should -Be $expected
  }
}

Describe "Sample plan CSV" {
  BeforeAll {
    $script:Plan = @(Import-Csv -Path (Join-Path $RepoRoot "data/KvPlan-sample.csv"))
    $script:RequiredColumns = @("TenantId", "SubscriptionId", "ResourceGroup", "VaultName", "VaultId", "ObjectId", "PrincipalType", "DisplayName", "TargetGroupName", "TargetRole", "Action", "Wave")
  }

  It "has every column Invoke-KvRbacMigration.ps1 requires" {
    foreach ($column in $RequiredColumns) { $Plan[0].PSObject.Properties.Name | Should -Contain $column }
  }

  It "has the optional TargetGroupDescription and TargetScope columns" {
    $Plan[0].PSObject.Properties.Name | Should -Contain "TargetGroupDescription"
    $Plan[0].PSObject.Properties.Name | Should -Contain "TargetScope"
  }

  It "uses only valid Action values" {
    $Plan | ForEach-Object { $_.Action | Should -BeIn @("Group", "Direct", "Drop", "Skip") }
  }

  It "demonstrates every Action" {
    $actions = @($Plan | Select-Object -ExpandProperty Action -Unique | Sort-Object)
    $actions | Should -Be @("Direct", "Drop", "Group", "Skip")
  }

  It "gives every non-Skip row a Wave" {
    $Plan | Where-Object { $_.Action -ne "Skip" } | ForEach-Object { $_.Wave | Should -Not -BeNullOrEmpty }
  }

  It "gives every Group row a TargetGroupName" {
    $Plan | Where-Object { $_.Action -eq "Group" } | ForEach-Object { $_.TargetGroupName | Should -Not -BeNullOrEmpty }
  }

  It "uses only placeholder tenant and subscription IDs" {
    $Plan | ForEach-Object {
      $_.TenantId | Should -Be "11111111-1111-1111-1111-111111111111"
      $_.SubscriptionId | Should -Be "22222222-2222-2222-2222-222222222222"
    }
  }

  It "follows the group naming convention" {
    $names = @($Plan | Where-Object { $_.TargetGroupName } | Select-Object -ExpandProperty TargetGroupName -Unique)
    foreach ($name in $names) { $name | Should -Match '^RBAC_(RG_[^_]+_KVAdmin|KV_[^_]+_Admin)$' }
  }
}

Describe "Workbook" {
  BeforeAll {
    $script:WorkbookPath = Join-Path $RepoRoot "workbooks/KeyVault-Audit.workbook.json"
    $script:WorkbookText = Get-Content -Path $WorkbookPath -Raw -Encoding UTF8
    $script:Workbook = $WorkbookText | ConvertFrom-Json
  }

  It "is valid workbook JSON" {
    $Workbook.version | Should -Be "Notebook/1.0"
    $Workbook.items.Count | Should -BeGreaterThan 0
  }

  It "carries a placeholder workspace in fallbackResourceIds" {
    $Workbook.fallbackResourceIds.Count | Should -Be 1
    $Workbook.fallbackResourceIds[0] | Should -Match '00000000-0000-0000-0000-000000000000'
  }

  It "exposes the Time_Zone parameter used by the off-hours analysis" {
    $tz = $Workbook.items[0].content.parameters | Where-Object { $_.name -eq "Time_Zone" }
    $tz | Should -Not -BeNullOrEmpty
    $tz.value | Should -Be "UTC"
    $WorkbookText | Should -Match 'datetime_utc_to_local\(TimeGenerated, \\"\{Time_Zone\}\\"\)'
  }

  It "has the six tabs" {
    $tabs = $Workbook.items | Where-Object { $_.type -eq 11 } | Select-Object -First 1
    @($tabs.content.links).Count | Should -Be 6
  }

  It "contains no real subscription, workspace or tenant identifiers" {
    $WorkbookText | Should -Not -Match 'alz-'
    $WorkbookText | Should -Not -Match '\.onmicrosoft\.com'
    $WorkbookText | Should -Not -Match '@[a-z0-9-]+\.gov'
  }

  It "ships with a valid ARM deployment template" {
    $template = Get-Content -Path (Join-Path $RepoRoot "workbooks/workbook.template.json") -Raw | ConvertFrom-Json
    $template.resources[0].type | Should -Be "Microsoft.Insights/workbooks"
    $template.parameters.workbookContent | Should -Not -BeNullOrEmpty
  }
}

Describe "Repository hygiene" {
  It "ignores generated plan and output files" {
    $gitignore = Get-Content -Path (Join-Path $RepoRoot ".gitignore") -Raw
    $gitignore | Should -Match 'KvInventory/'
    $gitignore | Should -Match 'KvMigration/'
    $gitignore | Should -Match 'KvPlan-\*\.csv'
  }

  It "carries a licence" {
    Test-Path (Join-Path $RepoRoot "LICENSE") | Should -BeTrue
  }
}
