@{
  # Rules are applied to scripts/ and workbooks/ by .github/workflows/ci.yml.
  Severity     = @('Error', 'Warning')

  ExcludeRules = @(
    # Write-Host is deliberate: the scripts are operator tools and pipeline tasks, and Write-Log wraps it.
    'PSAvoidUsingWriteHost',
    # The scripts are Windows PowerShell 5.1 compatible by design and use New-Object where [type]::new() would not be.
    'PSUseShouldProcessForStateChangingFunctions',
    # Plural nouns such as Get-PlannedAssignments are intentional in these single-file scripts.
    'PSUseSingularNouns'
  )

  Rules        = @{
    PSUseCompatibleSyntax = @{
      Enable         = $true
      TargetVersions = @('5.1', '7.0')
    }
    PSPlaceOpenBrace      = @{
      Enable             = $true
      OnSameLine         = $true
      NewLineAfter       = $true
      IgnoreOneLineBlock = $true
    }
    PSUseConsistentIndentation = @{
      Enable              = $true
      IndentationSize     = 2
      PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
      Kind                = 'space'
    }
  }
}
