# Changelog

## 1.0.0

Initial public release.

- `Export-KvAccessPolicyInventory.ps1`: tenant-wide access policy and role assignment inventory with Graph identity resolution, legacy `all` expansion, live-role least-privilege suggestion and 90-day usage enrichment. Emits the optional `TargetGroupDescription` and `TargetScope` plan columns as empty columns so the consolidation spreadsheet has them ready.
- `Invoke-KvRbacMigration.ps1`: Plan, Groups, Assign, Verify, Flip and Rollback actions driven by the plan CSV, with wave and vault filters, vault or resource group scope, `-WhatIf` on every state change and a `-DefaultGroupDescription` parameter.
- `KeyVault-Audit.workbook.json`: six-tab Azure Monitor workbook over `AzureDiagnostics` with an RBAC Migration tab; time zone for the off-hours analysis is a workbook parameter (`Time_Zone`, default UTC).
- `Deploy-KeyVaultAuditWorkbook.ps1` and `workbook.template.json` for idempotent workbook deployment.
- Azure DevOps pipeline and GitHub Actions workflow with approval-gated state changes, plus a CI workflow running PSScriptAnalyzer and Pester.
- Runbook, plan CSV reference, group naming convention, permissions, change record template, rollback and pipeline docs.
