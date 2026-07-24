param(
  [string]$ProjectId = "sports-firebase-6a885",
  [string]$Region = "us-central1",
  [string]$ArtifactRepo = "avrc",
  [string]$Tag = "latest",
  [string]$ForgejoBaseUrl = "",
  [string]$ForgejoToken = "",
  [string]$ForgejoRepo = ""
)

$ErrorActionPreference = "Stop"

function Invoke-Step([string]$Message, [scriptblock]$Action) {
  Write-Host "`n==> $Message" -ForegroundColor Cyan
  & $Action
}

function Get-ServiceUrl([string]$ServiceName) {
  gcloud run services describe $ServiceName `
    --project $ProjectId `
    --region $Region `
    --format "value(status.url)"
}

Invoke-Step "Setting gcloud project and region" {
  gcloud config set project $ProjectId | Out-Null
  gcloud config set run/region $Region | Out-Null
}

Invoke-Step "Enabling required APIs" {
  gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com --project $ProjectId
}

Invoke-Step "Ensuring Artifact Registry repository exists" {
  $exists = gcloud artifacts repositories list --project $ProjectId --location $Region --format "value(name)" | Select-String "/$ArtifactRepo$"
  if (-not $exists) {
    gcloud artifacts repositories create $ArtifactRepo `
      --project $ProjectId `
      --location $Region `
      --repository-format docker `
      --description "AVRC Cloud Run images"
  }
}

$baseImage = "$Region-docker.pkg.dev/$ProjectId/$ArtifactRepo"

$images = @{
  "avrc-orchestrator" = "$baseImage/avrc-orchestrator:$Tag"
  "mock-api-service" = "$baseImage/mock-api-service:$Tag"
  "git-ops-tool" = "$baseImage/git-ops-tool:$Tag"
  "trivy-scan-tool" = "$baseImage/trivy-scan-tool:$Tag"
  "renovate-fix-tool" = "$baseImage/renovate-fix-tool:$Tag"
  "semgrep-scan-tool" = "$baseImage/semgrep-scan-tool:$Tag"
  "osv-lookup-tool" = "$baseImage/osv-lookup-tool:$Tag"
}

Invoke-Step "Building and pushing container images" {
  gcloud builds submit . --project $ProjectId --tag $images["avrc-orchestrator"]
  gcloud builds submit tools/mock_api_service --project $ProjectId --tag $images["mock-api-service"]
  gcloud builds submit tools/git_ops_service --project $ProjectId --tag $images["git-ops-tool"]
  gcloud builds submit tools/trivy_service --project $ProjectId --tag $images["trivy-scan-tool"]
  gcloud builds submit tools/renovate_service --project $ProjectId --tag $images["renovate-fix-tool"]
  gcloud builds submit tools/semgrep_service --project $ProjectId --tag $images["semgrep-scan-tool"]
  gcloud builds submit tools/osv_service --project $ProjectId --tag $images["osv-lookup-tool"]
}

$mockTools = @(
  "defectdojo-api-tool:defectdojo_api_tool",
  "pipeline-lint-tool:pipeline_lint_tool",
  "container-scan-tool:container_scan_tool",
  "dependency-patch-tool:dependency_patch_tool",
  "os-pkg-upgrade-tool:os_pkg_upgrade_tool",
  "dynamic-software-scan-tool:dynamic_software_scan_tool",
  "remediation-decision-tool:remediation_decision_tool",
  "audit-logger-tool:audit_logger_tool",
  "cve-lookup-tool:cve_lookup_tool",
  "verification-scan-tool:verification_scan_tool",
  "notification-tool:notification_tool",
  "report-generator-tool:report_generator_tool",
  "copacetic-patch-tool:copacetic_patch_tool",
  "kubescape-scan-tool:kubescape_scan_tool",
  "wazuh-vulnerability-tool:wazuh_vulnerability_tool",
  "greenbone-scan-tool:greenbone_scan_tool",
  "zap-dast-tool:zap_dast_tool",
  "openrewrite-remediation-tool:openrewrite_remediation_tool",
  "nvd-lookup-tool:nvd_lookup_tool"
)

Invoke-Step "Deploying mock API services (unauthenticated, max instances = 1)" {
  foreach ($entry in $mockTools) {
    $parts = $entry.Split(":")
    $serviceName = $parts[0]
    $toolName = $parts[1]

    gcloud run deploy $serviceName `
      --project $ProjectId `
      --region $Region `
      --image $images["mock-api-service"] `
      --platform managed `
      --allow-unauthenticated `
      --max-instances 1 `
      --port 8080 `
      --set-env-vars "TOOL_NAME=$toolName"
  }
}

Invoke-Step "Deploying dedicated tool services (unauthenticated, max instances = 1)" {
  $gitOpsEnv = @("GIT_PROVIDER=forgejo")
  if ($ForgejoBaseUrl) { $gitOpsEnv += "FORGEJO_BASE_URL=$ForgejoBaseUrl" }
  if ($ForgejoToken) { $gitOpsEnv += "FORGEJO_TOKEN=$ForgejoToken" }
  if ($ForgejoRepo) { $gitOpsEnv += "FORGEJO_REPO=$ForgejoRepo" }

  gcloud run deploy git-ops-tool `
    --project $ProjectId `
    --region $Region `
    --image $images["git-ops-tool"] `
    --platform managed `
    --allow-unauthenticated `
    --max-instances 1 `
    --port 8080 `
    --set-env-vars ($gitOpsEnv -join ",")

  gcloud run deploy trivy-scan-tool `
    --project $ProjectId `
    --region $Region `
    --image $images["trivy-scan-tool"] `
    --platform managed `
    --allow-unauthenticated `
    --max-instances 1 `
    --port 8080 `
    --set-env-vars "^,^TRIVY_CACHE_DIR=/tmp/trivy-cache,TRIVY_TIMEOUT_SECONDS=300,TRIVY_SEVERITY=LOW,MEDIUM,HIGH,CRITICAL"

  gcloud run deploy renovate-fix-tool `
    --project $ProjectId `
    --region $Region `
    --image $images["renovate-fix-tool"] `
    --platform managed `
    --allow-unauthenticated `
    --max-instances 1 `
    --port 8080 `
    --set-env-vars "RENOVATE_PLATFORM=forgejo,RENOVATE_DRY_RUN=full,RENOVATE_TIMEOUT_MS=300000"

  gcloud run deploy semgrep-scan-tool `
    --project $ProjectId `
    --region $Region `
    --image $images["semgrep-scan-tool"] `
    --platform managed `
    --allow-unauthenticated `
    --max-instances 1 `
    --port 8080 `
    --set-env-vars "SEMGREP_CONFIG=p/default,SEMGREP_TIMEOUT_SECONDS=300"

  gcloud run deploy osv-lookup-tool `
    --project $ProjectId `
    --region $Region `
    --image $images["osv-lookup-tool"] `
    --platform managed `
    --allow-unauthenticated `
    --max-instances 1 `
    --port 8080 `
    --set-env-vars "OSV_API_BASE=https://api.osv.dev,OSV_TIMEOUT_MS=30000"
}

Invoke-Step "Collecting deployed tool URLs" {
  $urls = @{
    "TOOL_BASEURL_GIT_OPS_TOOL" = Get-ServiceUrl "git-ops-tool"
    "TOOL_BASEURL_TRIVY_SCAN_TOOL" = Get-ServiceUrl "trivy-scan-tool"
    "TOOL_BASEURL_RENOVATE_FIX_TOOL" = Get-ServiceUrl "renovate-fix-tool"
    "TOOL_BASEURL_SEMGREP_SCAN_TOOL" = Get-ServiceUrl "semgrep-scan-tool"
    "TOOL_BASEURL_OSV_LOOKUP_TOOL" = Get-ServiceUrl "osv-lookup-tool"
  }

  $envPairs = $urls.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }

  Invoke-Step "Deploying orchestrator (unauthenticated, max instances = 1)" {
    gcloud run deploy avrc-orchestrator `
      --project $ProjectId `
      --region $Region `
      --image $images["avrc-orchestrator"] `
      --platform managed `
      --allow-unauthenticated `
      --max-instances 1 `
      --port 3000 `
      --set-env-vars ((@("NODE_ENV=production") + $envPairs) -join ",")
  }

  Write-Host "`n=== Cloud Run URLs ===" -ForegroundColor Green
  Write-Host "avrc-orchestrator: $(Get-ServiceUrl 'avrc-orchestrator')"
  foreach ($entry in $mockTools) {
    $serviceName = $entry.Split(":")[0]
    Write-Host "${serviceName}: $(Get-ServiceUrl $serviceName)"
  }
  Write-Host "git-ops-tool: $($urls['TOOL_BASEURL_GIT_OPS_TOOL'])"
  Write-Host "trivy-scan-tool: $($urls['TOOL_BASEURL_TRIVY_SCAN_TOOL'])"
  Write-Host "renovate-fix-tool: $($urls['TOOL_BASEURL_RENOVATE_FIX_TOOL'])"
  Write-Host "semgrep-scan-tool: $($urls['TOOL_BASEURL_SEMGREP_SCAN_TOOL'])"
  Write-Host "osv-lookup-tool: $($urls['TOOL_BASEURL_OSV_LOOKUP_TOOL'])"
}

Write-Host "`nDeployment completed." -ForegroundColor Green
