param(
  [Parameter(Mandatory = $true)]
  [string]$ProjectId,

  [Parameter(Mandatory = $true)]
  [string]$ClusterName,

  [string]$ClusterLocation,
  [string]$Region = "asia-east1",
  [string]$Repository = "avrc",
  [string]$Namespace = "avrc",
  [string]$Tag = "latest",

  [switch]$CreateArtifactRepository,
  [switch]$ConfigureDockerAuth,
  [switch]$SkipBuild,
  [switch]$SkipPush,
  [switch]$Apply
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Resolve-Path (Join-Path $ScriptDir "..")
$GeneratedDir = Join-Path $RootDir ".gke"
$ManifestPath = Join-Path $GeneratedDir "avrc-stack.yaml"
$GkeConfigPath = Join-Path $GeneratedDir "config.gke.json"

$Registry = "$Region-docker.pkg.dev"
$ImagePrefix = "$Registry/$ProjectId/$Repository"
$OrchestratorImage = "$ImagePrefix/avrc-orchestrator:$Tag"
$ToolImage = "$ImagePrefix/avrc-tool-api:$Tag"

$ToolServices = @(
  @{ Service = "defectdojo-api-tool"; ToolName = "defectdojo_api_tool"; HostPort = 4010 },
  @{ Service = "pipeline-lint-tool"; ToolName = "pipeline_lint_tool"; HostPort = 4020 },
  @{ Service = "container-scan-tool"; ToolName = "container_scan_tool"; HostPort = 4030 },
  @{ Service = "dependency-patch-tool"; ToolName = "dependency_patch_tool"; HostPort = 4040 },
  @{ Service = "os-pkg-upgrade-tool"; ToolName = "os_pkg_upgrade_tool"; HostPort = 4050 },
  @{ Service = "dynamic-software-scan-tool"; ToolName = "dynamic_software_scan_tool"; HostPort = 4060 },
  @{ Service = "remediation-decision-tool"; ToolName = "remediation_decision_tool"; HostPort = 4070 },
  @{ Service = "audit-logger-tool"; ToolName = "audit_logger_tool"; HostPort = 4080 },
  @{ Service = "cve-lookup-tool"; ToolName = "cve_lookup_tool"; HostPort = 4090 },
  @{ Service = "git-ops-tool"; ToolName = "git_ops_tool"; HostPort = 4100 },
  @{ Service = "verification-scan-tool"; ToolName = "verification_scan_tool"; HostPort = 4110 },
  @{ Service = "notification-tool"; ToolName = "notification_tool"; HostPort = 4120 },
  @{ Service = "report-generator-tool"; ToolName = "report_generator_tool"; HostPort = 4130 },
  @{ Service = "trivy-scan-tool"; ToolName = "trivy_scan_tool"; HostPort = 4140 },
  @{ Service = "renovate-fix-tool"; ToolName = "renovate_fix_tool"; HostPort = 4150 },
  @{ Service = "copacetic-patch-tool"; ToolName = "copacetic_patch_tool"; HostPort = 4160 },
  @{ Service = "kubescape-scan-tool"; ToolName = "kubescape_scan_tool"; HostPort = 4170 },
  @{ Service = "wazuh-vulnerability-tool"; ToolName = "wazuh_vulnerability_tool"; HostPort = 4180 },
  @{ Service = "greenbone-scan-tool"; ToolName = "greenbone_scan_tool"; HostPort = 4190 },
  @{ Service = "zap-dast-tool"; ToolName = "zap_dast_tool"; HostPort = 4200 },
  @{ Service = "semgrep-scan-tool"; ToolName = "semgrep_scan_tool"; HostPort = 4210 },
  @{ Service = "openrewrite-remediation-tool"; ToolName = "openrewrite_remediation_tool"; HostPort = 4220 },
  @{ Service = "osv-lookup-tool"; ToolName = "osv_lookup_tool"; HostPort = 4230 },
  @{ Service = "nvd-lookup-tool"; ToolName = "nvd_lookup_tool"; HostPort = 4240 }
)

function Require-Command {
  param([string]$Name)

  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "$Name was not found on PATH."
  }
}

function Write-Step {
  param([string]$Message)
  Write-Host ""
  Write-Host "==> $Message" -ForegroundColor Cyan
}

Require-Command gcloud
Require-Command kubectl
Require-Command docker

New-Item -ItemType Directory -Force -Path $GeneratedDir | Out-Null

Write-Step "Preparing GKE runtime config"
$ConfigJson = Get-Content (Join-Path $RootDir "config/config.json") -Raw
Set-Content -Path $GkeConfigPath -Value $ConfigJson -Encoding utf8

if ($CreateArtifactRepository) {
  Write-Step "Creating Artifact Registry repository if missing"
  gcloud artifacts repositories describe $Repository --project $ProjectId --location $Region 1>$null 2>$null
  if ($LASTEXITCODE -ne 0) {
    gcloud artifacts repositories create $Repository `
      --project $ProjectId `
      --location $Region `
      --repository-format docker `
      --description "AVRC container images"
  }
}

if ($ConfigureDockerAuth) {
  Write-Step "Configuring Docker auth for $Registry"
  gcloud auth configure-docker $Registry --quiet
}

if (-not $SkipBuild) {
  Write-Step "Building orchestrator image"
  docker build -t $OrchestratorImage -f (Join-Path $RootDir "Dockerfile") $RootDir

  Write-Step "Building reusable tool API image"
  docker build -t $ToolImage (Join-Path $RootDir "tools/mock_api_service")
}

if (-not $SkipPush) {
  Write-Step "Pushing images to Artifact Registry"
  docker push $OrchestratorImage
  docker push $ToolImage
}

if ($ClusterLocation) {
  Write-Step "Fetching GKE credentials"
  $LocationFlag = if ($ClusterLocation -match "-[a-z]$") { "--zone" } else { "--region" }
  gcloud container clusters get-credentials $ClusterName `
    --project $ProjectId `
    $LocationFlag $ClusterLocation
}

Write-Step "Generating Kubernetes manifest"

$Manifest = @"
apiVersion: v1
kind: Namespace
metadata:
  name: $Namespace
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: avrc-config
  namespace: $Namespace
data:
  config.json: |
$((Get-Content $GkeConfigPath) | ForEach-Object { "    $_" } | Out-String)
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: avrc-output
  namespace: $Namespace
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 2Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: avrc-orchestrator
  namespace: $Namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: avrc-orchestrator
  template:
    metadata:
      labels:
        app: avrc-orchestrator
    spec:
      containers:
        - name: avrc-orchestrator
          image: $OrchestratorImage
          imagePullPolicy: Always
          env:
            - name: NODE_ENV
              value: production
            - name: PORT
              value: "3000"
          ports:
            - containerPort: 3000
          volumeMounts:
            - name: avrc-config
              mountPath: /app/config/config.json
              subPath: config.json
            - name: avrc-output
              mountPath: /app/output
          readinessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 10
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 30
            periodSeconds: 30
      volumes:
        - name: avrc-config
          configMap:
            name: avrc-config
        - name: avrc-output
          persistentVolumeClaim:
            claimName: avrc-output
---
apiVersion: v1
kind: Service
metadata:
  name: avrc-orchestrator
  namespace: $Namespace
spec:
  type: LoadBalancer
  selector:
    app: avrc-orchestrator
  ports:
    - name: http
      port: 3000
      targetPort: 3000
"@

foreach ($Tool in $ToolServices) {
  $ServiceName = $Tool.Service
  $ToolName = $Tool.ToolName

  $Manifest += @"

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $ServiceName
  namespace: $Namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: $ServiceName
  template:
    metadata:
      labels:
        app: $ServiceName
    spec:
      containers:
        - name: $ServiceName
          image: $ToolImage
          imagePullPolicy: Always
          env:
            - name: TOOL_NAME
              value: $ToolName
            - name: PORT
              value: "8080"
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: $ServiceName
  namespace: $Namespace
spec:
  type: ClusterIP
  selector:
    app: $ServiceName
  ports:
    - name: http
      port: 8080
      targetPort: 8080
"@
}

Set-Content -Path $ManifestPath -Value $Manifest -Encoding utf8

Write-Host ""
Write-Host "Generated manifest: $ManifestPath" -ForegroundColor Green
Write-Host "Orchestrator image: $OrchestratorImage"
Write-Host "Tool API image:     $ToolImage"

if ($Apply) {
  Write-Step "Applying manifest to GKE"
  kubectl apply -f $ManifestPath

  Write-Step "Current service status"
  kubectl get svc -n $Namespace
} else {
  Write-Host ""
  Write-Host "Dry run complete. Apply with:"
  Write-Host "  .\scripts\deploy-gke.ps1 -ProjectId $ProjectId -ClusterName $ClusterName -ClusterLocation <region-or-zone> -Apply"
}
