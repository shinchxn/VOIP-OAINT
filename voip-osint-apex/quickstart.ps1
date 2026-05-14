<#
.SYNOPSIS
Quick-start script for VoIP OSINT APEX v3.0 (Docker) on Windows.

.DESCRIPTION
This script checks prerequisites (Docker, API keys), builds the image,
and drops you into a ready-to-use APEX CLI container.
#>

$ErrorActionPreference = "Stop"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " VoIP OSINT APEX v3.0 — Docker Quickstart (Windows)" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# 1. Check if Docker is running
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Docker is not running" }
} catch {
    Write-Host "[ERROR] Docker Desktop is not running or not installed." -ForegroundColor Red
    Write-Host "Please install/start Docker Desktop and try again." -ForegroundColor Yellow
    exit 1
}

# 2. Check for .env file
if (-not (Test-Path ".env")) {
    Write-Host "[WARN] .env file not found. Creating from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env. Please open it and add your API keys (IPQualityScore, etc.) before running full scans." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
}

# 3. Create necessary directories
$dirs = @("outputs", "outputs\reports", "outputs\logs", "outputs\pcaps", "pcap_drop")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }
}

# 4. Build and start services
Write-Host "`n[1/2] Building APEX Docker Image (this might take a minute on first run)..." -ForegroundColor Cyan
docker compose build apex

Write-Host "`n[2/2] Starting Redis cache server..." -ForegroundColor Cyan
docker compose up -d redis

Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host " READY! Drop PCAPs into 'pcap_drop' or use the CLI." -ForegroundColor Green
Write-Host "=======================================================" -ForegroundColor Green

Write-Host "`nUseful commands to try:" -ForegroundColor Yellow
Write-Host "  docker compose run --rm apex number +14155552671"
Write-Host "  docker compose run --rm apex ip 8.8.8.8 --ports"
Write-Host "  docker compose run --rm apex scan 192.168.1.0/24"
Write-Host "  docker compose run --rm apex --help"

Write-Host "`nStarting APEX help menu..." -ForegroundColor Cyan
docker compose run --rm apex --help
