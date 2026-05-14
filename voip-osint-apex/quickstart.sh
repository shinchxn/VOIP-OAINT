#!/usr/bin/env bash
# Quick-start script for VoIP OSINT APEX v3.0 (Docker) on Linux/macOS.

set -e

echo -e "\033[1;36m=======================================================\033[0m"
echo -e "\033[1;36m VoIP OSINT APEX v3.0 — Docker Quickstart (Linux/Mac)\033[0m"
echo -e "\033[1;36m=======================================================\033[0m"

# 1. Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "\033[1;31m[ERROR] Docker is not running or not installed.\033[0m"
    echo "Please install/start Docker and try again."
    exit 1
fi

# 2. Check for .env file
if [ ! -f ".env" ]; then
    echo -e "\033[1;33m[WARN] .env file not found. Creating from .env.example...\033[0m"
    cp .env.example .env
    echo "Created .env. Please open it and add your API keys before running full scans."
    sleep 2
fi

# 3. Create necessary directories
mkdir -p outputs/reports outputs/logs outputs/pcaps pcap_drop

# 4. Build and start services
echo -e "\n\033[1;36m[1/2] Building APEX Docker Image (this might take a minute on first run)...\033[0m"
docker compose build apex

echo -e "\n\033[1;36m[2/2] Starting Redis cache server...\033[0m"
docker compose up -d redis

echo -e "\n\033[1;32m=======================================================\033[0m"
echo -e "\033[1;32m READY! Drop PCAPs into 'pcap_drop' or use the CLI.\033[0m"
echo -e "\033[1;32m=======================================================\033[0m"

echo -e "\n\033[1;33mUseful commands to try:\033[0m"
echo "  docker compose run --rm apex number +14155552671"
echo "  docker compose run --rm apex ip 8.8.8.8 --ports"
echo "  docker compose run --rm apex scan 192.168.1.0/24"
echo "  docker compose run --rm apex --help"

echo -e "\n\033[1;36mStarting APEX help menu...\033[0m"
docker compose run --rm apex --help
