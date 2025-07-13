#!/bin/bash
set -e

# SyftBox app runner for syft-perm
# This script is executed by SyftBox when the app is deployed

echo "Starting syft-perm SyftBox app..."

# Get assigned port from SyftBox or use default
SYFTBOX_ASSIGNED_PORT=${SYFTBOX_ASSIGNED_PORT:-8080}
echo "Using port: $SYFTBOX_ASSIGNED_PORT"

# Environment setup for clean installation
export ZSH_DISABLE_COMPFIX=true
export NONINTERACTIVE=1

# Create fresh virtual environment with UV
echo "Setting up Python environment..."
rm -rf .venv
uv venv --python 3.12
export VIRTUAL_ENV="$(pwd)/.venv"
export PATH="$VIRTUAL_ENV/bin:$PATH"

# Install dependencies
echo "Installing dependencies..."
uv sync

# Launch the syft-perm app server
echo "Launching syft-perm server on port $SYFTBOX_ASSIGNED_PORT..."
export SYFTBOX_PORT=$SYFTBOX_ASSIGNED_PORT
uv run python -m syft_perm.syftbox_app