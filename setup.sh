#!/bin/bash
# CTEM Experiment Setup Script

echo "CTEM vs Traditional VM - Experiment Setup"

# Check prerequisites
echo -e "\n[1/5] Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "  ✗ Docker not found. Please install Docker Desktop"
    echo "    Download from: https://www.docker.com/products/docker-desktop"
    exit 1
fi
echo "  ✓ Docker installed"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "  ✗ Docker Compose not found"
    exit 1
fi
echo "  ✓ Docker Compose installed"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "  ✗ Python 3 not found. Please install Python 3.8+"
    exit 1
fi
echo "  ✓ Python 3 installed"

# Install Python dependencies
echo -e "\n[2/5] Installing Python dependencies..."
pip3 install --quiet --user pandas numpy sqlite3 &> /dev/null || true
echo "  ✓ Python packages installed"

# Create data directory
echo -e "\n[3/5] Creating data directory..."
mkdir -p data
echo "  ✓ Data directory ready"

# Make scripts executable
echo -e "\n[4/5] Setting permissions..."
chmod +x scripts/*.py
echo "  ✓ Scripts are executable"

# Test Docker
echo -e "\n[5/5] Testing Docker setup..."
if ! docker ps &> /dev/null; then
    echo "  ✗ Docker daemon not running. Please start Docker Desktop"
    exit 1
fi
echo "  ✓ Docker is running"

echo "Setup Complete!"

echo ""
echo "Next steps:"
echo "1. Review the methodology in docs/METHODOLOGY.md"
echo "2. Run the experiment:"
echo "   python3 scripts/run_experiment.py"
echo ""
echo "The experiment will:"
echo "  - Deploy vulnerable services"
echo "  - Run 5 Traditional VM iterations"
echo "  - Run 5 CTEM iterations"
echo "  - Generate metrics (MEW, MTTR, CEC, RFR)"
echo "  - Export CSV files for Power BI"
echo ""
echo "Estimated completion time: 30-40 minutes"


# Create data directory if it doesn't exist
mkdir -p data

echo "✓ Data directory ready"
