#!/bin/bash

# Vibe Probe Setup Script

set -e

echo "🔍 Vibe Probe - Setup Script"
echo "=============================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python $python_version found"
echo ""

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt
echo "✓ Dependencies installed"
echo ""

# Setup configuration
echo "Setting up configuration files..."

if [ ! -f .env ]; then
    cp .env.example .env
    echo "✓ Created .env file"
    echo "  → Edit .env to add your API keys"
else
    echo "⚠ .env already exists (skipping)"
fi

if [ ! -f config.yaml ]; then
    cp config.example.yaml config.yaml
    echo "✓ Created config.yaml file"
else
    echo "⚠ config.yaml already exists (skipping)"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your API keys (optional)"
echo "  2. Run your first scan: python3 vibe-probe.py example.com"
echo "  3. Check QUICKSTART.md for more examples"
echo ""
