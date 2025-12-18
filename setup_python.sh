#!/bin/bash

# ===============================================
# GitHub OAuth Dashboard - Python Setup Script
# ===============================================
# Quick setup script for the Python/FastAPI version

set -e  # Exit on error

echo "=================================================="
echo "  GitHub OAuth Dashboard - Python Setup"
echo "=================================================="
echo ""

# Check Python version
echo "🔍 Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✅ Python $PYTHON_VERSION found"
echo ""

# Create virtual environment
echo "🐍 Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "ℹ️  Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate
echo "✅ Virtual environment activated"
echo ""

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1
echo "✅ pip upgraded"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt
echo "✅ Dependencies installed"
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found"
    echo "📝 Creating .env from .env.example..."
    cp .env.example .env
    
    echo ""
    echo "🔑 Generating secure SESSION_SECRET..."
    SESSION_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    
    # Update SESSION_SECRET in .env (works on both Linux and macOS)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/change-this-to-a-random-secret-string-at-least-32-chars/$SESSION_SECRET/" .env
    else
        # Linux
        sed -i "s/change-this-to-a-random-secret-string-at-least-32-chars/$SESSION_SECRET/" .env
    fi
    
    echo "✅ .env file created with secure SESSION_SECRET"
    echo ""
    echo "⚠️  IMPORTANT: You still need to configure:"
    echo "   - GITHUB_CLIENT_ID"
    echo "   - GITHUB_CLIENT_SECRET"
    echo ""
    echo "   Edit the .env file and add your GitHub OAuth credentials."
    echo "   See README_PYTHON.md for instructions."
else
    echo "✅ .env file already exists"
fi

echo ""
echo "=================================================="
echo "  ✅ Setup Complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Configure your GitHub OAuth app:"
echo "   https://github.com/settings/developers"
echo ""
echo "2. Update .env with your credentials:"
echo "   - GITHUB_CLIENT_ID"
echo "   - GITHUB_CLIENT_SECRET"
echo ""
echo "3. Run the application:"
echo "   python main.py"
echo "   # or"
echo "   uvicorn main:app --reload"
echo ""
echo "4. Visit http://localhost:8000"
echo ""
echo "=================================================="
