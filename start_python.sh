#!/bin/bash

# ===============================================
# GitHub OAuth Dashboard - Python Start Script
# ===============================================
# Quick start script for the Python/FastAPI server

echo "🚀 Starting GitHub OAuth Dashboard (Python/FastAPI)"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Run ./setup_python.sh first to set up the project."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found!"
    echo "Run ./setup_python.sh first or create .env manually."
    exit 1
fi

# Start the server
echo "✅ Starting server on http://localhost:8000"
echo ""
python main.py
