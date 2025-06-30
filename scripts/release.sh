#!/bin/bash
set -e

echo "🚀 Building and releasing syft-perm"

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: pyproject.toml not found. Make sure you're in the project root."
    exit 1
fi

# Check if we're in a git repository and on main branch
if [ -d ".git" ]; then
    BRANCH=$(git branch --show-current)
    if [ "$BRANCH" != "main" ]; then
        echo "⚠️  Warning: Not on main branch (currently on $BRANCH)"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check for uncommitted changes
    if [ -n "$(git status --porcelain)" ]; then
        echo "⚠️  Warning: You have uncommitted changes"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf dist/
rm -rf build/
rm -rf *.egg-info/

# Run tests
echo "🧪 Running tests..."
if command -v pytest &> /dev/null; then
    python -m pytest tests/ -v
else
    echo "⚠️  pytest not found, skipping tests"
fi

# Build the package
echo "📦 Building package..."
python -m build

# Check the built package
echo "🔍 Checking package..."
python -m twine check dist/*

# List what we built
echo "📋 Built files:"
ls -la dist/

# Ask for confirmation before uploading
echo ""
echo "🚀 Ready to upload to PyPI!"
echo "Files to upload:"
ls dist/

read -p "Upload to PyPI? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📤 Uploading to PyPI..."
    python -m twine upload dist/*
    echo "✅ Package uploaded successfully!"
    
    # Get the version for the success message
    VERSION=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])" 2>/dev/null || echo "latest")
    echo "🎉 syft-perm $VERSION is now available on PyPI!"
    echo "   Install with: pip install syft-perm"
else
    echo "❌ Upload cancelled"
    echo "💡 To upload later, run: python -m twine upload dist/*"
fi 