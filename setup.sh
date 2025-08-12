#!/bin/zsh
# Setup script for test_mail_server
set -e

# Activate virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate

# Install Python requirements
if [ -f "pyproject.toml" ]; then
    pip install --upgrade pip
    pip install .
else
    echo "pyproject.toml not found. Skipping pip install."
fi

# Generate certificates if not present
cd docker-imap
if [ ! -f "mail.crt.pem" ] || [ ! -f "mail.key.pem" ]; then
    echo "Generating certificates..."
    python3 create_certs.py
else
    echo "Certificates already exist."
fi
cd ..

# Launch Docker container
cd docker-imap
docker-compose up -d
cd ..

echo "Setup complete!"
