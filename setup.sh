#!/bin/zsh
# Setup script for test_mail_server
set -e

# Activate virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate

# Check if .venv is activated, try to activate if not, and exit if still not active
if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$(pwd)/.venv" ]; then
    echo "Activating .venv..."
    source .venv/bin/activate
    # Check again after sourcing
    if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$(pwd)/.venv" ]; then
        echo "Failed to activate .venv. Exiting."
        exit 1
    fi
fi

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
docker compose up -d
cd ..

sleep 5

# Check if mailserver container is running, then add default user
if docker ps --format '{{.Names}}' | grep -q '^mailserver$'; then
    echo "Creating default mail user: postmaster@local"
    docker exec -i mailserver setup email add postmaster@local password123
    echo "Default mail user created."
else
    echo "Mailserver container is not running. Skipping user creation."
fi

echo "Setup complete!"
