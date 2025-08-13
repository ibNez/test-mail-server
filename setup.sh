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


# Wait for mailserver container to be running
MAX_WAIT=180
WAITED=0
echo "Waiting for mailserver container to be running (up to $MAX_WAIT seconds)..."
while [ $WAITED -lt $MAX_WAIT ]; do
    if docker ps | grep mailserver | awk '{print $NF}' | head -n1; then
        echo "Mailserver container is running after $WAITED seconds."
        break
    fi
    if [ $((WAITED % 10)) -eq 0 ]; then
        echo "...still waiting for container ($WAITED seconds elapsed)"
    fi
    sleep 2
    WAITED=$((WAITED+2))
done
if ! docker ps | grep mailserver | awk '{print $NF}' | head -n1; then
    echo "Mailserver container did not start after $MAX_WAIT seconds. Skipping user creation."
    exit 1
fi

# Add default user
echo "Creating default mail user: postmaster@local"
docker exec -i mailserver setup email add postmaster@local password123
echo "Default mail user created."
# Check if user exists
if docker exec -i mailserver setup email list | grep 'postmaster@local'; then
    echo "Verified: postmaster@local exists."
else
    echo "Warning: postmaster@local was not found after creation!"
fi

echo "Setup complete!"
