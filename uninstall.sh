#!/bin/zsh
# Uninstall script for test_mail_server
set -e

# Stop and remove docker containers and volumes
cd docker-imap
docker compose down --volumes

# Remove certificates
rm -f mail.crt.pem mail.key.pem

# Remove config and mail-data folders and their contents
rm -rf config mail-data
cd ..

# Remove seed_users.json if it exists in the project root
echo "Removing seed_users.json if it exists..."
rm -f seed_users.json

echo "Uninstall complete!"
