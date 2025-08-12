# test_mail_server

A developer friendly mail server manager using docker (mailserver). Fake email generation for developer testing of email systems. Fake user and email threading features as well as spam generation.

## Setup Instructions

1. Clone the repository and navigate to the project directory.
2. Run the setup script:

```sh
chmod +x setup.sh
./setup.sh
```

This will:
- Create and activate a Python virtual environment (`.venv`)
- Install Python dependencies from `pyproject.toml`
- Generate SSL certificates if not present
- Launch the Docker container for the mail server

## Project Structure

- `docker-imap/` - Docker Compose setup and certificate scripts
- `email_seeder.py` - (Your email seeding script)
- `setup.sh` - Project setup script
- `pyproject.toml` - Python project dependencies

## Requirements
- Python 3.8+
- Docker & Docker Compose

## Notes
- Certificates are generated in `docker-imap/` as `mail.crt.pem` and `mail.key.pem`.
- The mail server is started in detached mode using Docker Compose.
