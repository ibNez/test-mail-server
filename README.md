# test_mail_server / IMAP Email Seeder

Local Docker mail server plus an advanced IMAP seeder that populates realistic user personalities, multi‑participant threads, outside inbound mail, and spam/phish style messages using an Ollama LLM model.

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

- `docker-imap/` – Docker Compose setup and certificate scripts
- `email_seeder.py` – Seeder script (also installed as `email-seeder` console script)
- `seed_users.json` – Persisted generated user inventory (names, personalities, passwords)
- `setup.sh` / `uninstall.sh` – Helper scripts
- `pyproject.toml` – Packaging / dependencies

## Seeder Features

- LLM (Ollama) generated user full names & vivid personality sentence
- Email addresses formed as `firstname.lastname@<domain>`
- Conversation threads with proper Message-ID, In-Reply-To, References headers
- Outside inbound personal emails from a configurable external domain
- Spam messages with dynamic, model-generated clickbait subjects & bodies
- Dynamic spammy domain roots (no fixed list)
- Per-user metrics: total messages, added this run, spam estimate
- Runtime duration printed on completion

## Quick Start (Seeding)

Assuming Docker mailserver already running via `setup.sh`:

```sh
source .venv/bin/activate
email-seeder --num-users 5 --domain local
```

Or directly:

```sh
python email_seeder.py --num-users 5 --thread-count 4 --thread-length-min 2 --thread-length-max 5 --outside-email-count 50
```

Verification-only mode (no new messages):

```sh
python email_seeder.py --verify-only
```

## Key Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| IMAP_HOST | localhost | IMAP server host |
| IMAP_PORT | 143 | IMAP server port |
| IMAP_USE_SSL | 0 | Use SSL (1) or STARTTLS/clear (0) |
| INTERNAL_DOMAIN | local | Domain for generated internal users (env only; not a CLI flag) |
| THREAD_COUNT | 5 | Number of conversation threads (CLI: --thread-count) |
| THREAD_LENGTH_MIN | 3 | Min messages per thread (CLI: --thread-length-min) |
| THREAD_LENGTH_MAX | 6 | Max messages per thread (CLI: --thread-length-max) |
| OUTSIDE_EMAIL_COUNT | 100 | Outside one‑off inbound messages (CLI: --outside-email-count) |
| NUM_USERS | 10 | Number of internal accounts to target |
| THREAD_COUNT | 5 | Number of conversation threads |
| THREAD_LENGTH_MIN | 3 | Min messages per thread |
| THREAD_LENGTH_MAX | 6 | Max messages per thread |
| OUTSIDE_EMAIL_COUNT | 100 | Outside one‑off inbound messages |
| OUTSIDE_DOMAIN | external.test | Domain for outside senders |
| SPAM_EMAIL_COUNT | 5 | Number of spam emails |
| SPAM_DOMAIN_TLD | test | TLD used for spam root domains |
| OLLAMA_HOST | 127.0.0.1 | Ollama host (IP only) |
| OLLAMA_PORT | 11434 | Ollama port |
| OLLAMA_MODEL | wizard-vicuna-uncensored:latest | Model name for generation |
| USERS_JSON_PATH | seed_users.json | Inventory JSON path |
| VERIFY_ONLY | 0 | Skip seeding if set to 1 |
| POST_VERIFY | 1 | Run summary verification after seeding |
| SEEDER_SLEEP | 0.05 | Sleep between thread seeds (seconds) |

All variables can be overridden inline: `NUM_USERS=3 SPAM_EMAIL_COUNT=10 python email_seeder.py`.

## Ollama Notes

The seeder requires an active Ollama instance providing the configured model. Example to run locally:

```sh
ollama pull wizard-vicuna-uncensored:latest
ollama serve
```

If running remotely expose the port and set `OLLAMA_HOST` / `OLLAMA_PORT` accordingly.

## Output Summary

At completion (or in verify-only mode) a table like:

```
User                           Total  Added  SpamEst
alice.smith@local                 57     12        3
...
```

`Added` counts messages appended during the current run; `SpamEst` is a heuristic count from captured spam subjects + keyword scan.

### CLI Flag Summary

Essential:
- `--num-users` Number of internal accounts
- `--thread-count` Conversation threads
- `--thread-length-min` / `--thread-length-max` Thread length bounds
- `--outside-email-count` Number of outside inbound emails
- `--ollama-host` / `--ollama-port` Ollama endpoint
- `--verify-only` Skip seeding, just summarize

## Packaging / Installation

Editable install for development:

```sh
pip install -e .
```

This provides the `email-seeder` console entry point.

## Development

Type checking / lint (optional tools declared in `pyproject.toml` under extras if added):

```sh
pip install mypy ruff
mypy email_seeder.py
ruff check .
```

## License

MIT License. See `LICENSE`.

## Requirements
- Python 3.8+
- Docker & Docker Compose

## Notes
- Certificates are generated in `docker-imap/` as `mail.crt.pem` and `mail.key.pem`.
- Mail server started in detached mode via Docker Compose.
- Passwords are random alphanumeric; persisted in `seed_users.json` for reuse.
