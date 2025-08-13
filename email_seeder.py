# --- CLI Output Styling ---
class Style:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    GREY = '\033[90m'

def cprint(msg, color: str = Style.RESET, bold: bool = False, end: str = '\n') -> None:
    style = color
    if bold:
        style += Style.BOLD
    print(f"{style}{msg}{Style.RESET}", end=end)
# MIT License
# Copyright (c) 2025 Tony Philip
# Author: Tony Philip
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Advanced IMAP seeder: populate a local docker-mailserver with synthetic mail.

Features:
    - Multiple internal user accounts (user1@local, user2@local, ...)
    - Optional auto-creation of users via `docker exec mailserver setup email add`
    - Conversation threads (alternating participants, proper Message-ID, In-Reply-To, References)
    - One‑off "outside" inbound emails from external domains
    - Deterministic + model (Ollama) generated bodies (toggle for speed)
    - Direct IMAP APPEND (no SMTP) for speed & simplicity

Environment / Config variables (defaults in code below):
    IMAP_HOST, IMAP_PORT, IMAP_USE_SSL
    INTERNAL_DOMAIN, USER_PREFIX, USER_PASSWORD, NUM_USERS
    THREAD_COUNT, THREAD_LENGTH_MIN, THREAD_LENGTH_MAX
    OUTSIDE_EMAIL_COUNT, OUTSIDE_DOMAIN
    OLLAMA_HOST (IP only), OLLAMA_PORT, OLLAMA_ADDRESS (built as http://HOST:PORT), OLLAMA_MODEL (model usage mandatory; no fallback bodies)
    MAILBOX (target mailbox for all users, default INBOX)
    DOCKER_AUTOCREATE (1 to attempt user creation via docker exec)

Usage example:
    NUM_USERS=3 THREAD_COUNT=5 OUTSIDE_EMAIL_COUNT=8 python examples/email_seeder.py

Result: Users get a mixture of threaded conversations and standalone inbound messages.
"""
import os
import sys
if not os.environ.get('VIRTUAL_ENV'):
    venv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.venv', 'bin', 'activate_this.py')
    if os.path.exists(venv_path):
        with open(venv_path) as f:
            exec(f.read(), {'__file__': venv_path})
    else:
        print("[WARN] .venv not found or not activated. source .venv/bin/activate", file=sys.stderr)
        exit(1)
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
import imaplib
import random
import time
import subprocess
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Optional
from collections import defaultdict
import json
import argparse

try:
    import requests
except ImportError as e:
    raise RuntimeError("'requests' package is required for Ollama integration. Install with: pip install requests") from e


# Global capture for spam subjects (used in verification)
SPAM_SUBJECTS_CAPTURED: List[str] = []
PER_USER_ADDED = defaultdict(int)  # messages appended this run

# Generate a unique personality description for a user using Ollama
def generate_personality(full_name: str) -> str:
    prompt = (
        f"In 1 short, vivid sentence, describe the personality and email style of a fictional person named {full_name}. "
        "Personalities should be highly varied: some happy, some sad, some angry, some sarcastic, some passionate, some blunt, some who swear, some who are pessimistic, some who are dramatic, some who are cold, some who are inappropriate, some who are G-rated, some who are not. "
        "Do not make everyone cheerful or playful. Use strong language or swearing if it fits. Do not mention this is for a test or seeding."
    )
    return ollama_generate(prompt).strip()


"""Simplified configuration: rely mostly on sane defaults & minimal flags.
Environment variables still honored for basic overrides.
"""
IMAP_HOST = os.getenv("IMAP_HOST", "localhost")
IMAP_PORT = int(os.getenv("IMAP_PORT", "143"))
IMAP_USE_SSL = bool(int(os.getenv("IMAP_USE_SSL", "0")))
MAILBOX = os.getenv("MAILBOX", "INBOX")

INTERNAL_DOMAIN = os.getenv("INTERNAL_DOMAIN", "local")
NUM_USERS = int(os.getenv("NUM_USERS", "10"))

THREAD_COUNT = int(os.getenv("THREAD_COUNT", "5"))
THREAD_LENGTH_MIN = int(os.getenv("THREAD_LENGTH_MIN", "3"))
THREAD_LENGTH_MAX = int(os.getenv("THREAD_LENGTH_MAX", "6"))

OUTSIDE_EMAIL_COUNT = int(os.getenv("OUTSIDE_EMAIL_COUNT", "100"))
OUTSIDE_DOMAIN = os.getenv("OUTSIDE_DOMAIN", "external.test")

SLEEP_BETWEEN_SECONDS = float(os.getenv("SEEDER_SLEEP", "0.05"))
BASE_TIME = datetime.now(timezone.utc)
RUN_START = time.perf_counter()

DOCKER_MAILSERVER_CONTAINER = os.getenv("DOCKER_MAILSERVER_CONTAINER", "mailserver")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "127.0.0.1")  # IP only
OLLAMA_PORT = os.getenv("OLLAMA_PORT", "11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "wizard-vicuna-uncensored:latest")
OLLAMA_ADDRESS = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"

# Spam / outside traffic config (domains always dynamically generated)
SPAM_EMAIL_COUNT = int(os.getenv("SPAM_EMAIL_COUNT", "5"))
SPAM_DOMAIN_TLD = os.getenv("SPAM_DOMAIN_TLD", "test")

# Users JSON export
USERS_JSON_PATH = os.getenv("USERS_JSON_PATH", os.path.join(os.path.dirname(__file__), "seed_users.json"))

# Verification controls
VERIFY_ONLY = bool(int(os.getenv("VERIFY_ONLY", "0")))
POST_VERIFY = bool(int(os.getenv("POST_VERIFY", "1")))

# Optional: add custom X- header to identify seeded messages
X_SEEDED_HEADER = "X-Seeded-By"
X_SEEDED_VALUE = "imap-seeder"


# Ollama LLM-based topic and spam generation
def ollama_generate_personal_topic() -> str:
    prompt = "Suggest a realistic, non-repetitive personal email topic for a conversation between friends or family. Return only the subject line."
    return ollama_generate(prompt)

def ollama_generate_spam_subject() -> str:
    prompt = "Generate a spammy, clickbait email subject line (e.g., prize, urgent, refund, security, offer). Return only the subject."
    return ollama_generate(prompt)

def ollama_generate_spam_body() -> str:
    prompt = "Write a short, plausible spam email body (2-4 lines, clickbait, urgent, or scammy, but not illegal or offensive)."
    return ollama_generate(prompt)

def ollama_generate(prompt, model=OLLAMA_MODEL):
    """Call Ollama to generate text for the given prompt (mandatory)."""
    url = f"{OLLAMA_ADDRESS}/api/generate"
    payload = {"model": model, "prompt": prompt, "stream": False}
    r = requests.post(url, json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    resp = (data.get("response") or "").strip()
    if not resp:
        raise RuntimeError("Empty response from Ollama for prompt snippet: " + repr(prompt[:80]))
    return resp

def generate_personal_email(sender: dict, recipient: dict) -> Tuple[str, str]:
    cprint("[seeder] Requesting personal email topic from LLM...", Style.CYAN)
    topic = ollama_generate_personal_topic()
    cprint(f"[seeder] Got topic: {topic}", Style.GREEN, bold=True)
    sender_name = sender.get('full_name', 'Unknown Sender')
    sender_personality = sender.get('personality', 'fun and quirky')
    recipient_name = recipient.get('full_name', 'Unknown Recipient')
    prompt = (
        f"Write a email from {sender_name} to {recipient_name} about '{topic}'. "
        f"Write the email using the sender's personality: {sender_personality}. "
        "Make sure the writing style matches the sender's personality. Keep it witty, and original. 3-20 sentences."
    )
    cprint(f"[seeder] Generating personal email body for topic '{topic}'...", Style.CYAN)
    body = ollama_generate(prompt)
    cprint(f"[seeder] Generated body for topic '{topic}' (length {len(body)} chars)", Style.GREEN)
    return topic, body

def generate_reply(previous_body: str, topic: str, personality_prompt: str) -> str:
    prompt = (
        "Write a reply (40-120 words) continuing the email thread about '"
        f"{topic}'. Prior snippet (do not quote verbatim): {previous_body[:180]!r}. "
        f"Adopt this persona: {personality_prompt}. Do not state persona explicitly."
    )
    cprint(f"[seeder] Generating reply for topic '{topic}'...", Style.CYAN)
    reply = ollama_generate(prompt)
    cprint(f"[seeder] Generated reply for topic '{topic}' (length {len(reply)} chars)", Style.GREEN)
    return reply

def generate_spam_email() -> Tuple[str, str]:
    cprint("[seeder] Generating spam subject...", Style.MAGENTA)
    subj = ollama_generate_spam_subject()
    SPAM_SUBJECTS_CAPTURED.append(subj)
    cprint(f"[seeder] Got spam subject: {subj}", Style.YELLOW, bold=True)
    cprint("[seeder] Generating spam body...", Style.MAGENTA)
    body = ollama_generate_spam_body()
    cprint(f"[seeder] Got spam body (length {len(body)} chars)", Style.YELLOW)
    token = hex(random.getrandbits(40))[2:]
    body = f"{subj}\n\n{body}\n\nTracking-ID: {token}\nUnsubscribe: http://unsubscribe.example/{token[:8]}"
    return subj, body

def generate_fake_domain_roots(count: int) -> List[str]:
    """Return a list of spammy domain roots (LLM required)."""
    if count <= 0:
        return []
    prompt = (
        f"Generate {count} distinct short spammy domain roots (no dots, no TLD, 6-14 lowercase alphanumeric chars) "
        "as a JSON array of strings. Examples style: securealert, accountupdate, winprize, rewardcenter."
    )
    raw = ollama_generate(prompt)
    import json as _json
    segment = raw[raw.find('['): raw.rfind(']')+1] if '[' in raw and ']' in raw else raw
    parsed = _json.loads(segment)
    if not isinstance(parsed, list):
        raise RuntimeError("Ollama did not return JSON list for domain roots")
    roots: List[str] = []
    for item in parsed:
        if isinstance(item, str):
            slug = ''.join(ch for ch in item.lower() if ch.isalnum())
            if 4 <= len(slug) <= 20:
                roots.append(slug[:14])
        if len(roots) >= count:
            break
    if len(roots) < count:
        raise RuntimeError(f"Only got {len(roots)}/{count} roots from Ollama")
    return roots[:count]

def ensure_users(accounts: List[dict], existing_server: Optional[set] = None) -> None:
    """Create only users not already present on the server.

    accounts: list of dicts with keys: email, password, full_name, username
    existing_server: optional set of already-present email addresses
    """
    created = 0
    existing_server = existing_server or set()
    for acc in accounts:
        email = acc['email']
        if email in existing_server:
            continue
        password = acc['password']
        try:
            subprocess.run([
                "docker", "exec", "-i", DOCKER_MAILSERVER_CONTAINER,
                "setup", "email", "add", email, password
            ], check=True, capture_output=True)
            created += 1
            print(f"[create] {email}")
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.lower()
            if b"already exists" in stderr:
                print(f"[exists] {email}")
            else:
                print(f"[warn] create failed {email}: {e.stderr.decode(errors='ignore')[:120]}")
    # Write JSON inventory including names & usernames
    try:
        with open(USERS_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(accounts, f, indent=2)
        print(f"[users.json] wrote {USERS_JSON_PATH} ({len(accounts)} accounts, {created} created)")
    except Exception as e:
        print(f"[warn] could not write users json: {e}")

def imap_append_email(
    login_user: str,
    login_pass: str,
    subject: str,
    body: str,
    from_addr: str,
    to_addrs: List[str],
    msg_id: Optional[str] = None,
    in_reply_to: Optional[str] = None,
    references: Optional[List[str]] = None,
    time_offset_minutes: int = 0,
    seen: bool = True,
)-> None:
    """Append an email into a user's mailbox with optional threading headers."""
    msg = MIMEText(body, _charset="utf-8")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    # RFC2822 date approximated by base time + offset
    msg_date = (BASE_TIME + timedelta(minutes=time_offset_minutes)).astimezone(timezone.utc)
    msg["Date"] = formatdate(msg_date.timestamp(), localtime=False)
    mid = msg_id or make_msgid(domain=from_addr.split('@')[-1])
    msg["Message-ID"] = mid
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = " ".join(references)
    msg[X_SEEDED_HEADER] = X_SEEDED_VALUE

    raw_bytes = msg.as_bytes()
    # IMAP APPEND expects flags as string (or empty) not None for type clarity
    flags = "(\\Seen)" if seen else ""
    internaldate = imaplib.Time2Internaldate(time.mktime(msg_date.timetuple()))

    if IMAP_USE_SSL:
        conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    else:
        conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
        try:
            typ, caps = conn.capability()
            if b'STARTTLS' in b' '.join(caps):
                conn.starttls()
        except Exception:
            pass
    try:
        try:
            conn.login(login_user, login_pass)
        except imaplib.IMAP4.error as e:
            raise RuntimeError(f"AUTH FAILED for {login_user}: {e}") from e
        try:
            conn.create(MAILBOX)
        except Exception:
            pass
        status = conn.append(MAILBOX, flags, internaldate, raw_bytes)
        if status[0] != 'OK':
            raise RuntimeError(f"APPEND failed: {status}")
    finally:
        try:
            conn.logout()
        except Exception:
            pass

def preflight_logins(users: List[str], password_lookup: Optional[dict] = None) -> List[str]:
    """Attempt a simple IMAP login for each user; return list of failures.

    password_lookup: map email -> password (if per-user)
    """
    failures = []
    for u in users:
        try:
            if IMAP_USE_SSL:
                c = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
            else:
                c = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
                try:
                    typ, caps = c.capability()
                    if b'STARTTLS' in b' '.join(caps):
                        c.starttls()
                except Exception:
                    pass
            pw = password_lookup.get(u) if password_lookup else None
            if not pw:
                pw = password_lookup.get('*') if password_lookup and '*' in password_lookup else None
            if not pw:
                # fallback random wrong pass provoking failure (should not happen normally)
                pw = 'invalid'
            try:
                c.login(u, pw)
            except imaplib.IMAP4.error as e:
                failures.append(u)
            finally:
                try:
                    c.logout()
                except Exception:
                    pass
        except Exception:
            failures.append(u)
    return failures

def preflight_logins_with_retries(users: List[str], password_lookup: dict, retries: int = 3, delay: float = 1.0) -> List[str]:
    """Attempt IMAP logins with limited retries; re-create missing accounts if necessary.

    Returns list of accounts still failing after retries.
    """
    remaining = list(users)
    attempt = 0
    while remaining and attempt <= retries:
        if attempt > 0 and delay:
            time.sleep(delay)
        failures = preflight_logins(remaining, password_lookup=password_lookup)
        if not failures:
            return []
        existing = set(list_existing_accounts())
        missing = [u for u in failures if u not in existing]
        if missing:
            print(f"[preflight] Missing accounts (attempt {attempt+1}/{retries}): {missing} -> re-creating")
            ensure_users([
                {
                    'email': u,
                    'password': password_lookup.get(u, random_password()),
                    'full_name': u.split('@')[0],
                    'username': u.split('@')[0]
                }
                for u in missing
            ], existing_server=existing)
        remaining = failures
        attempt += 1
    return remaining

def seed_conversation(thread_index: int, participants: List[str], length: int, offset_start_min: int) -> int:
    """Create a conversation thread among given participants (round-robin senders)."""
    # First message uses first sender's personality
    first_sender = participants[0]
    first_recipient = participants[1] if len(participants) > 1 else participants[0]
    sender_dict = ACCOUNT_DIRECTORY.get(first_sender, {'full_name': first_sender.split('@')[0], 'email': first_sender, 'personality': 'fun and quirky'})
    recipient_dict = ACCOUNT_DIRECTORY.get(first_recipient, {'full_name': first_recipient.split('@')[0], 'email': first_recipient, 'personality': 'fun and quirky'})
    topic, body = generate_personal_email(sender_dict, recipient_dict)
    subject = f"Re: {topic}" if random.random() < 0.3 else topic
    prev_mid = None
    references: List[str] = []
    msg_body = body
    cprint(f"\n[seeder] Seeding conversation thread {thread_index+1} with {len(participants)} participants, {length} messages...", Style.BLUE, bold=True)
    for i in range(length):
        cprint(f"[seeder]   Message {i+1}/{length} in thread {thread_index+1}", Style.BLUE)
        sender = participants[i % len(participants)]
        receivers = [p for p in participants if p != sender] or [sender]
        if i > 0:
            prev_snippet = (msg_body or body)[:180]
            persona_prompt = ACCOUNT_DIRECTORY.get(sender, {}).get('personality', 'fun and quirky')
            msg_body = generate_reply(prev_snippet, topic, persona_prompt)
        mid = make_msgid(domain=sender.split('@')[-1])
        # Password & display name resolution deferred to runtime via global ACCOUNT_DIRECTORY
        imap_append_email(
            login_user=sender,
            login_pass=ACCOUNT_DIRECTORY.get(sender, {}).get('password', ''),
            subject=subject,
            body=msg_body,
            from_addr=format_address(ACCOUNT_DIRECTORY.get(sender, {'full_name': sender.split('@')[0], 'email': sender})),
            to_addrs=receivers,
            msg_id=mid,
            in_reply_to=prev_mid,
            references=references if references else None,
            time_offset_minutes=offset_start_min + i * 5,
            seen=True,
        )
        PER_USER_ADDED[sender] += 1
        if prev_mid:
            references.append(prev_mid)
        prev_mid = mid
    return length

def seed_outside_inbound(internal_users: List[str], count: int, offset_start_min: int) -> int:
    """Seed one-off inbound personal-style emails from external senders."""
    cprint(f"\n[seeder] Seeding {count} outside inbound emails...", Style.MAGENTA, bold=True)
    for i in range(count):
        cprint(f"[seeder]   Outside email {i+1}/{count}", Style.MAGENTA)
        outside_sender = f"ext{i}@{OUTSIDE_DOMAIN}"
        recipient = random.choice(internal_users)
        recipient_dict = ACCOUNT_DIRECTORY.get(recipient, {'full_name': recipient.split('@')[0], 'email': recipient, 'personality': 'fun and quirky'})
        # For outside sender, create a dummy dict
        sender_dict = {'full_name': f"External User {i}", 'email': outside_sender, 'personality': 'fun and quirky'}
        topic, body = generate_personal_email(sender_dict, recipient_dict)
        subject = topic
        imap_append_email(
            login_user=recipient,
            login_pass=ACCOUNT_DIRECTORY.get(recipient, {}).get('password', ''),
            subject=subject,
            body=body,
            from_addr=outside_sender,
            to_addrs=[recipient],
            time_offset_minutes=offset_start_min + i * 3,
            seen=False,
        )
        PER_USER_ADDED[recipient] += 1
    return count

def seed_spam_inbound(internal_users: List[str], count: int, offset_start_min: int) -> int:
    if count <= 0:
        return 0
    # Always dynamic domains
    roots = generate_fake_domain_roots(count)
    domains = [f"{r}.{SPAM_DOMAIN_TLD}" for r in roots]
    cprint(f"\n[seeder] Seeding {count} spam inbound emails...", Style.YELLOW, bold=True)
    for i in range(count):
        cprint(f"[seeder]   Spam email {i+1}/{count}", Style.YELLOW)
        domain = domains[i]
        sender = f"no-reply@{domain}"
        recipient = random.choice(internal_users)
        subj, body = generate_spam_email()
        try:
            imap_append_email(
                login_user=recipient,
                login_pass=ACCOUNT_DIRECTORY.get(recipient, {}).get('password', ''),
                subject=subj,
                body=body,
                from_addr=sender,
                to_addrs=[recipient],
                time_offset_minutes=offset_start_min + i * 2,
                seen=False,
            )
            PER_USER_ADDED[recipient] += 1
        except Exception as e:
            print(f"[WARN] spam append failed ({sender} -> {recipient}): {e}")
    return count

def verify_mailboxes(internal_users: List[str], added: Optional[dict] = None):
    """Verify mailbox contents for each user.

    Metrics per user:
      - total messages (ALL)
      - seeded messages (HEADER X-Seeded-By)
      - spam (subset of seeded with spam subject heuristics)
    """
    results = []
    spam_markers = {s.lower() for s in SPAM_SUBJECTS_CAPTURED}
    heuristic_terms = ["win", "free", "urgent", "offer", "refund", "selected", "suspicious"]
    for user in internal_users:
        conn = None  # ensure defined for finally block
        try:
            if IMAP_USE_SSL:
                conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
            else:
                conn = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
                try:
                    typ, caps = conn.capability()
                    if b'STARTTLS' in b' '.join(caps):
                        conn.starttls()
                except Exception:
                    pass
            conn.login(user, ACCOUNT_DIRECTORY.get(user, {}).get('password', ''))
            typ, _ = conn.select(MAILBOX, readonly=True)
            if typ != 'OK':
                raise RuntimeError("select failed")
            # Total
            typ, data = conn.search(None, 'ALL')
            all_ids = data[0].split() if typ == 'OK' and data and data[0] else []
            # Seeded
            typ, data = conn.search(None, 'HEADER', X_SEEDED_HEADER, X_SEEDED_VALUE)
            seeded_ids = set(data[0].split()) if typ == 'OK' and data and data[0] else set()
            spam_count = 0
            if seeded_ids:
                for mid in list(seeded_ids):
                    try:
                        ft, fd = conn.fetch(mid, '(BODY.PEEK[HEADER.FIELDS (SUBJECT)])')
                        if ft != 'OK' or not fd:
                            continue
                        # Flatten tuple payloads only
                        header_parts = []
                        for part in fd:
                            if isinstance(part, tuple) and len(part) >= 2:
                                header_parts.append(part[1])
                        if not header_parts:
                            continue
                        header_blob = b''.join(header_parts)
                        subject_line = header_blob.decode(errors='ignore').lower()
                        if (
                            any(marker in subject_line for marker in spam_markers)
                            or any(term in subject_line for term in heuristic_terms)
                        ):
                            spam_count += 1
                    except Exception:
                        continue
            results.append({'user': user, 'total': len(all_ids), 'seeded': len(seeded_ids), 'spam_est': spam_count})
        except Exception as e:
            results.append({'user': user, 'error': str(e), 'total': 0, 'seeded': 0, 'spam_est': 0})
        finally:
            if conn:
                try:
                    conn.logout()
                except Exception:
                    pass
    # Print summary table
    print("\nVerification Summary:")
    print(f"{'User':30} {'Total':>6} {'Added':>6} {'SpamEst':>7}")
    print("-" * 54)
    for r in results:
        if 'error' in r and r['error']:
            print(f"{r['user']:<30} ERR   ERR   ERR    ({r['error'][:25]})")
        else:
            added_count = (added or {}).get(r['user'], 0)
            print(f"{r['user']:<30} {r['total']:6d} {added_count:6d} {r['spam_est']:7d}")
    return results

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automatic IMAP mailbox seeder (threads + outside + spam).",
        epilog="Minimal flags: most behavior is automatic."
    )
    parser.add_argument("--num-users", type=int, default=NUM_USERS, help="Number of user accounts to synthesize")
    parser.add_argument("--thread-count", type=int, default=THREAD_COUNT, help="Number of conversation threads to seed")
    parser.add_argument("--thread-length-min", type=int, default=THREAD_LENGTH_MIN, help="Minimum messages per thread")
    parser.add_argument("--thread-length-max", type=int, default=THREAD_LENGTH_MAX, help="Maximum messages per thread")
    parser.add_argument("--outside-email-count", type=int, default=OUTSIDE_EMAIL_COUNT, help="Number of outside (external sender) emails")
    parser.add_argument("--spam-email-count", type=int, default=SPAM_EMAIL_COUNT, help="Number of spam emails to generate")
    parser.add_argument("--verify-only", action="store_true", default=VERIFY_ONLY, help="Only run verification (no seeding)")
    parser.add_argument("--no-post-verify", action="store_false", dest="post_verify", default=POST_VERIFY, help="Skip post verification")
    parser.add_argument("--users-json-path", default=USERS_JSON_PATH, help="Inventory JSON output path")
    parser.add_argument("--ollama-host", default=OLLAMA_HOST, help="Ollama host IP (no scheme, default 127.0.0.1)")
    parser.add_argument("--ollama-port", default=OLLAMA_PORT, help="Ollama port (default 11434)")
    # Ollama always on; flag removed.
    return parser.parse_args()

def apply_args(args: argparse.Namespace) -> None:
    global NUM_USERS, USERS_JSON_PATH, VERIFY_ONLY, POST_VERIFY, OLLAMA_HOST, OLLAMA_PORT, OLLAMA_ADDRESS
    global THREAD_COUNT, THREAD_LENGTH_MIN, THREAD_LENGTH_MAX, OUTSIDE_EMAIL_COUNT, SPAM_EMAIL_COUNT
    NUM_USERS = args.num_users
    USERS_JSON_PATH = args.users_json_path
    VERIFY_ONLY = args.verify_only
    POST_VERIFY = args.post_verify
    THREAD_COUNT = args.thread_count
    THREAD_LENGTH_MIN = args.thread_length_min
    THREAD_LENGTH_MAX = args.thread_length_max
    OUTSIDE_EMAIL_COUNT = args.outside_email_count
    SPAM_EMAIL_COUNT = args.spam_email_count
    OLLAMA_HOST = args.ollama_host
    OLLAMA_PORT = str(args.ollama_port)
    # Rebuild derived address
    OLLAMA_ADDRESS = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"

def list_existing_accounts() -> List[str]:
    try:
        out = subprocess.run(["docker", "exec", "-i", DOCKER_MAILSERVER_CONTAINER, "setup", "email", "list"],
                              check=True, capture_output=True, text=True, timeout=10)
        raw = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        emails = []
        for line in raw:
            if line.startswith('*'):
                parts = line.split()
                if len(parts) >= 2 and '@' in parts[1]:
                    emails.append(parts[1])
            elif '@' in line and ' ' not in line:
                emails.append(line)
        return emails
    except Exception:
        return []

def random_password(length: int = 14) -> str:
    import secrets, string
    # Restrict to alphanumeric to avoid any shell/encoding quirks with mailserver script
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# Removed synthesize_names: fallback generation eliminated.

def generate_accounts(count: int, domain: str) -> List[dict]:
    """Generate accounts solely via LLM; fail if insufficient."""
    prompt = (
        f"Generate {count} distinct humorous fictional user records as compact JSON array. "
        "Each element object: {full_name, username}. Full names playful, 2-3 words. "
        "Usernames lowercase alphanumeric only, 3-14 chars, derived from name (no spaces)."
    )
    raw = ollama_generate(prompt)
    import json as _json
    segment = raw[raw.find('['): raw.rfind(']')+1] if '[' in raw and ']' in raw else raw
    parsed = _json.loads(segment)
    if not isinstance(parsed, list):
        raise RuntimeError("Ollama did not return JSON list for accounts")
    accounts: List[dict] = []
    for rec in parsed:
        if len(accounts) >= count:
            break
        if isinstance(rec, str):
            full_name = rec.strip()
            uname_seed = ''.join(ch for ch in full_name.lower() if ch.isalnum())
            username = uname_seed[:14] if uname_seed else None
        elif isinstance(rec, dict):
            full_name = (rec.get('full_name') or rec.get('name') or '').strip()
            username = rec.get('username')
            if full_name and not username:
                uname_seed = ''.join(ch for ch in full_name.lower() if ch.isalnum())
                username = uname_seed[:14]
        else:
            continue
        if not full_name or not username:
            continue
        username = ''.join(ch for ch in username.lower() if ch.isalnum())[:14]
        if not username:
            continue
        name_parts = full_name.strip().split()
        if len(name_parts) >= 2:
            email_local = f"{name_parts[0]}.{name_parts[-1]}"
        else:
            email_local = name_parts[0]
        email_local = ''.join(ch for ch in email_local if ch.isalnum() or ch == '.')
        email = f"{email_local.lower()}@{domain}"
        personality = generate_personality(full_name)
        accounts.append({'full_name': full_name, 'username': username, 'personality': personality, 'email': email})
    if len(accounts) < count:
        raise RuntimeError(f"Only generated {len(accounts)}/{count} accounts from LLM")
    seen = set()
    for acc in accounts:
        orig = acc['username']
        uname = orig
        i = 2
        while uname in seen:
            uname = f"{orig}{i}"[:14]
            i += 1
        acc['username'] = uname
        seen.add(uname)
        acc['password'] = random_password()
    print(f"[names] LLM generated {len(accounts)} accounts with personalities")
    return accounts[:count]

def load_inventory() -> List[dict]:
    try:
        with open(USERS_JSON_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []

def generate_additional_accounts(n: int, domain: str, used_slugs: set) -> List[dict]:
    """Generate additional accounts via LLM only."""
    if n <= 0:
        return []
    prompt = (
        f"Generate {n} humorous fictional user full names as JSON array (strings). "
        "Names playful, whimsical, 2-3 words, PG, no internal quotes."
    )
    raw = ollama_generate(prompt)
    import json as _json
    segment = raw[raw.find('['): raw.rfind(']')+1] if '[' in raw and ']' in raw else raw
    parsed = _json.loads(segment)
    if not isinstance(parsed, list):
        raise RuntimeError("Ollama did not return JSON list for additional accounts")
    accounts: List[dict] = []
    for rec in parsed:
        if len(accounts) >= n:
            break
        if isinstance(rec, str):
            full_name = rec.strip()
        elif isinstance(rec, dict):
            full_name = (rec.get('full_name') or rec.get('name') or '').strip()
        else:
            continue
        if not full_name:
            continue
        parts = full_name.split()
        if len(parts) >= 2:
            fn, ln = parts[0], parts[-1]
        else:
            fn = parts[0]; ln = 'user'
        base = ''.join(ch for ch in (fn + ln).lower() if ch.isalnum()) or 'user'
        slug = base[:32]
        i = 2
        while slug in used_slugs:
            slug = (base + str(i))[:32]
            i += 1
        used_slugs.add(slug)
        name_parts = full_name.strip().split()
        if len(name_parts) >= 2:
            email_local = f"{name_parts[0]}.{name_parts[-1]}"
        else:
            email_local = name_parts[0]
        email_local = ''.join(ch for ch in email_local if ch.isalnum() or ch == '.')
        email = f"{email_local.lower()}@{domain}"
        personality = generate_personality(full_name)
        accounts.append({
            'full_name': full_name,
            'username': slug,
            'email': email,
            'password': random_password(),
            'personality': personality,
        })
    if len(accounts) < n:
        raise RuntimeError(f"Only generated {len(accounts)}/{n} additional accounts")
    return accounts

def build_accounts(requested: int, domain: str) -> List[dict]:
    inventory = load_inventory()
    # Fast path: if inventory already has >= requested accounts for domain, reuse first requested.
    domain_inv = [acc for acc in inventory if isinstance(acc, dict) and acc.get('email','').endswith(f"@{domain}")]
    if len(domain_inv) >= requested:
        reused = domain_inv[:requested]
        print(f"[accounts] Fast reuse from JSON inventory ({len(reused)}/{requested}); skipping server listing.")
        return [
            {
                'full_name': acc.get('full_name') or acc.get('username') or acc['email'].split('@')[0],
                'username': acc.get('username') or acc['email'].split('@')[0],
                'email': acc['email'],
                'password': acc.get('password') or random_password(),
            }
            for acc in reused
        ]
    # Otherwise, need to know which of inventory accounts actually exist server-side
    existing_server = set(list_existing_accounts())
    reused: List[dict] = []
    used_slugs = set()
    for acc in domain_inv:
        email = acc.get('email')
        if email:
            username = acc.get('username') or email.split('@')[0]
        else:
            username = acc.get('username') or "user"
        if email and email in existing_server and username not in used_slugs:
            used_slugs.add(username)
            reused.append({
                'full_name': acc.get('full_name') or username,
                'username': username,
                'email': email,
                'password': acc.get('password') or random_password(),
            })
        if len(reused) >= requested:
            break
    shortfall = requested - len(reused)
    if shortfall <= 0:
        print(f"[accounts] Reusing {len(reused)} server-present accounts (>= requested {requested}).")
        return reused
    # Need to generate additional
    new_accounts = generate_additional_accounts(shortfall, domain, used_slugs)
    accounts = reused + new_accounts
    ensure_users(accounts, existing_server=existing_server)
    return accounts

def format_address(acc: dict) -> str:
    return f"{acc['full_name']} <{acc['email']}>"

def _format_elapsed(seconds: float) -> str:
    """Return human friendly elapsed string."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m {s:02d}s"

def main() -> None:
    args = parse_args()
    apply_args(args)
    accounts = build_accounts(NUM_USERS, INTERNAL_DOMAIN)
    print(f"Active accounts (domain={INTERNAL_DOMAIN}): {[a['email'] for a in accounts]}")
    # Build password lookup
    pw_lookup = {a['email']: a['password'] for a in accounts}
    global ACCOUNT_DIRECTORY
    ACCOUNT_DIRECTORY = {a['email']: a for a in accounts}
    internal_users = [a['email'] for a in accounts]
    # Preflight login with per-user passwords
    failures = preflight_logins_with_retries(internal_users, password_lookup=pw_lookup, retries=3, delay=1.0)
    if failures:
        print(f"[preflight] STILL failing auth for: {failures}")
        if VERIFY_ONLY:
            print("[preflight] Proceeding to verification.")
        else:
            print("[preflight] Aborting seeding (cannot authenticate all users). Use --verify-only to inspect.")
            if POST_VERIFY:
                verify_mailboxes(internal_users)
            return

    if not VERIFY_ONLY:
        total = 0
        print(f"Seeding {THREAD_COUNT} conversation threads (len {THREAD_LENGTH_MIN}-{THREAD_LENGTH_MAX})")
        for t in range(THREAD_COUNT):
            length = random.randint(THREAD_LENGTH_MIN, THREAD_LENGTH_MAX)
            k = min(len(internal_users), random.choice([2, 2, 3, len(internal_users)]))
            participants = random.sample(internal_users, k)
            try:
                seeded = seed_conversation(t, participants, length, offset_start_min=t * 60)
                total += seeded
                if SLEEP_BETWEEN_SECONDS:
                    time.sleep(SLEEP_BETWEEN_SECONDS)
            except Exception as e:
                print(f"[WARN] Thread {t} failed: {e}")

        print(f"Seeding outside inbound emails (normal={OUTSIDE_EMAIL_COUNT}) and spam={SPAM_EMAIL_COUNT}")
        outside_offset = THREAD_COUNT * 60
        try:
            if OUTSIDE_EMAIL_COUNT:
                total += seed_outside_inbound(internal_users, OUTSIDE_EMAIL_COUNT, offset_start_min=outside_offset)
            if SPAM_EMAIL_COUNT:
                total += seed_spam_inbound(internal_users, SPAM_EMAIL_COUNT, offset_start_min=outside_offset + 5)
        except Exception as e:
            print(f"[WARN] Outside/spam seed failed: {e}")
        print(f"✅ Seeding complete: {total} messages (threads + outside).")
    else:
        print("VERIFY_ONLY: skipping seeding.")

    if POST_VERIFY or VERIFY_ONLY:
        verify_mailboxes(internal_users, added=PER_USER_ADDED)

    elapsed = time.perf_counter() - RUN_START
    print(f"\n⏱ Run time: {_format_elapsed(elapsed)}")

if __name__ == "__main__":
    main()
