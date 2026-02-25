# Gmail Forwarder

Copies emails from any IMAP server to Gmail using IMAP APPEND — preserving the original sender, date, and content.

## Why IMAP APPEND?

Instead of relaying through SMTP, this tool fetches raw RFC822 bytes from the source server and appends them directly to your Gmail mailbox. This means:

- Original sender, date, HTML body, and attachments are preserved unchanged
- No dependency on the source server's SMTP relay
- No header modifications or added forwarding traces

## Requirements

- Python 3.10+
- `keyring` library (`pip install -r requirements.txt`)
- Gmail [App Password](https://myaccount.google.com/apppasswords) (required — regular password won't work)

## Installation

```bash
git clone https://github.com/kujawiak/gmail-forwarder.git
cd gmail-forwarder
pip install -r requirements.txt
cp config.ini.sample config.ini
```

> **Note:** `config.ini` contains credentials — do not commit it.

## Configuration

Edit `config.ini` based on the `config.ini.sample` template. Each account is a separate INI section.

| Field | Description |
|---|---|
| `host`, `user` | Source IMAP server address and username |
| `ssl`, `port` | Connection settings (default: SSL on port 993) |
| `gmail_user` | Gmail address (requires App Password) |
| `gmail_folder` | Target Gmail folder (default: `INBOX`) |
| `trash_folder` | Folder for processed source emails (default: `Trash`) |
| `mark_source_as_read` | Mark source as `\Seen` before moving to trash (default: `false`) |
| `filters` | Multi-line filter rules (see below) |

## Filters

Each filter rule follows this format (one rule per line):

```
field:value:label1,label2:never_spam
```

- **`field`** — `to`, `from`, or `subject`
- **`value`** — plain substring (case-insensitive) or regex; auto-detected by the presence of `.[](){}*+?^$|\\` characters
- **`label1,label2`** — comma-separated Gmail labels to apply
- **`never_spam`** — `true` removes the `\Spam` label from the Gmail copy

Example:

```ini
filters =
    to:me@example.com:me@example.com:true
    from:important@company.com:Important:true
    from:.*@facebookmail\.com:Facebook:true
    subject:Invoice|FV:Invoices:false
```

## Password Management

Passwords are stored securely in the OS keyring (Windows Credential Manager, macOS Keychain, or Linux Secret Service).

```bash
# Store passwords
python gmfwi.py --config config.ini --account work --store-password --store-gmail-password

# Remove passwords
python gmfwi.py --config config.ini --account work --forget-password --forget-gmail-password
```

## Usage

```bash
# Preview emails from all accounts
python gmfwi.py --config config.ini

# Preview emails from a specific account
python gmfwi.py --config config.ini --account work

# Forward: copy to Gmail and move originals to Trash
python gmfwi.py --config config.ini --account work --autoforward

# Override the message preview limit
python gmfwi.py --config config.ini --account work --limit 20
```