# mailverify

Local SMTP email verifier. Designed to catch **non-existent mailboxes** without expensive APIs.

## What it does
- Syntax check
- MX lookup
- SMTP RCPT check (detects non-existent mailboxes)
- Optional catch-all detection
- Role account filtering

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python3 mailverify.py --input leads.csv --output results.csv --catch-all
```

### Input CSV
- If first row has `email` header, it uses that column.
- Otherwise, it uses the first column.

### Output CSV
Includes:
- `email`
- `status` (valid, invalid_mailbox, catch_all, role_account, no_mx, invalid_syntax, unknown)
- `mx` (if available)
- `detail` (SMTP response or error)

## Notes
SMTP verification can be throttled or blocked by some mail servers. Use `--sleep` to slow down if needed.

Default MAIL FROM is `verify@localhost`. You can override with `--from`.

## Example
```bash
python3 mailverify.py --input leads.csv --output verified.csv --catch-all --sleep 1
```
