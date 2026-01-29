# mailverify

Local SMTP email verifier. Built to catch **non‑existent mailboxes** without paid APIs.

## Features
- Syntax + MX checks
- SMTP RCPT verification (mailbox exists)
- Catch‑all detection
- Disposable + role filtering
- Concurrency + rate limiting
- Resume support
- CSV input/output + summary

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python3 mailverify.py \
  --input leads.csv \
  --output verified.csv \
  --catch-all \
  --rate 1 \
  --per-domain 3 \
  --concurrency 4 \
  --resume
```

### Input CSV
- Uses `email` header if present, otherwise first column.

### Output CSV
Columns include:
- `email`
- `status` (valid, invalid_mailbox, catch_all, role_account, disposable_domain, no_mx, invalid_syntax, unknown)
- `mx`
- `detail` (SMTP response/error)

## Notes
- 1/sec global rate is safest for avoiding blocks.
- `--per-domain` throttles per domain to reduce server bans.
- Some servers always return `unknown` or block SMTP checks.

## Example (safe settings)
```bash
python3 mailverify.py --input leads.csv --output verified.csv --rate 1 --per-domain 3 --resume
```
