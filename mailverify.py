#!/usr/bin/env python3
import argparse
import csv
import random
import re
import socket
import string
import time
from typing import Dict, List, Tuple

import dns.resolver
import smtplib

ROLE_ACCOUNTS = {
    "admin","administrator","billing","contact","info","support","sales",
    "help","hello","hi","inquiry","team","office","careers","hr",
    "jobs","press","media","abuse","security","legal","privacy",
    "accounts","accounting","payments","marketing"
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_email(addr: str) -> Tuple[bool, str, str]:
    addr = (addr or "").strip()
    if not addr or not EMAIL_RE.match(addr):
        return False, "", ""
    local, domain = addr.split("@", 1)
    return True, local.lower(), domain.lower()


def get_mx(domain: str) -> List[Tuple[int, str]]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
        return mx
    except Exception:
        return []


def smtp_check(mx_host: str, email: str, mail_from: str, timeout: int) -> Tuple[str, str]:
    try:
        server = smtplib.SMTP(timeout=timeout)
        server.connect(mx_host)
        server.helo(socket.gethostname())
        server.mail(mail_from)
        code, msg = server.rcpt(email)
        server.quit()
        if 200 <= code < 300:
            return "accepted", f"{code} {msg.decode(errors='ignore') if isinstance(msg, bytes) else msg}"
        if 500 <= code < 600:
            return "rejected", f"{code} {msg.decode(errors='ignore') if isinstance(msg, bytes) else msg}"
        return "unknown", f"{code} {msg.decode(errors='ignore') if isinstance(msg, bytes) else msg}"
    except Exception as e:
        return "error", str(e)


def random_local() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


def verify_email(addr: str, mail_from: str, timeout: int, catch_all: bool) -> Dict[str, str]:
    ok, local, domain = parse_email(addr)
    if not ok:
        return {"email": addr, "status": "invalid_syntax"}

    if local in ROLE_ACCOUNTS:
        return {"email": addr, "status": "role_account"}

    mx = get_mx(domain)
    if not mx:
        return {"email": addr, "status": "no_mx"}

    mx_host = mx[0][1]
    status, detail = smtp_check(mx_host, addr, mail_from, timeout)
    if status == "accepted":
        if catch_all:
            fake = f"{random_local()}@{domain}"
            fstatus, _ = smtp_check(mx_host, fake, mail_from, timeout)
            if fstatus == "accepted":
                return {"email": addr, "status": "catch_all", "mx": mx_host}
        return {"email": addr, "status": "valid", "mx": mx_host}

    if status == "rejected":
        return {"email": addr, "status": "invalid_mailbox", "mx": mx_host, "detail": detail}

    return {"email": addr, "status": "unknown", "mx": mx_host, "detail": detail}


def read_emails(path: str) -> List[str]:
    emails = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)
        if not rows:
            return []
        # Detect header
        header = [c.strip().lower() for c in rows[0]]
        if "email" in header:
            idx = header.index("email")
            for r in rows[1:]:
                if idx < len(r):
                    emails.append(r[idx])
        else:
            for r in rows:
                if r:
                    emails.append(r[0])
    return emails


def write_results(path: str, results: List[Dict[str, str]]):
    fieldnames = sorted({k for r in results for k in r.keys()})
    if "email" in fieldnames:
        fieldnames = ["email"] + [f for f in fieldnames if f != "email"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def main():
    p = argparse.ArgumentParser(description="Local SMTP email verifier")
    p.add_argument("--input", required=True, help="Input CSV file (first column or 'email' header)")
    p.add_argument("--output", required=True, help="Output CSV file")
    p.add_argument("--from", dest="mail_from", default="verify@localhost", help="MAIL FROM address")
    p.add_argument("--timeout", type=int, default=10, help="SMTP timeout seconds")
    p.add_argument("--sleep", type=float, default=0.5, help="Sleep between checks (seconds)")
    p.add_argument("--catch-all", action="store_true", help="Detect catch-all domains")
    args = p.parse_args()

    emails = read_emails(args.input)
    results = []
    for i, email in enumerate(emails, 1):
        res = verify_email(email, args.mail_from, args.timeout, args.catch_all)
        results.append(res)
        if args.sleep:
            time.sleep(args.sleep)

    write_results(args.output, results)
    print(f"Done. {len(results)} emails processed.")


if __name__ == "__main__":
    main()
