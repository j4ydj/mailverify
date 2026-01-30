#!/usr/bin/env python3
import argparse
import csv
import os
import random
import re
import socket
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Set

import dns.resolver
import smtplib

ROLE_ACCOUNTS = {
    "admin","administrator","billing","contact","info","support","sales",
    "help","hello","hi","inquiry","team","office","careers","hr",
    "jobs","press","media","abuse","security","legal","privacy",
    "accounts","accounting","payments","marketing","postmaster","webmaster"
}

DEFAULT_DISPOSABLE = {
    "mailinator.com","10minutemail.com","tempmail.com","guerrillamail.com",
    "yopmail.com","trashmail.com","getnada.com","tempmail.net","maildrop.cc"
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Rate limiting
_global_lock = threading.Lock()
_last_global = 0.0
_domain_lock = threading.Lock()
_last_domain = {}


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
        msg_text = msg.decode(errors='ignore') if isinstance(msg, bytes) else str(msg)
        if 200 <= code < 300:
            return "accepted", f"{code} {msg_text}"
        if 500 <= code < 600:
            return "rejected", f"{code} {msg_text}"
        return "unknown", f"{code} {msg_text}"
    except Exception as e:
        return "error", str(e)


def random_local() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


def rate_limit(domain: str, per_sec: float, per_domain_sec: float):
    global _last_global
    now = time.time()
    min_interval = 1.0 / per_sec if per_sec > 0 else 0
    with _global_lock:
        wait = max(0, (_last_global + min_interval) - now)
        if wait > 0:
            time.sleep(wait)
        _last_global = time.time()

    if per_domain_sec > 0:
        with _domain_lock:
            last = _last_domain.get(domain, 0)
            wait = max(0, (last + per_domain_sec) - time.time())
            if wait > 0:
                time.sleep(wait)
            _last_domain[domain] = time.time()


def verify_email(addr: str, mail_from: str, timeout: int, catch_all: bool,
                 per_sec: float, per_domain_sec: float,
                 disposable_domains: Set[str]) -> Dict[str, str]:
    ok, local, domain = parse_email(addr)
    if not ok:
        return {"email": addr, "status": "invalid_syntax"}

    if local in ROLE_ACCOUNTS:
        return {"email": addr, "status": "role_account"}

    if domain in disposable_domains:
        return {"email": addr, "status": "disposable_domain"}

    mx = get_mx(domain)
    if not mx:
        return {"email": addr, "status": "no_mx"}

    mx_host = mx[0][1]
    rate_limit(domain, per_sec, per_domain_sec)
    status, detail = smtp_check(mx_host, addr, mail_from, timeout)

    if status == "accepted":
        if catch_all:
            fake = f"{random_local()}@{domain}"
            rate_limit(domain, per_sec, per_domain_sec)
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


def load_seen(output: str) -> Set[str]:
    seen = set()
    if not os.path.exists(output):
        return seen
    with open(output, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("email"):
                seen.add(row["email"].strip())
    return seen


def main():
    p = argparse.ArgumentParser(description="Local SMTP email verifier")
    p.add_argument("--input", required=True, help="Input CSV file (first column or 'email' header)")
    p.add_argument("--output", required=True, help="Output CSV file")
    p.add_argument("--from", dest="mail_from", default="verify@localhost", help="MAIL FROM address")
    p.add_argument("--timeout", type=int, default=10, help="SMTP timeout seconds")
    p.add_argument("--catch-all", action="store_true", help="Detect catch-all domains")
    p.add_argument("--rate", type=float, default=1.0, help="Global checks per second")
    p.add_argument("--per-domain", type=float, default=3.0, help="Seconds between checks per domain")
    p.add_argument("--concurrency", type=int, default=4, help="Concurrent workers")
    p.add_argument("--resume", action="store_true", help="Skip emails already in output")
    p.add_argument("--disposable-list", help="Optional file with disposable domains (one per line)")
    args = p.parse_args()

    emails = read_emails(args.input)
    seen = load_seen(args.output) if args.resume else set()
    emails = [e for e in emails if e and e.strip() and e.strip() not in seen]

    disposable = set(DEFAULT_DISPOSABLE)
    if args.disposable_list and os.path.exists(args.disposable_list):
        with open(args.disposable_list, encoding="utf-8") as f:
            for line in f:
                d = line.strip().lower()
                if d:
                    disposable.add(d)

    fieldnames = ["email","status","mx","detail"]
    mode = "a" if args.resume and os.path.exists(args.output) else "w"
    out = open(args.output, mode, newline="", encoding="utf-8")
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    if mode == "w":
        writer.writeheader()

    lock = threading.Lock()
    summary = {
        "valid":0,"invalid_mailbox":0,"catch_all":0,"role_account":0,
        "disposable_domain":0,"no_mx":0,"invalid_syntax":0,"unknown":0
    }

    def task(email):
        return verify_email(email, args.mail_from, args.timeout, args.catch_all,
                            args.rate, args.per_domain, disposable)

    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(task, e): e for e in emails}
        for fut in as_completed(futures):
            res = fut.result()
            with lock:
                writer.writerow({
                    "email": res.get("email",""),
                    "status": res.get("status",""),
                    "mx": res.get("mx",""),
                    "detail": res.get("detail",""),
                })
                out.flush()
            status = res.get("status", "unknown")
            summary[status] = summary.get(status, 0) + 1

    out.close()
    print("Summary:")
    for k, v in summary.items():
        print(f"{k}: {v}")
    print(f"Done. {len(emails)} emails processed.")


if __name__ == "__main__":
    main()
