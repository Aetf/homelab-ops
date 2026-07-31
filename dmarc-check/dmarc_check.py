#!/usr/bin/env python3
"""Daily DMARC aggregate-report triage.

Fetches unread DMARC aggregate reports from the Gmail INBOX over IMAP, unpacks
the (gzip/zip) XML attachment and evaluates the per-source SPF/DKIM results.

A record is a candidate failure when it passes NEITHER SPF nor DKIM after
alignment, or when the receiver quarantined/rejected it. Because a correctly
policed domain still produces a steady stream of such records (the domain's own
mail relayed unaligned, forwarders, and spoofing that the policy is already
catching), a raw failure is NOT treated as "notify me". Instead:

  - clean report (no failing records)
        -> mark read + archive. Silent.
  - report with failing records
        -> ask `claude` to classify BENIGN (own/legit mail merely unaligned, or
           abuse the policy already handles) vs SUSPICIOUS (worth a human look).
        - BENIGN     -> mark read + archive. Silent.
        - SUSPICIOUS -> keep it unread, tag `DMARC-Issue`, and mail an alert,
                        rate-limited per domain (a persistent issue re-alerts at
                        most once per cooldown window; the report still gets
                        tagged + kept unread so it stays visible).
  - unparseable report
        -> leave it untouched and alert once, so a parsing gap can't silently
           swallow reports.

State ($STATE_DIR/state.json) records which reports were already classified (so
an unread SUSPICIOUS report is not re-analysed every day) and the per-domain
alert cooldown. claude's verdict gates archive-vs-keep; a claude failure
fails safe to SUSPICIOUS.

Standard library only; runtime inputs are the env vars below, a mounted claude
credential, and the state dir.
"""

import email
import email.message
import gzip
import imaplib
import io
import json
import os
import smtplib
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone


def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        die(f"missing required env var {name}")
    return val


CONFIG = {}


def load_config():
    CONFIG.update(
        imap_host=env("DMARC_IMAP_HOST", "imap.gmail.com"),
        imap_port=int(env("DMARC_IMAP_PORT", "993")),
        imap_user=env("DMARC_IMAP_USER", required=True),
        imap_pass=env("DMARC_IMAP_PASS", required=True),
        smtp_host=env("DMARC_SMTP_HOST", "smtp.gmail.com"),
        smtp_port=int(env("DMARC_SMTP_PORT", "587")),
        smtp_user=env("DMARC_SMTP_USER") or env("DMARC_IMAP_USER"),
        smtp_pass=env("DMARC_SMTP_PASS") or env("DMARC_IMAP_PASS"),
        mail_to=env("DMARC_MAILTO") or env("DMARC_IMAP_USER"),
        mail_from=env("DMARC_MAILFROM") or env("DMARC_SMTP_USER") or env("DMARC_IMAP_USER"),
        issue_label=env("DMARC_ISSUE_LABEL", "DMARC-Issue"),
        state_dir=env("STATE_DIR", "/state"),
        claude_bin=env("DMARC_CLAUDE_BIN", "claude"),
        claude_timeout=int(env("DMARC_CLAUDE_TIMEOUT", "180")),
        cooldown_days=float(env("DMARC_COOLDOWN_DAYS", "7")),
        # When set, mutate nothing and send nothing — just report what would
        # happen. Handy for the first manual runs. claude is still consulted
        # (read-only) so its verdicts can be observed.
        dry_run=bool(env("DMARC_DRY_RUN")),
    )


def log(msg):
    """Structured stdout line -> ends up in the systemd journal."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{ts} {msg}", flush=True)


def die(msg):
    log(f"FATAL {msg}")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# state: {"processed": {report_key: verdict}, "cooldown": {domain: epoch}}
# --------------------------------------------------------------------------- #
def state_path():
    return os.path.join(CONFIG["state_dir"], "state.json")


def load_state():
    try:
        with open(state_path()) as f:
            data = json.load(f)
    except (FileNotFoundError, ValueError):
        data = {}
    data.setdefault("processed", {})
    data.setdefault("cooldown", {})
    return data


def save_state(state):
    if CONFIG["dry_run"]:
        return
    os.makedirs(CONFIG["state_dir"], exist_ok=True)
    tmp = state_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, state_path())


def in_cooldown(state, domain):
    ts = state["cooldown"].get(domain)
    return bool(ts) and (time.time() - ts) < CONFIG["cooldown_days"] * 86400


def start_cooldown(state, domain):
    state["cooldown"][domain] = int(time.time())


# --------------------------------------------------------------------------- #
# report parsing
# --------------------------------------------------------------------------- #
def extract_xml(part_bytes, filename):
    """Return decompressed XML bytes from an attachment payload.

    DMARC aggregate reports arrive gzip'd (`.xml.gz`) or zip'd (`.zip`); a few
    senders attach raw XML. Sniff by magic number, fall back to the name.
    """
    if part_bytes[:2] == b"\x1f\x8b":  # gzip magic
        return gzip.decompress(part_bytes)
    if part_bytes[:2] == b"PK":  # zip magic
        with zipfile.ZipFile(io.BytesIO(part_bytes)) as z:
            names = [n for n in z.namelist() if n.lower().endswith(".xml")] or z.namelist()
            return z.read(names[0])
    if b"<feedback" in part_bytes[:4096] or (filename or "").lower().endswith(".xml"):
        return part_bytes
    raise ValueError(f"attachment {filename!r} is not a recognised DMARC report")


def report_xml_from_message(msg):
    """Find the report attachment in an email and return its XML bytes."""
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename() or ""
        ctype = (part.get_content_type() or "").lower()
        looks_like_report = (
            ctype in ("application/gzip", "application/x-gzip", "application/zip",
                      "application/x-zip-compressed", "application/octet-stream")
            or filename.lower().endswith((".gz", ".zip", ".xml"))
        )
        if not looks_like_report:
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        try:
            return extract_xml(payload, filename)
        except (ValueError, OSError, zipfile.BadZipFile):
            continue
    raise ValueError("no parseable DMARC attachment found")


def _text(node, path, default=""):
    el = node.find(path)
    return el.text.strip() if el is not None and el.text else default


def parse_report(xml_bytes):
    """Parse aggregate-report XML into a dict with a per-source verdict."""
    root = ET.fromstring(xml_bytes)
    org = _text(root, "report_metadata/org_name", "unknown")
    report_id = _text(root, "report_metadata/report_id")
    domain = _text(root, "policy_published/domain", "unknown")
    policy_p = _text(root, "policy_published/p", "none")

    records = []
    for rec in root.findall("record"):
        pe = rec.find("row/policy_evaluated")
        if pe is None:
            continue
        disposition = _text(pe, "disposition", "none")
        dkim = _text(pe, "dkim", "fail")
        spf = _text(pe, "spf", "fail")
        try:
            count = int(_text(rec, "row/count", "0") or "0")
        except ValueError:
            count = 0
        source_ip = _text(rec, "row/source_ip")
        header_from = _text(rec, "identifiers/header_from")
        is_failure = (dkim == "fail" and spf == "fail") or disposition in ("quarantine", "reject")
        records.append(dict(
            source_ip=source_ip, count=count, disposition=disposition,
            dkim=dkim, spf=spf, header_from=header_from, is_failure=is_failure,
        ))

    failures = [r for r in records if r["is_failure"]]
    return dict(
        org=org, report_id=report_id, domain=domain, policy_p=policy_p,
        records=records, failures=failures,
        total_messages=sum(r["count"] for r in records),
        failure_messages=sum(r["count"] for r in failures),
    )


# --------------------------------------------------------------------------- #
# claude triage
# --------------------------------------------------------------------------- #
def build_prompt(report):
    lines = [
        "You are triaging a DMARC aggregate report for the administrator of "
        f"the domain {report['domain']} (published policy p={report['policy_p']}).",
        f"Reporter: {report['org']}, report_id={report['report_id']}.",
        f"{report['failure_messages']} of {report['total_messages']} message(s) "
        "passed NEITHER SPF nor DKIM after alignment (or were quarantined/rejected).",
        "",
        "Failing sources (source_ip, message count, header From, receiver "
        "disposition, dkim/spf alignment result):",
    ]
    for r in report["failures"]:
        lines.append(
            f"  - {r['source_ip']} count={r['count']} from={r['header_from']} "
            f"disposition={r['disposition']} dkim={r['dkim']} spf={r['spf']}"
        )
    lines += [
        "",
        "Classify this report. Output the FIRST line as exactly one of:",
        "  VERDICT: BENIGN",
        "  VERDICT: SUSPICIOUS",
        "BENIGN = the failing mail is the domain's own or otherwise legitimate "
        "traffic that is merely unaligned/misconfigured (e.g. relayed through a "
        "provider like Google/Microsoft, mailing lists, forwarders), OR abuse "
        "that the published policy is already correctly quarantining/rejecting "
        "with nothing new for the admin to do.",
        "SUSPICIOUS = a new or unexpected source, a pattern that suggests active "
        "spoofing/abuse worth investigating, or a misconfiguration that is "
        "silently harming the domain's own legitimate delivery.",
        "Then a blank line, then 3-6 sentences: what the sources look like and a "
        "concrete recommended action. Plain text only.",
    ]
    return "\n".join(lines)


def analyze_with_claude(report):
    """Return (verdict, explanation_text). Fails safe to SUSPICIOUS."""
    prompt = build_prompt(report)
    try:
        proc = subprocess.run(
            [CONFIG["claude_bin"], "-p", prompt, "--output-format", "text"],
            capture_output=True, text=True, timeout=CONFIG["claude_timeout"],
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        log(f"claude analysis failed ({e}); failing safe to SUSPICIOUS")
        return "SUSPICIOUS", None
    if proc.returncode != 0:
        log(f"claude exited {proc.returncode} ({proc.stderr.strip()[:300]}); "
            "failing safe to SUSPICIOUS")
        return "SUSPICIOUS", None

    out = proc.stdout.strip()
    verdict = "SUSPICIOUS"  # default if the model omits a parseable verdict
    body = out
    first, _, rest = out.partition("\n")
    if first.upper().startswith("VERDICT:"):
        label = first.split(":", 1)[1].strip().upper()
        if label in ("BENIGN", "SUSPICIOUS"):
            verdict = label
        body = rest.strip()
    return verdict, (body or None)


# --------------------------------------------------------------------------- #
# notification
# --------------------------------------------------------------------------- #
def render_alert_body(report, analysis):
    lines = [
        f"DMARC report for {report['domain']} flagged {report['failure_messages']} "
        f"of {report['total_messages']} message(s) as failing.",
        f"Reporter: {report['org']}  (published policy p={report['policy_p']})",
        "",
        "Failing sources:",
    ]
    for r in report["failures"]:
        lines.append(
            f"  {r['source_ip']:<18} x{r['count']:<6} "
            f"from={r['header_from'] or '?'} disp={r['disposition']} "
            f"dkim={r['dkim']} spf={r['spf']}"
        )
    lines += ["", "--- claude analysis ---",
              analysis or "(analysis unavailable — see raw records above)",
              "",
              "Left unread and tagged DMARC-Issue in your inbox. This domain "
              f"will not re-alert for {CONFIG['cooldown_days']:g} day(s)."]
    return "\n".join(lines)


def send_mail(subject, body):
    if CONFIG["dry_run"]:
        log(f"[dry-run] would mail: {subject}")
        log(body)
        return
    msg = email.message.EmailMessage()
    msg["Subject"] = subject
    msg["From"] = CONFIG["mail_from"]
    msg["To"] = CONFIG["mail_to"]
    msg.set_content(body)
    ctx = ssl.create_default_context()
    with smtplib.SMTP(CONFIG["smtp_host"], CONFIG["smtp_port"], timeout=60) as s:
        s.starttls(context=ctx)
        s.login(CONFIG["smtp_user"], CONFIG["smtp_pass"])
        s.send_message(msg)


# --------------------------------------------------------------------------- #
# IMAP
# --------------------------------------------------------------------------- #
def imap_search(m):
    """Return UIDs of unread DMARC reports in the inbox.

    Prefer Gmail's raw search (precise); fall back to a portable IMAP query.
    """
    query = 'in:inbox is:unread (subject:"report domain" OR from:dmarc)'
    escaped = query.replace("\\", "\\\\").replace('"', '\\"')
    typ, data = m.uid("SEARCH", "X-GM-RAW", f'"{escaped}"')
    if typ != "OK":
        log("X-GM-RAW search failed, falling back to portable IMAP search")
        typ, data = m.uid("SEARCH", None, "UNSEEN", "OR", "FROM", "dmarc",
                          "SUBJECT", "report")
    if typ != "OK":
        die(f"IMAP search failed: {typ} {data}")
    return data[0].split() if data and data[0] else []


def imap_store(m, uid, flag_type, value):
    if CONFIG["dry_run"]:
        log(f"[dry-run] would STORE uid={uid.decode()} {flag_type} {value}")
        return
    typ, data = m.uid("STORE", uid, flag_type, value)
    if typ != "OK":
        log(f"WARN STORE {flag_type} {value} on uid={uid.decode()} -> {typ} {data}")


def mark_clean(m, uid):
    """Mark read and archive.

    `-X-GM-LABELS (\\Inbox)` looks like it succeeds (STORE returns OK) but is
    a silent no-op: Gmail excludes the currently-selected folder's own label
    from X-GM-LABELS, and a message can't have that label removed via STORE
    while its folder is selected. The message stays in the inbox.

    The working method: set \\Deleted and EXPUNGE while INBOX is selected.
    Gmail interprets that as "archive" (label removed, message kept in All
    Mail) rather than a real delete, per the account's Settings > Forwarding
    and POP/IMAP > "When a message is marked as deleted and expunged..."
    setting -- this only holds if that's set to its default, "Archive the
    message" (verified for this account before relying on it here).
    """
    imap_store(m, uid, "+FLAGS", r"(\Seen \Deleted)")
    if CONFIG["dry_run"]:
        log(f"[dry-run] would UID EXPUNGE uid={uid.decode()}")
        return
    typ, data = m.uid("EXPUNGE", uid)
    if typ != "OK":
        log(f"WARN UID EXPUNGE uid={uid.decode()} -> {typ} {data}")


def tag_issue(m, uid):
    """Tag DMARC-Issue; leave read/inbox state untouched (stays unread+visible)."""
    imap_store(m, uid, "+X-GM-LABELS", f"({CONFIG['issue_label']})")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def handle_message(m, uid, state):
    """Process one candidate email. Returns a one-word outcome for the summary."""
    typ, data = m.uid("FETCH", uid, "(RFC822)")
    if typ != "OK" or not data or not data[0]:
        log(f"WARN could not fetch uid={uid.decode()}")
        return "fetch-error"
    msg = email.message_from_bytes(data[0][1])
    msg_id = msg.get("Message-ID", uid.decode())
    subject = (msg.get("Subject") or "").replace("\n", " ")[:120]

    try:
        report = parse_report(report_xml_from_message(msg))
    except (ValueError, ET.ParseError) as e:
        log(f"UNPARSEABLE uid={uid.decode()} subject={subject!r}: {e}")
        key = f"parse-error:{msg_id}"
        if key not in state["processed"]:
            send_mail("[dmarc-check] could not parse a DMARC report",
                      f"Subject: {subject}\nMessage-ID: {msg_id}\nError: {e}\n\n"
                      "Left untouched in the inbox for manual review.")
            state["processed"][key] = "unparseable"
        return "unparseable"

    key = report["report_id"] or msg_id

    if not report["failures"]:
        log(f"CLEAN uid={uid.decode()} domain={report['domain']} "
            f"org={report['org']} msgs={report['total_messages']} -> read+archive")
        mark_clean(m, uid)
        return "clean"

    # Failing report. Reuse a prior verdict so an unread SUSPICIOUS report is
    # not re-analysed by claude on every daily run.
    verdict = state["processed"].get(key)
    reused = verdict is not None
    analysis = None
    if not reused:
        verdict, analysis = analyze_with_claude(report)
        state["processed"][key] = verdict

    log(f"{'PROBLEM' if verdict == 'SUSPICIOUS' else 'BENIGN'} "
        f"uid={uid.decode()} domain={report['domain']} org={report['org']} "
        f"failing={report['failure_messages']}/{report['total_messages']} "
        f"verdict={verdict}{' (reused)' if reused else ''}")

    if verdict == "BENIGN":
        mark_clean(m, uid)
        return "benign"

    # SUSPICIOUS: keep unread + in inbox, tag it, alert (per-domain cooldown).
    tag_issue(m, uid)
    if reused:
        return "suspicious-known"
    if in_cooldown(state, report["domain"]):
        log(f"  {report['domain']} in cooldown; tagged, not e-mailing")
        return "suspicious-cooldown"
    send_mail(f"[dmarc-check] {report['domain']} has suspicious DMARC failures",
              render_alert_body(report, analysis))
    start_cooldown(state, report["domain"])
    log(f"  alerted for {report['domain']}")
    return "suspicious"


def main():
    load_config()
    if CONFIG["dry_run"]:
        log("DRY RUN: no mailbox changes, no mail sent (claude still consulted)")
    state = load_state()

    m = imaplib.IMAP4_SSL(CONFIG["imap_host"], CONFIG["imap_port"])
    try:
        m.login(CONFIG["imap_user"], CONFIG["imap_pass"])
        m.select("INBOX")
        uids = imap_search(m)
        log(f"found {len(uids)} candidate report(s)")
        outcomes = {}
        for uid in uids:
            outcome = handle_message(m, uid, state)
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
        save_state(state)
        log("done: " + (", ".join(f"{k}={v}" for k, v in sorted(outcomes.items()))
                        or "nothing to do"))
    finally:
        try:
            m.logout()
        except Exception:
            pass


if __name__ == "__main__":
    main()
