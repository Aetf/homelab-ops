#!/usr/bin/env python3
"""Daily DMARC aggregate-report triage.

Division of labour with the mailbox:

  - A Gmail filter (gmailctl) labels every incoming aggregate report
    `DMARC/Reports` and skips the inbox. That label is the work queue: this
    job picks up the *unread* messages under it ($DMARC_REPORT_QUERY).
  - This job parses each report, decides whether it needs the admin, and
    mails a summary. The summary carries a `List-Id` header naming its tier;
    Gmail filters route on `list:` — a NOTICE is labelled and skips the inbox
    (stays unread), an ACTION is labelled and lands in the inbox.

Per report:

  - no failing records             -> mark read. No mail.
  - failing records                -> classify, mail a NOTICE or an ACTION
                                      summary, mark the report read.
  - unparseable                    -> ACTION mail once; the report stays
                                      unread under the label for a human.

A record fails when it passes neither SPF nor DKIM after alignment, or the
receiver quarantined/rejected it.

Classification has a deterministic floor and a model on top:

  - The senders inventory ($DMARC_SENDERS, JSON, per report domain) lists the
    authentication identities (DKIM d= / SPF domains) and networks that
    belong to the domain's own mail streams. A failing record that carries a
    passing result for one of those identities, or comes from one of those
    networks, is the domain's own mail failing DMARC: that is always ACTION.
    Everything else is "unrecognized" — by definition not ours.
  - `claude -p` receives the full per-record auth results, the per-record
    classification and the inventory notes, and returns ACTION or NOTICE plus
    a short explanation. It can raise a report to ACTION (e.g. unrecognized
    mail that the policy did NOT stop); it cannot lower the floor. A claude
    failure is ACTION: the triage itself is broken and needs fixing.

Unrecognized sources that the published policy already quarantined/rejected
are spoofing handled as designed; they are NOTICE, and neither the prompt nor
the mail ever proposes authorizing them (SPF include / DKIM key) — that would
hand the domain to whoever is spoofing it.

ACTION mail is rate-limited per domain ($DMARC_COOLDOWN_DAYS): within the
window a further ACTION verdict is mailed as a NOTICE that says so.

State ($STATE_DIR/state.json): `processed` {report key -> verdict} makes a
re-run after a partial failure (mail sent, flag not stored) not mail twice;
`cooldown` {domain -> epoch} is the ACTION rate limit.

Standard library only; runtime inputs are the env vars below, the mounted
senders inventory, a mounted claude credential, and the state dir.
"""

import email
import email.message
import email.utils
import gzip
import imaplib
import io
import ipaddress
import json
import os
import re
import smtplib
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone

ACTION = "ACTION"
NOTICE = "NOTICE"

# Gmail filters route on `list:<id>`; keep in sync with the gmailctl config.
LIST_IDS = {
    ACTION: "dmarc-check action <action.dmarc-check.invalid>",
    NOTICE: "dmarc-check notice <notice.dmarc-check.invalid>",
}


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
        # Gmail search selecting untriaged reports. The label is applied by
        # the gmailctl filter, which is the one place that defines what a
        # DMARC report is.
        report_query=env("DMARC_REPORT_QUERY", "label:DMARC/Reports is:unread"),
        action_label=env("DMARC_ACTION_LABEL", "DMARC/Action"),
        senders_path=env("DMARC_SENDERS", "/config/senders.json"),
        state_dir=env("STATE_DIR", "/state"),
        claude_bin=env("DMARC_CLAUDE_BIN", "claude"),
        claude_timeout=int(env("DMARC_CLAUDE_TIMEOUT", "180")),
        cooldown_days=float(env("DMARC_COOLDOWN_DAYS", "7")),
        # When set, mutate nothing and send nothing — just report what would
        # happen. claude is still consulted so its verdicts can be observed.
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


def cooldown_since(state, domain):
    """Epoch of the ACTION mail that opened the domain's window, or None."""
    ts = state["cooldown"].get(domain)
    if ts and (time.time() - ts) < CONFIG["cooldown_days"] * 86400:
        return ts
    return None


# --------------------------------------------------------------------------- #
# senders inventory
# --------------------------------------------------------------------------- #
def load_senders(path):
    """{report domain: {"auth_domains": {d: why}, "networks": [(net, why)], "notes": str}}.

    File format (JSON), per report domain:
      "own_auth_domains": {"<dkim d= or spf domain>": "<why it is ours>"}
      "own_networks":     {"<cidr>": "<why it is ours>"}
      "notes":            "<free text for the model: how the domain sends mail>"
    A missing file is not fatal: every source is then unrecognized.
    """
    try:
        with open(path) as f:
            raw = json.load(f)
    except FileNotFoundError:
        log(f"WARN senders inventory {path} not found; every source is unrecognized")
        return {}
    senders = {}
    for domain, spec in raw.items():
        senders[domain.lower()] = dict(
            auth_domains={d.lower(): why for d, why in spec.get("own_auth_domains", {}).items()},
            networks=[(ipaddress.ip_network(n, strict=False), why)
                      for n, why in spec.get("own_networks", {}).items()],
            notes=spec.get("notes", ""),
        )
    return senders


def own_match(record, inv):
    """Why this record belongs to the domain's own mail, or None if unrecognized."""
    if not inv:
        return None
    for kind in ("dkim_auth", "spf_auth"):
        for a in record[kind]:
            if a["result"] == "pass" and a["domain"] in inv["auth_domains"]:
                return (f"{kind.split('_')[0].upper()} pass for {a['domain']} "
                        f"({inv['auth_domains'][a['domain']]})")
    try:
        ip = ipaddress.ip_address(record["source_ip"])
    except ValueError:
        return None
    for net, why in inv["networks"]:
        if ip in net:
            return f"source in {net} ({why})"
    return None


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


def _auth_results(rec, kind, extra):
    out = []
    for node in rec.findall(f"auth_results/{kind}"):
        entry = dict(domain=_text(node, "domain").lower(), result=_text(node, "result", "none"))
        for field in extra:
            entry[field] = _text(node, field)
        out.append(entry)
    return out


def _date(epoch_text):
    try:
        return datetime.fromtimestamp(int(epoch_text), timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return "?"


def parse_report(xml_bytes):
    """Parse aggregate-report XML into a dict with per-record auth detail."""
    root = ET.fromstring(xml_bytes)
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
        records.append(dict(
            source_ip=_text(rec, "row/source_ip"),
            count=count,
            disposition=disposition,
            dkim=dkim,
            spf=spf,
            header_from=_text(rec, "identifiers/header_from").lower(),
            dkim_auth=_auth_results(rec, "dkim", ("selector",)),
            spf_auth=_auth_results(rec, "spf", ("scope",)),
            is_failure=(dkim == "fail" and spf == "fail")
            or disposition in ("quarantine", "reject"),
        ))

    failures = [r for r in records if r["is_failure"]]
    return dict(
        org=_text(root, "report_metadata/org_name", "unknown"),
        report_id=_text(root, "report_metadata/report_id"),
        begin=_date(_text(root, "report_metadata/date_range/begin")),
        end=_date(_text(root, "report_metadata/date_range/end")),
        domain=_text(root, "policy_published/domain", "unknown").lower(),
        policy_p=_text(root, "policy_published/p", "none"),
        records=records,
        failures=failures,
        total_messages=sum(r["count"] for r in records),
        failure_messages=sum(r["count"] for r in failures),
    )


def classify_records(report, senders):
    """Annotate each failing record with `own` (reason str or None); return floor verdict."""
    inv = senders.get(report["domain"])
    for r in report["failures"]:
        r["own"] = own_match(r, inv)
    return ACTION if any(r["own"] for r in report["failures"]) else NOTICE


def describe_record(r):
    dkim = ", ".join(
        f"d={a['domain'] or '?'} s={a.get('selector') or '?'} {a['result']}" for a in r["dkim_auth"]
    ) or "no signature"
    spf = ", ".join(f"{a['domain'] or '?'} {a['result']}" for a in r["spf_auth"]) or "none"
    who = f"OWN ({r['own']})" if r.get("own") else "UNRECOGNIZED"
    return (f"{r['source_ip']} x{r['count']} from={r['header_from'] or '?'} "
            f"disposition={r['disposition']} aligned dkim={r['dkim']} spf={r['spf']}\n"
            f"      raw DKIM: {dkim}\n"
            f"      raw SPF:  {spf}\n"
            f"      source:   {who}")


# --------------------------------------------------------------------------- #
# claude triage
# --------------------------------------------------------------------------- #
def build_prompt(report, floor, senders):
    inv = senders.get(report["domain"])
    lines = [
        "You are triaging a DMARC aggregate report for the administrator of "
        f"{report['domain']} (published policy p={report['policy_p']}).",
        f"Reporter: {report['org']}, report_id={report['report_id']}, "
        f"period {report['begin']}..{report['end']}.",
        "",
        "What the administrator knows about this domain's own mail:",
    ]
    if inv:
        lines.append(f"  {inv['notes']}")
        lines.append("  Authentication identities that are ours: "
                     + ("; ".join(f"{d} ({why})" for d, why in inv["auth_domains"].items())
                        or "none listed"))
        lines.append("  Networks that are ours: "
                     + ("; ".join(f"{n} ({why})" for n, why in inv["networks"])
                        or "none listed"))
        lines.append("  This inventory is complete: a source that matches none of it is "
                     "NOT one of the domain's mail streams.")
    else:
        lines.append("  (no inventory for this domain — you cannot tell own mail from "
                     "third-party mail; say so)")
    lines += [
        "",
        f"{report['failure_messages']} of {report['total_messages']} message(s) failed "
        "DMARC (neither SPF nor DKIM aligned, or quarantined/rejected). Failing "
        "records, with the receiver's raw DKIM/SPF results and whether the source "
        "matched the inventory:",
    ]
    lines += [f"  - {describe_record(r)}" for r in report["failures"]]
    lines += [
        "",
        "Decide whether the administrator has to act.",
        "ACTION = something the administrator must change or investigate: the domain's "
        "own mail is failing (any record marked OWN — this is already decided and "
        "you must answer ACTION), unrecognized mail using the domain was NOT stopped "
        "by the policy (disposition none) in a way that looks like abuse, or a "
        "volume/pattern that warrants tightening the policy.",
        "NOTICE = nothing to do: unrecognized sources that the published policy "
        "already quarantined or rejected (spoofing handled as designed), or "
        "forwarding/mailing-list artefacts with no fix on our side.",
        "Never recommend authorizing an unrecognized source (adding it to SPF, "
        "publishing a DKIM key for it, routing mail through it). Do not guess that "
        "an unrecognized source is the domain's own web host or service: the "
        "inventory above is authoritative. Use the raw DKIM d= domain to say whose "
        "infrastructure sent it.",
        f"The deterministic pre-check says: {floor}.",
        "",
        "Output format, plain text only:",
        "  line 1: VERDICT: ACTION   or   VERDICT: NOTICE",
        "  line 2: SUMMARY: <one line, at most 80 characters>",
        "  line 3: empty",
        "  then 2-5 sentences: what the failing sources are and, for ACTION, the "
        "concrete action.",
    ]
    return "\n".join(lines)


def parse_claude_output(out):
    """-> (verdict or None, summary or None, body)."""
    verdict = summary = None
    body_lines = []
    for line in out.strip().splitlines():
        m = re.match(r"\s*VERDICT:\s*(\w+)", line, re.I)
        if verdict is None and m:
            v = m.group(1).upper()
            verdict = v if v in (ACTION, NOTICE) else None
            continue
        m = re.match(r"\s*SUMMARY:\s*(.*)", line, re.I)
        if summary is None and m:
            summary = m.group(1).strip()[:100] or None
            continue
        body_lines.append(line)
    return verdict, summary, "\n".join(body_lines).strip()


def analyze_with_claude(report, floor, senders):
    """Return (verdict, summary, explanation). Any failure -> ACTION."""
    prompt = build_prompt(report, floor, senders)
    try:
        proc = subprocess.run(
            [CONFIG["claude_bin"], "-p", prompt, "--output-format", "text"],
            capture_output=True, text=True, timeout=CONFIG["claude_timeout"],
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        log(f"claude analysis failed ({e}); verdict ACTION")
        return ACTION, "triage model unavailable", f"claude could not run: {e}"
    if proc.returncode != 0:
        err = proc.stderr.strip()[:300]
        log(f"claude exited {proc.returncode} ({err}); verdict ACTION")
        return ACTION, "triage model unavailable", f"claude exited {proc.returncode}: {err}"
    verdict, summary, body = parse_claude_output(proc.stdout)
    if verdict is None:
        log("claude output has no parseable verdict; verdict ACTION")
        return ACTION, "triage model gave no verdict", proc.stdout.strip()
    return verdict, summary, body


# --------------------------------------------------------------------------- #
# notification
# --------------------------------------------------------------------------- #
def render_body(report, verdict, floor, analysis, cooled_since):
    lines = [
        f"DMARC report for {report['domain']} ({report['org']}, "
        f"{report['begin']}..{report['end']}, policy p={report['policy_p']}):",
        f"{report['failure_messages']} of {report['total_messages']} message(s) failed.",
        f"Verdict: {verdict} (inventory pre-check: {floor}).",
    ]
    if cooled_since:
        when = datetime.fromtimestamp(cooled_since, timezone.utc).strftime("%Y-%m-%d")
        lines.append(f"Already raised as ACTION on {when}; within the "
                     f"{CONFIG['cooldown_days']:g}-day window this is filed as a notice.")
    lines += ["", "Failing records:"]
    lines += [f"  {describe_record(r)}" for r in report["failures"]]
    lines += ["", "--- analysis ---", analysis or "(none)",
              "", f"report_id={report['report_id']}"]
    return "\n".join(lines)


def send_mail(tier, subject, body):
    if CONFIG["dry_run"]:
        log(f"[dry-run] would mail ({tier}): {subject}")
        log(body)
        return
    msg = email.message.EmailMessage()
    msg["Subject"] = subject
    msg["From"] = CONFIG["mail_from"]
    msg["To"] = CONFIG["mail_to"]
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain="dmarc-check.invalid")
    msg["List-Id"] = LIST_IDS[tier]
    msg.set_content(body)
    ctx = ssl.create_default_context()
    with smtplib.SMTP(CONFIG["smtp_host"], CONFIG["smtp_port"], timeout=60) as s:
        s.starttls(context=ctx)
        s.login(CONFIG["smtp_user"], CONFIG["smtp_pass"])
        s.send_message(msg)


# --------------------------------------------------------------------------- #
# IMAP
# --------------------------------------------------------------------------- #
def select_all_mail(m):
    """SELECT the \\All folder (its name is locale-dependent, so find it by flag).

    Labels are changed from All Mail because Gmail silently ignores a STORE
    that removes the label of the currently selected folder.
    """
    typ, boxes = m.list()
    if typ != "OK":
        die(f"IMAP LIST failed: {typ} {boxes}")
    for line in boxes:
        if rb"\All" in line:
            name = re.search(rb'"([^"]+)"\s*$', line) or re.search(rb"(\S+)\s*$", line)
            typ, data = m.select(b'"' + name.group(1) + b'"')
            if typ != "OK":
                die(f"SELECT All Mail failed: {typ} {data}")
            return
    die("no \\All folder in IMAP LIST")


def imap_search(m):
    q = CONFIG["report_query"].replace("\\", "\\\\").replace('"', '\\"')
    typ, data = m.uid("SEARCH", "X-GM-RAW", f'"{q}"')
    if typ != "OK":
        die(f"IMAP search failed: {typ} {data}")
    return data[0].split() if data and data[0] else []


def imap_store(m, uid, op, value):
    if CONFIG["dry_run"]:
        log(f"[dry-run] would STORE uid={uid.decode()} {op} {value}")
        return
    typ, data = m.uid("STORE", uid, op, value)
    if typ != "OK":
        raise RuntimeError(f"STORE {op} {value} on uid={uid.decode()} -> {typ} {data}")


def file_report(m, uid, verdict):
    """Mark the report triaged: read, out of the inbox, ACTION ones labelled."""
    imap_store(m, uid, "+FLAGS", r"(\Seen)")
    imap_store(m, uid, "-X-GM-LABELS", r"(\Inbox)")
    if verdict == ACTION:
        imap_store(m, uid, "+X-GM-LABELS", f'("{CONFIG["action_label"]}")')


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def handle_message(m, uid, state, senders):
    """Process one report email. Returns a one-word outcome for the summary."""
    typ, data = m.uid("FETCH", uid, "(BODY.PEEK[])")
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
            send_mail(ACTION, "[dmarc-check] ACTION: could not parse a DMARC report",
                      f"Subject: {subject}\nMessage-ID: {msg_id}\nError: {e}\n\n"
                      f"Left unread under {CONFIG['report_query']!r}.")
            state["processed"][key] = "unparseable"
        return "unparseable"

    key = report["report_id"] or msg_id
    if key in state["processed"]:
        # Summary already mailed on an earlier run that stopped before the
        # report was filed; finish filing without mailing again.
        file_report(m, uid, state["processed"][key])
        log(f"REFILED uid={uid.decode()} report_id={key} verdict={state['processed'][key]}")
        return "refiled"

    if not report["failures"]:
        log(f"CLEAN uid={uid.decode()} domain={report['domain']} "
            f"org={report['org']} msgs={report['total_messages']}")
        file_report(m, uid, NOTICE)
        return "clean"

    floor = classify_records(report, senders)
    verdict, summary, analysis = analyze_with_claude(report, floor, senders)
    if floor == ACTION:
        verdict = ACTION

    cooled_since = cooldown_since(state, report["domain"]) if verdict == ACTION else None
    tier = NOTICE if cooled_since else verdict
    summary = summary or f"{report['failure_messages']} failing message(s)"
    label = ("ACTION" if tier == ACTION
             else "notice (ACTION already raised)" if cooled_since else "notice")
    send_mail(tier, f"[dmarc-check] {label}: {report['domain']} — {summary}",
              render_body(report, verdict, floor, analysis, cooled_since))
    if tier == ACTION:
        state["cooldown"][report["domain"]] = int(time.time())
    state["processed"][key] = verdict
    file_report(m, uid, verdict)

    log(f"{verdict} uid={uid.decode()} domain={report['domain']} org={report['org']} "
        f"failing={report['failure_messages']}/{report['total_messages']} floor={floor} "
        f"mailed={tier}")
    return verdict.lower() + ("-cooldown" if cooled_since else "")


def main():
    load_config()
    if CONFIG["dry_run"]:
        log("DRY RUN: no mailbox changes, no mail sent (claude still consulted)")
    senders = load_senders(CONFIG["senders_path"])
    state = load_state()

    log(f"connecting to {CONFIG['imap_host']} to search {CONFIG['report_query']!r}")
    m = imaplib.IMAP4_SSL(CONFIG["imap_host"], CONFIG["imap_port"])
    errors = 0
    try:
        m.login(CONFIG["imap_user"], CONFIG["imap_pass"])
        select_all_mail(m)
        uids = imap_search(m)
        log(f"found {len(uids)} untriaged report(s)")
        outcomes = {}
        for uid in uids:
            log(f"triaging uid={uid.decode()}")
            try:
                outcome = handle_message(m, uid, state, senders)
            except (OSError, smtplib.SMTPException, imaplib.IMAP4.error, RuntimeError) as e:
                # Leave the report unread so tomorrow's run retries it.
                log(f"ERROR uid={uid.decode()}: {e}")
                outcome, errors = "error", errors + 1
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
            save_state(state)
        log("done: " + (", ".join(f"{k}={v}" for k, v in sorted(outcomes.items()))
                        or "nothing to do"))
    finally:
        try:
            m.logout()
        except Exception:
            pass
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
