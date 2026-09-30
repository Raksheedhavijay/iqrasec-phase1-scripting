#!/usr/bin/env python3
"""
IOCX - IOC Extractor & Threat Report Generator
IqraSec Academy | Cybersecurity Scripting & Automation Internship | Phase 1

Pulls Indicators of Compromise (IOCs) out of any text: incident reports, logs,
phishing e-mails, threat-intel blogs, malware sandbox output, etc.

Extracts : IPv4, IPv6, URLs, domains, e-mails, MD5 / SHA1 / SHA256 / SHA512
           hashes, CVE IDs, MITRE ATT&CK technique IDs and suspicious file names.
Handles  : "defanged" indicators (hxxp://evil[.]com, user[@]bad[.]org) by
           re-fanging them before matching, and can defang results on output.
Extras   : private-IP filtering, allow-lists, risk tagging (suspicious TLD,
           URL shorteners, punycode, IP-based URLs...), SHA-256 of every input
           file for evidence tracking, and table / JSON / CSV / TXT /
           Markdown / HTML report output.

Only analyse data you are authorised to handle.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse

__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Configuration / constants
# --------------------------------------------------------------------------- #

# Order here is the order used in reports.
IOC_TYPES: List[str] = [
    "ipv4", "ipv6", "url", "domain", "email",
    "md5", "sha1", "sha256", "sha512",
    "cve", "mitre", "filename",
]

# Domain matches are only kept when the TLD is real. This stops file names such
# as "setup.py" or "run.sh" from being reported as domains. Ambiguous TLDs that
# are also common file extensions (py, sh, pl, rs, md, zip, mov) are left out.
VALID_TLDS: Set[str] = set("""
com net org info biz edu gov mil int io co xyz top site online tech app dev cloud
shop store club live link click work buzz icu cyou rest monster space fun vip pro
name mobi tk ml ga cf gq ws cc tv me ly to su in us uk de fr ru cn jp br au ca nl
it es se no fi ch at be dk ir tr ua kr id za mx ar cz ro hu gr pt il hk tw sg my
th vn pk bd ng ke eg ae sa nz ie by kz lt lv ee bg sk si hr
""".split())

SUSPICIOUS_TLDS: Set[str] = {
    "top", "xyz", "click", "work", "buzz", "icu", "cyou", "rest", "monster",
    "tk", "ml", "ga", "cf", "gq", "su", "ws",
}
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly",
}
EXECUTABLE_EXT = ("exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "jar", "msi", "hta", "lnk")
MACRO_DOC_EXT = ("docm", "xlsm", "pptm", "iso", "img")
FILE_EXT_PATTERN = "|".join(EXECUTABLE_EXT + MACRO_DOC_EXT)

# Rules that turn "defanged" text back into normal text (order matters).
REFANG_RULES: List[Tuple["re.Pattern[str]", str]] = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.I), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.I), "@"),
]

# Regular expressions -------------------------------------------------------- #
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\d|\.\d)")
IPV6_RE = re.compile(r"(?<![:\w])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![:\w])")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\]\)}]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
MITRE_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
FILENAME_RE = re.compile(rf"(?<![\w.-])[\w\-]+(?:\.[\w\-]+)*\.(?:{FILE_EXT_PATTERN})\b", re.I)
HASH_RES = {
    "md5": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])"),
    "sha1": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"),
    "sha256": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"),
    "sha512": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{128}(?![A-Fa-f0-9])"),
}

TEXT_EXTENSIONS_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".7z", ".mp4", ".mp3", ".pyc", ".so"}


# --------------------------------------------------------------------------- #
# Terminal colours
# --------------------------------------------------------------------------- #
class Colors:
    """ANSI colour codes; all empty strings when colour is disabled."""

    def __init__(self, enabled: bool) -> None:
        on = lambda code: f"\033[{code}m" if enabled else ""  # noqa: E731
        self.red, self.green, self.yellow = on(31), on(32), on(33)
        self.blue, self.cyan, self.magenta = on(34), on(36), on(35)
        self.bold, self.dim, self.reset = on(1), on(2), on(0)


# --------------------------------------------------------------------------- #
# Normalisation helpers
# --------------------------------------------------------------------------- #
def refang(text: str) -> str:
    """Convert defanged indicators (hxxp, [.], [@] ...) back to normal form."""
    for pattern, replacement in REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def defang_value(ioc_type: str, value: str) -> str:
    """Make an indicator safe to paste into chats/tickets (no clickable links)."""
    if ioc_type not in ("ipv4", "ipv6", "domain", "url", "email"):
        return value
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    value = re.sub(r"^ftp", "fxp", value, flags=re.I)
    value = value.replace(".", "[.]")
    return value.replace("@", "[@]")


# --------------------------------------------------------------------------- #
# Extraction functions - each returns an iterator of raw string matches
# --------------------------------------------------------------------------- #
def extract_ipv4(text: str) -> Iterator[str]:
    for m in IPV4_RE.finditer(text):
        yield m.group(0)


def extract_ipv6(text: str) -> Iterator[str]:
    for m in IPV6_RE.finditer(text):
        candidate = m.group(0)
        if len(candidate) < 4:
            continue
        try:
            yield str(ipaddress.IPv6Address(candidate))
        except ValueError:
            continue  # things like timestamps (12:30:45) are not IPv6


def extract_urls(text: str) -> Iterator[str]:
    for m in URL_RE.finditer(text):
        yield m.group(0).rstrip(".,;:!?)]}'\"")


def extract_domains(text: str) -> Iterator[str]:
    for m in DOMAIN_RE.finditer(text.lower()):
        domain = m.group(0)
        if domain.rsplit(".", 1)[1] in VALID_TLDS:
            yield domain


def extract_emails(text: str) -> Iterator[str]:
    for m in EMAIL_RE.finditer(text):
        email = m.group(0).lower()
        if email.rsplit(".", 1)[1] in VALID_TLDS:
            yield email


def extract_hashes(text: str, kind: str) -> Iterator[str]:
    for m in HASH_RES[kind].finditer(text):
        value = m.group(0).lower()
        if value.isdigit():      # long numeric IDs are not hashes
            continue
        yield value


def extract_cves(text: str) -> Iterator[str]:
    for m in CVE_RE.finditer(text):
        yield m.group(0).upper()


def extract_mitre(text: str) -> Iterator[str]:
    for m in MITRE_RE.finditer(text):
        yield m.group(0)


def extract_filenames(text: str) -> Iterator[str]:
    for m in FILENAME_RE.finditer(text):
        yield m.group(0).lower()


EXTRACTORS = {
    "ipv4": extract_ipv4,
    "ipv6": extract_ipv6,
    "url": extract_urls,
    "domain": extract_domains,
    "email": extract_emails,
    "md5": lambda t: extract_hashes(t, "md5"),
    "sha1": lambda t: extract_hashes(t, "sha1"),
    "sha256": lambda t: extract_hashes(t, "sha256"),
    "sha512": lambda t: extract_hashes(t, "sha512"),
    "cve": extract_cves,
    "mitre": extract_mitre,
    "filename": extract_filenames,
}


# --------------------------------------------------------------------------- #
# Filtering & enrichment
# --------------------------------------------------------------------------- #
def is_non_routable_ip(value: str) -> bool:
    """True for private, loopback, link-local, multicast, reserved addresses."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def load_allowlist(path: str) -> Set[str]:
    """Read one indicator per line (blank lines and # comments ignored)."""
    allow: Set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                allow.add(line)
    return allow


def is_allowlisted(ioc_type: str, value: str, allowlist: Set[str]) -> bool:
    """Match exact values, or a domain / sub-domain of an allow-listed domain."""
    if not allowlist:
        return False
    v = value.lower()
    if ioc_type == "url":
        v = (urlparse(value).hostname or v).lower()
    elif ioc_type == "email":
        if v in allowlist:
            return True
        v = v.rsplit("@", 1)[-1]          # judge an address by its domain
    if v in allowlist:
        return True
    return any(v.endswith("." + a) for a in allowlist)


def annotate(ioc_type: str, value: str) -> List[str]:
    """Return short risk tags that help an analyst prioritise."""
    tags: List[str] = []
    if ioc_type == "domain":
        labels = value.split(".")
        if labels[-1] in SUSPICIOUS_TLDS:
            tags.append("suspicious-tld")
        if any(label.startswith("xn--") for label in labels):
            tags.append("punycode")
        if value in URL_SHORTENERS:
            tags.append("url-shortener")
        if len(labels) >= 5:
            tags.append("deep-subdomain")
    elif ioc_type == "url":
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        try:
            ipaddress.ip_address(host)
            tags.append("ip-in-url")
        except ValueError:
            if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
                tags.append("suspicious-tld")
            if host in URL_SHORTENERS:
                tags.append("url-shortener")
        if parsed.port not in (None, 80, 443):
            tags.append("non-standard-port")
        if parsed.path.lower().endswith(tuple("." + e for e in EXECUTABLE_EXT)):
            tags.append("executable-download")
    elif ioc_type == "ipv4" and is_non_routable_ip(value):
        tags.append("non-routable")
    elif ioc_type == "filename":
        ext = value.rsplit(".", 1)[-1]
        tags.append("executable" if ext in EXECUTABLE_EXT else "macro/disk-image")
    return tags


# --------------------------------------------------------------------------- #
# IOC storage
# --------------------------------------------------------------------------- #
class IOCStore:
    """Holds unique indicators, how often each was seen and where."""

    def __init__(self) -> None:
        self.counts: Dict[str, Counter] = {t: Counter() for t in IOC_TYPES}
        self.sources: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        self.filtered = 0   # indicators dropped by private-IP / allow-list filters

    def add(self, ioc_type: str, value: str, source: str) -> None:
        self.counts[ioc_type][value] += 1
        self.sources[(ioc_type, value)].add(source)

    def unique(self, ioc_type: str) -> int:
        return len(self.counts[ioc_type])

    def total_unique(self) -> int:
        return sum(self.unique(t) for t in IOC_TYPES)

    def rows(self, ioc_type: str, min_count: int = 1) -> List[Tuple[str, int, List[str]]]:
        """(value, count, sources) sorted by frequency then alphabetically."""
        items = [(v, c) for v, c in self.counts[ioc_type].items() if c >= min_count]
        items.sort(key=lambda x: (-x[1], x[0]))
        return [(v, c, sorted(self.sources[(ioc_type, v)])) for v, c in items]


def process_text(text: str, source: str, store: IOCStore, types: List[str],
                 include_private: bool, allowlist: Set[str]) -> None:
    """Run every selected extractor over `text` and store the results."""
    text = refang(text)
    for ioc_type in types:
        for value in EXTRACTORS[ioc_type](text):
            if ioc_type in ("ipv4", "ipv6") and not include_private and is_non_routable_ip(value):
                store.filtered += 1
                continue
            if is_allowlisted(ioc_type, value, allowlist):
                store.filtered += 1
                continue
            store.add(ioc_type, value, source)


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #
def sha256_file(path: Path) -> str:
    """SHA-256 of a file, read in chunks (works for large files)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text_file(path: Path) -> str:
    """Read a file as text, handling UTF-16 (common in Windows logs)."""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def collect_files(inputs: List[str], recursive: bool, max_size: int) -> Tuple[List[Path], List[str]]:
    """Expand the CLI inputs into a list of readable files + warning messages."""
    files: List[Path] = []
    warnings: List[str] = []
    for item in inputs:
        p = Path(item)
        if not p.exists():
            warnings.append(f"not found: {item}")
        elif p.is_dir():
            if not recursive:
                warnings.append(f"'{item}' is a directory - use -r to scan it recursively")
                continue
            for root, dirs, names in os.walk(p):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for name in sorted(names):
                    fp = Path(root) / name
                    if fp.suffix.lower() not in TEXT_EXTENSIONS_SKIP:
                        files.append(fp)
        else:
            files.append(p)

    usable: List[Path] = []
    for fp in files:
        try:
            if fp.stat().st_size > max_size:
                warnings.append(f"skipped (larger than limit): {fp}")
            else:
                usable.append(fp)
        except OSError as exc:
            warnings.append(f"cannot access {fp}: {exc.strerror}")
    return usable, warnings


# --------------------------------------------------------------------------- #
# Result building & renderers
# --------------------------------------------------------------------------- #
def build_result(store: IOCStore, types: List[str], sources: List[Dict[str, object]],
                 defang: bool, min_count: int) -> Dict[str, object]:
    """Turn the store into a plain dict used by every output format."""
    iocs: Dict[str, List[Dict[str, object]]] = {}
    for t in types:
        entries = []
        for value, count, srcs in store.rows(t, min_count):
            entries.append({
                "value": defang_value(t, value) if defang else value,
                "count": count,
                "sources": srcs,
                "notes": annotate(t, value),
            })
        if entries:
            iocs[t] = entries
    return {
        "tool": "IOCX",
        "version": __version__,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "defanged": defang,
        "sources": sources,
        "summary": {t: len(v) for t, v in iocs.items()},
        "total_unique": sum(len(v) for v in iocs.values()),
        "filtered_out": store.filtered,
        "iocs": iocs,
    }


def render_table(result: Dict[str, object], colors: Colors) -> str:
    c = colors
    out = io.StringIO()
    out.write(f"{c.bold}{c.cyan}")
    out.write("  ___ ___   ____ __  __\n |_ _/ _ \\ / ___|\\ \\/ /\n  | | | | | |     \\  / \n")
    out.write("  | | |_| | |___  /  \\ \n |___\\___/ \\____|/_/\\_\\")
    out.write(f"  v{result['version']}{c.reset}\n")
    out.write(f"{c.dim} IOC Extractor & Threat Report Generator | IqraSec Academy{c.reset}\n\n")

    srcs = result["sources"]
    out.write(f"{c.bold}Sources analysed:{c.reset} {len(srcs)}\n")
    for s in srcs:  # type: ignore[union-attr]
        sha = f"  sha256:{str(s['sha256'])[:16]}..." if s.get("sha256") else ""
        out.write(f"  - {s['name']}{c.dim}{sha}{c.reset}\n")

    out.write(f"\n{c.bold}Summary{c.reset}  (unique indicators: {c.bold}{result['total_unique']}{c.reset}"
              f", filtered out: {result['filtered_out']})\n")
    summary = result["summary"]
    for t, n in summary.items():  # type: ignore[union-attr]
        bar = "#" * min(n, 40)
        out.write(f"  {t:<9} {n:>4}  {c.green}{bar}{c.reset}\n")

    if not summary:
        out.write(f"\n{c.yellow}No indicators found.{c.reset}\n")
        return out.getvalue()

    for t, entries in result["iocs"].items():  # type: ignore[union-attr]
        out.write(f"\n{c.bold}{c.cyan}== {t.upper()} ({len(entries)}) =={c.reset}\n")
        width = min(max(len(str(e["value"])) for e in entries), 90)
        for e in entries:
            notes = ",".join(e["notes"])
            flag = f"  {c.red}[{notes}]{c.reset}" if notes else ""
            out.write(f"  {str(e['value']):<{width}}  x{e['count']:<3}{flag}\n")
    return out.getvalue()


def render_json(result: Dict[str, object]) -> str:
    return json.dumps(result, indent=2, ensure_ascii=False) + "\n"


def render_csv(result: Dict[str, object]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "count", "sources", "notes"])
    for t, entries in result["iocs"].items():  # type: ignore[union-attr]
        for e in entries:
            writer.writerow([t, e["value"], e["count"], ";".join(e["sources"]), ";".join(e["notes"])])
    return buf.getvalue()


def render_txt(result: Dict[str, object]) -> str:
    """Plain deduplicated list grouped by type - easy to feed into other tools."""
    lines: List[str] = []
    for t, entries in result["iocs"].items():  # type: ignore[union-attr]
        lines.append(f"# {t}")
        lines.extend(str(e["value"]) for e in entries)
        lines.append("")
    return "\n".join(lines)


def render_markdown(result: Dict[str, object]) -> str:
    """A ready-to-share incident/threat report."""
    md: List[str] = [
        "# IOC Extraction Report", "",
        f"- **Generated (UTC):** {result['generated_utc']}",
        f"- **Tool:** IOCX v{result['version']}",
        f"- **Unique indicators:** {result['total_unique']}",
        f"- **Filtered out (private/allow-listed):** {result['filtered_out']}",
        f"- **Defanged output:** {'yes' if result['defanged'] else 'no'}", "",
        "## Sources", "", "| Source | SHA-256 |", "|---|---|",
    ]
    for s in result["sources"]:  # type: ignore[union-attr]
        md.append(f"| {s['name']} | `{s.get('sha256') or 'n/a'}` |")
    md += ["", "## Summary", "", "| Type | Unique |", "|---|---|"]
    for t, n in result["summary"].items():  # type: ignore[union-attr]
        md.append(f"| {t} | {n} |")

    flagged = [(t, e) for t, es in result["iocs"].items() for e in es if e["notes"]]  # type: ignore[union-attr]
    if flagged:
        md += ["", "## High-attention indicators", "", "| Type | Indicator | Why |", "|---|---|---|"]
        for t, e in flagged:
            md.append(f"| {t} | `{e['value']}` | {', '.join(e['notes'])} |")

    for t, entries in result["iocs"].items():  # type: ignore[union-attr]
        md += ["", f"## {t.upper()} ({len(entries)})", "", "| Indicator | Seen | Notes |", "|---|---|---|"]
        for e in entries:
            md.append(f"| `{e['value']}` | {e['count']} | {', '.join(e['notes'])} |")
    return "\n".join(md) + "\n"


def render_html(result: Dict[str, object]) -> str:
    """Self-contained HTML report (no external assets)."""
    esc = html.escape
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<title>IOC Extraction Report</title><style>",
        "body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1b1f24}",
        "h1{border-bottom:3px solid #0a7d5a;padding-bottom:.4rem}h2{margin-top:2rem;color:#0a7d5a}",
        "table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border:1px solid #d0d7de;padding:.35rem .6rem;text-align:left}",
        "th{background:#f0f4f2}code{font-size:.9em}.tag{background:#fde2e1;color:#a4161a;border-radius:4px;padding:1px 6px;margin-right:4px;font-size:.8em}",
        ".card{display:inline-block;background:#f0f4f2;border-radius:8px;padding:.6rem 1rem;margin:.2rem}",
        "</style></head><body><h1>IOC Extraction Report</h1>",
        f"<p>Generated <b>{esc(str(result['generated_utc']))} UTC</b> by IOCX v{esc(str(result['version']))}. "
        f"Unique indicators: <b>{result['total_unique']}</b>. Filtered out: {result['filtered_out']}.</p>",
        "<h2>Summary</h2><div>",
    ]
    for t, n in result["summary"].items():  # type: ignore[union-attr]
        parts.append(f"<span class='card'><b>{n}</b> {esc(t)}</span>")
    parts.append("</div><h2>Sources</h2><table><tr><th>File</th><th>SHA-256</th></tr>")
    for s in result["sources"]:  # type: ignore[union-attr]
        parts.append(f"<tr><td>{esc(str(s['name']))}</td><td><code>{esc(str(s.get('sha256') or 'n/a'))}</code></td></tr>")
    parts.append("</table>")
    for t, entries in result["iocs"].items():  # type: ignore[union-attr]
        parts.append(f"<h2>{esc(t.upper())} ({len(entries)})</h2><table><tr><th>Indicator</th><th>Seen</th><th>Notes</th></tr>")
        for e in entries:
            tags = "".join(f"<span class='tag'>{esc(n)}</span>" for n in e["notes"])
            parts.append(f"<tr><td><code>{esc(str(e['value']))}</code></td><td>{e['count']}</td><td>{tags}</td></tr>")
        parts.append("</table>")
    parts.append("</body></html>")
    return "".join(parts)


def render(fmt: str, result: Dict[str, object], colors: Colors) -> str:
    """Dispatch to the chosen renderer."""
    if fmt == "table":
        return render_table(result, colors)
    return {"json": render_json, "csv": render_csv, "txt": render_txt,
            "md": render_markdown, "html": render_html}[fmt](result)


# --------------------------------------------------------------------------- #
# Command line interface
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tool.py",
        description="IOCX - extract Indicators of Compromise (IPs, domains, URLs, hashes, "
                    "e-mails, CVEs, ATT&CK IDs) from files, folders, stdin or text.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python3 tool.py report.txt                      # analyse a file
  python3 tool.py logs/ -r -f json -o iocs.json   # scan a folder, save JSON
  python3 tool.py -t "beacon to hxxp://evil[.]xyz/a.exe from 203.0.113.9"
  cat mail.eml | python3 tool.py --defang         # read stdin, defang output
  python3 tool.py incident.txt -f md -o report.md # Markdown threat report
  python3 tool.py a.log --types ipv4,domain --allowlist safe.txt

exit codes: 0 = IOCs found, 1 = no IOCs found, 2 = error""",
    )
    parser.add_argument("inputs", nargs="*", help="files or directories to analyse (omit to read stdin)")
    parser.add_argument("-t", "--text", help="analyse this text string directly")
    parser.add_argument("-T", "--types", default="all",
                        help=f"comma-separated types to extract (default: all). Choices: {', '.join(IOC_TYPES)}")
    parser.add_argument("-f", "--format", default="table", choices=["table", "json", "csv", "txt", "md", "html"],
                        help="output format (default: table)")
    parser.add_argument("-o", "--output", help="write the result to this file instead of the screen")
    parser.add_argument("-r", "--recursive", action="store_true", help="scan directories recursively")
    parser.add_argument("--defang", action="store_true", help="defang IPs/domains/URLs/e-mails in the output")
    parser.add_argument("--include-private", action="store_true",
                        help="keep private/loopback/reserved IP addresses (dropped by default)")
    parser.add_argument("--allowlist", metavar="FILE", help="file of benign domains/IPs/hashes to ignore")
    parser.add_argument("--min-count", type=int, default=1, metavar="N", help="only show indicators seen at least N times")
    parser.add_argument("--max-size", type=int, default=50, metavar="MB", help="skip files larger than MB (default: 50)")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--color", action="store_true", help="force colour even when piped")
    parser.add_argument("-V", "--version", action="version", version=f"IOCX {__version__}")
    return parser


def parse_types(value: str) -> List[str]:
    """Validate the --types argument and return the list of type names."""
    if value.strip().lower() == "all":
        return list(IOC_TYPES)
    chosen = [v.strip().lower() for v in value.split(",") if v.strip()]
    bad = [v for v in chosen if v not in IOC_TYPES]
    if bad:
        raise ValueError(f"unknown type(s): {', '.join(bad)} (valid: {', '.join(IOC_TYPES)})")
    return [t for t in IOC_TYPES if t in chosen]


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    use_color = args.color or (not args.no_color and sys.stdout.isatty() and not args.output)
    colors = Colors(use_color)

    def error(msg: str) -> int:
        print(f"{colors.red}Error:{colors.reset} {msg}", file=sys.stderr)
        return 2

    # --- validate options --------------------------------------------------
    try:
        types = parse_types(args.types)
    except ValueError as exc:
        return error(str(exc))
    if args.min_count < 1:
        return error("--min-count must be 1 or greater")

    allowlist: Set[str] = set()
    if args.allowlist:
        try:
            allowlist = load_allowlist(args.allowlist)
        except OSError as exc:
            return error(f"cannot read allow-list '{args.allowlist}': {exc.strerror}")

    store = IOCStore()
    sources: List[Dict[str, object]] = []

    # --- gather input ------------------------------------------------------
    if args.text is not None:
        process_text(args.text, "<text>", store, types, args.include_private, allowlist)
        sources.append({"name": "<text>", "sha256": hashlib.sha256(args.text.encode()).hexdigest()})
    elif args.inputs:
        files, warnings = collect_files(args.inputs, args.recursive, args.max_size * 1024 * 1024)
        for w in warnings:
            print(f"{colors.yellow}Warning:{colors.reset} {w}", file=sys.stderr)
        if not files:
            return error("no readable input files")
        for fp in files:
            try:
                text = read_text_file(fp)
                sources.append({"name": str(fp), "sha256": sha256_file(fp)})
            except OSError as exc:
                print(f"{colors.yellow}Warning:{colors.reset} cannot read {fp}: {exc.strerror}", file=sys.stderr)
                continue
            process_text(text, str(fp), store, types, args.include_private, allowlist)
    elif not sys.stdin.isatty():
        data = sys.stdin.read()
        process_text(data, "<stdin>", store, types, args.include_private, allowlist)
        sources.append({"name": "<stdin>", "sha256": hashlib.sha256(data.encode()).hexdigest()})
    else:
        parser.print_help(sys.stderr)
        return 2

    # --- build & output the result ----------------------------------------
    result = build_result(store, types, sources, args.defang, args.min_count)
    output = render(args.format, result, colors)

    if args.output:
        try:
            Path(args.output).write_text(output, encoding="utf-8")
        except OSError as exc:
            return error(f"cannot write '{args.output}': {exc.strerror}")
        print(f"{colors.green}Saved{colors.reset} {result['total_unique']} unique indicators "
              f"({args.format}) to {args.output}")
    else:
        sys.stdout.write(output)

    return 0 if result["total_unique"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:      # e.g. `tool.py file | head`
        sys.exit(0)
