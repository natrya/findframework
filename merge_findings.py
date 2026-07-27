#!/usr/bin/env python3
"""Merge httpx / whatweb / nuclei / wafw00f output into results.json + report.md.

Author: Ryan Fabella
"""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse


def host_of(url_or_host: str) -> str:
    if "://" in url_or_host:
        return urlparse(url_or_host).netloc.split(":")[0].lower()
    return url_or_host.split(":")[0].lower()


def load_jsonl(path: Path):
    records = []
    if not path.exists() or path.stat().st_size == 0:
        return records
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def parse_httpx(path: Path, hosts: dict):
    for rec in load_jsonl(path):
        url = rec.get("url") or rec.get("input")
        if not url:
            continue
        h = host_of(url)
        entry = hosts.setdefault(h, new_host_entry(h))
        entry["url"] = url
        entry["status_code"] = rec.get("status_code") or rec.get("status-code")
        entry["title"] = rec.get("title", "")
        entry["server"] = rec.get("webserver", "")
        for tech in rec.get("tech", []) or []:
            add_tech(entry, tech, source="httpx")


def parse_whatweb(path: Path, hosts: dict):
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open() as f:
        content = f.read().strip()
    if not content:
        return
    # whatweb --log-json emits one JSON object per line (sometimes a bare
    # JSON array per line depending on version); handle both.
    for line in content.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, list):
            for r in rec:
                _parse_whatweb_record(r, hosts)
        else:
            _parse_whatweb_record(rec, hosts)


def _parse_whatweb_record(rec, hosts: dict):
    if not isinstance(rec, dict):
        return
    target = rec.get("target")
    if not target:
        return
    h = host_of(target)
    entry = hosts.setdefault(h, new_host_entry(h))
    plugins = rec.get("plugins", {}) or {}
    # Exclude whatweb plugins that surface raw header/security metadata rather
    # than an actual product/framework/library fingerprint - they're noise
    # for a "what tech stack is this" report.
    skip = {
        "Title", "HTTPServer", "Country", "IP", "Cookies", "RedirectLocation",
        "UncommonHeaders", "HttpOnly", "Strict-Transport-Security",
        "X-Frame-Options", "X-XSS-Protection", "Via-Proxy", "Script",
        "Frame", "Content-Language", "Open-Graph-Protocol", "Meta-Author",
        "PoweredBy", "Email", "X-UA-Compatible", "Cache-Control",
        "Content-Security-Policy", "X-Content-Type-Options",
        "Referrer-Policy", "Access-Control-Allow-Origin", "Via",
    }
    for name, data in plugins.items():
        if name in skip:
            continue
        version = ""
        if isinstance(data, dict):
            versions = data.get("version") or data.get("string")
            if isinstance(versions, list) and versions:
                version = str(versions[0])
        add_tech(entry, name, source="whatweb", version=version)


def parse_nuclei(path: Path, hosts: dict):
    for rec in load_jsonl(path):
        target = rec.get("host") or rec.get("matched-at") or rec.get("ip")
        if not target:
            continue
        h = host_of(target)
        entry = hosts.setdefault(h, new_host_entry(h))
        info = rec.get("info", {}) or {}
        name = info.get("name") or rec.get("template-id", "unknown")
        add_tech(entry, name, source="nuclei")


def parse_wafw00f(path: Path, hosts: dict):
    if not path.exists() or path.stat().st_size == 0:
        return
    content = path.read_text(errors="ignore")
    # Typical wafw00f line: "[*] Checking https://example.com\n[+] The site
    # https://example.com is behind Cloudflare WAF."  or "No WAF detected".
    blocks = re.split(r"\[\*\]\s*Checking\s+", content)
    for block in blocks[1:]:
        first_line, _, rest = block.partition("\n")
        target = first_line.strip()
        h = host_of(target)
        entry = hosts.setdefault(h, new_host_entry(h))
        m = re.search(r"is behind\s+(.+?)(?:\s+WAF)?\.?\s*$", rest, re.MULTILINE)
        if m:
            entry["waf"] = m.group(1).strip()
        elif "No WAF detected" in rest or "seems to be behind no WAF" in rest.lower():
            entry["waf"] = "none detected"


def new_host_entry(h):
    return {
        "subdomain": h,
        "url": "",
        "status_code": None,
        "title": "",
        "server": "",
        "waf": "",
        "technologies": [],
    }


def add_tech(entry, name, source, version=""):
    name = str(name).strip()
    if not name:
        return
    for t in entry["technologies"]:
        if t["name"].lower() == name.lower():
            if source not in t["sources"]:
                t["sources"].append(source)
            if version and not t.get("version"):
                t["version"] = version
            return
    entry["technologies"].append(
        {"name": name, "version": version, "sources": [source]}
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True)
    ap.add_argument("--httpx", required=True, type=Path)
    ap.add_argument("--whatweb", required=True, type=Path)
    ap.add_argument("--nuclei", required=True, type=Path)
    ap.add_argument("--wafw00f", required=True, type=Path)
    ap.add_argument("--subdomains", required=True, type=Path)
    ap.add_argument("--outdir", required=True, type=Path)
    args = ap.parse_args()

    hosts = {}

    all_subs = []
    if args.subdomains.exists():
        all_subs = [
            s.strip() for s in args.subdomains.read_text().splitlines() if s.strip()
        ]
    for s in all_subs:
        hosts.setdefault(s, new_host_entry(s))

    parse_httpx(args.httpx, hosts)
    parse_whatweb(args.whatweb, hosts)
    parse_nuclei(args.nuclei, hosts)
    parse_wafw00f(args.wafw00f, hosts)

    results = sorted(hosts.values(), key=lambda e: e["subdomain"])

    results_path = args.outdir / "results.json"
    results_path.write_text(json.dumps(results, indent=2))

    live = [r for r in results if r["status_code"]]
    with_tech = [r for r in live if r["technologies"]]
    unique_frameworks = sorted(
        {t["name"] for r in results for t in r["technologies"]}
    )

    lines = []
    lines.append(f"# Framework/Technology Recon Report: {args.domain}")
    lines.append("")
    lines.append(f"- Total subdomains discovered: {len(results)}")
    lines.append(f"- Live hosts: {len(live)}")
    lines.append(f"- Hosts with identified technologies: {len(with_tech)}")
    lines.append(f"- Unique technologies/frameworks found: {len(unique_frameworks)}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append("| Subdomain | Status | Server | Technologies | WAF |")
    lines.append("|---|---|---|---|---|")
    for r in results:
        techs = ", ".join(
            f"{t['name']} {t['version']}".strip() for t in r["technologies"]
        ) or "-"
        status = r["status_code"] if r["status_code"] else "-"
        server = r["server"] or "-"
        waf = r["waf"] or "-"
        lines.append(f"| {r['subdomain']} | {status} | {server} | {techs} | {waf} |")

    if unique_frameworks:
        lines.append("")
        lines.append("## Unique Technologies Observed")
        lines.append("")
        for name in unique_frameworks:
            lines.append(f"- {name}")

    report_path = args.outdir / "report.md"
    report_path.write_text("\n".join(lines) + "\n")

    print(f"  wrote {results_path}")
    print(f"  wrote {report_path}")


if __name__ == "__main__":
    main()
