#!/usr/bin/env python3
"""reconx - web attack-surface recon pipeline.

Chains subdomain discovery, live-host probing, URL harvesting and
template scanning into one reproducible run with structured output.
"""
from __future__ import annotations

import argparse
import json
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

VERSION = "1.3.0"


class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; CY = "\033[36m"; W = "\033[37m"; GR = "\033[90m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RST = "\033[0m"

    @classmethod
    def strip(cls):
        for k in list(vars(cls)):
            if k.isupper() and isinstance(getattr(cls, k), str):
                setattr(cls, k, "")


def banner() -> str:
    art = rf"""
{C.CY}{C.BOLD}    ┌─┐ ┌─┐ ┌─┐ ┌─┐ ┌┐┌ ─┐ ┬
    ├┬┘ ├┤  │   │ │ │││  ┌┴┬┘
    ┴└─ └─┘ └─┘ └─┘ ┘└┘ ┴ └─{C.RST}  {C.GR}attack-surface recon · v{VERSION}{C.RST}
{C.GR}    ────────────────────────────────────────────{C.RST}"""
    return art


def now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log(tag: str, msg: str, color: str = C.W):
    icons = {"+": C.G, "*": C.CY, "!": C.Y, "x": C.R, ">": C.M}
    c = icons.get(tag, color)
    print(f"{C.GR}{now()}{C.RST} {c}[{tag}]{C.RST} {msg}")


def die(msg: str):
    log("x", msg, C.R)
    sys.exit(1)


# external tooling 

@dataclass
class Tool:
    name: str
    required: bool = False

    @property
    def available(self) -> bool:
        return shutil.which(self.name) is not None


def run(cmd: list[str], timeout: int = 600) -> tuple[int, str]:
    """Run a command, capture stdout, swallow stderr noise."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, ""
    except FileNotFoundError:
        return 127, ""


def stream_lines(out: str) -> list[str]:
    return [l.strip() for l in out.splitlines() if l.strip()]


# results model 

@dataclass
class Host:
    url: str
    status: int = 0
    title: str = ""
    server: str = ""
    tech: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)


@dataclass
class Findings:
    target: str
    started: str
    subdomains: list[str] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    vulns: list[dict] = field(default_factory=list)

    def json(self) -> str:
        d = asdict(self)
        return json.dumps(d, indent=2, ensure_ascii=False)


# pipeline 

class Recon:
    def __init__(self, target: str, outdir: Path, threads: int, opts):
        self.target = target
        self.out = outdir
        self.threads = threads
        self.opts = opts
        self.f = Findings(target=target, started=datetime.now().isoformat())

    def save(self, name: str, lines: list[str]):
        (self.out / name).write_text("\n".join(lines) + "\n")

    # 1. subdomain discovery
    def enum_subdomains(self):
        log("*", f"enumerating subdomains for {C.BOLD}{self.target}{C.RST}")
        found: set[str] = {self.target}

        if Tool("subfinder").available:
            rc, out = run(["subfinder", "-d", self.target, "-silent"])
            found.update(stream_lines(out))

        if self.opts.deep and Tool("amass").available:
            log(">", "amass passive (deep mode, slower)")
            rc, out = run(
                ["amass", "enum", "-passive", "-d", self.target, "-silent"],
                timeout=900,
            )
            found.update(stream_lines(out))

        self.f.subdomains = sorted(found)
        self.save("subdomains.txt", self.f.subdomains)
        log("+", f"{len(self.f.subdomains)} subdomains")

    # 2. probe which hosts are alive
    def probe(self):
        if not Tool("httpx").available:
            log("!", "httpx missing - probing skipped, using bare host")
            self.f.hosts = [Host(url=f"https://{self.target}")]
            return

        log("*", "probing live hosts")
        src = self.out / "subdomains.txt"
        cmd = [
            "httpx", "-l", str(src), "-silent", "-json",
            "-title", "-tech-detect", "-status-code", "-web-server",
            "-threads", str(self.threads),
        ]
        rc, out = run(cmd, timeout=900)
        for line in stream_lines(out):
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            self.f.hosts.append(Host(
                url=d.get("url", ""),
                status=d.get("status_code", 0),
                title=d.get("title", "") or "",
                server=d.get("webserver", "") or "",
                tech=d.get("tech", []) or [],
            ))
        self.save("live.txt", [h.url for h in self.f.hosts])
        log("+", f"{len(self.f.hosts)} live hosts")
        self._print_hosts()

    def _print_hosts(self):
        for h in self.f.hosts[:25]:
            sc = h.status
            col = C.G if sc < 300 else C.Y if sc < 400 else C.R
            tech = f" {C.DIM}[{', '.join(h.tech[:3])}]{C.RST}" if h.tech else ""
            ttl = f" {C.GR}{h.title[:40]}{C.RST}" if h.title else ""
            print(f"    {col}{sc:>3}{C.RST} {h.url}{tech}{ttl}")
        if len(self.f.hosts) > 25:
            print(f"    {C.GR}... +{len(self.f.hosts) - 25} more{C.RST}")

    # 3. optional port sweep
    def port_scan(self):
        if self.opts.no_ports or not Tool("naabu").available:
            return
        log("*", "port sweep (top ports)")
        src = self.out / "subdomains.txt"
        rc, out = run(
            ["naabu", "-l", str(src), "-silent", "-top-ports", "100"],
            timeout=600,
        )
        port_map: dict[str, list[int]] = {}
        for line in stream_lines(out):
            if ":" in line:
                host, _, port = line.rpartition(":")
                port_map.setdefault(host, []).append(int(port))
        for h in self.f.hosts:
            key = h.url.split("://")[-1].split("/")[0].split(":")[0]
            h.ports = sorted(port_map.get(key, []))
        self.save("ports.txt", stream_lines(out))
        opened = sum(len(v) for v in port_map.values())
        log("+", f"{opened} open ports across {len(port_map)} hosts")

    # 4. harvest URLs from passive sources
    def harvest_urls(self):
        if self.opts.no_urls:
            return
        log("*", "harvesting URLs (passive)")
        urls: set[str] = set()
        for tool in ("gau", "waybackurls"):
            if not Tool(tool).available:
                continue
            rc, out = run([tool, self.target], timeout=300)
            urls.update(stream_lines(out))
        self.f.urls = sorted(urls)
        if self.f.urls:
            self.save("urls.txt", self.f.urls)
        log("+", f"{len(self.f.urls)} unique URLs")

    # 5. template scan on live hosts
    def scan(self):
        if self.opts.no_scan or not Tool("nuclei").available:
            if self.opts.no_scan:
                log("!", "nuclei stage disabled (--no-scan)")
            return
        if not self.f.hosts:
            return
        log("*", "running nuclei (this can take a while)")
        live = self.out / "live.txt"
        sev = self.opts.severity
        cmd = [
            "nuclei", "-l", str(live), "-silent", "-jsonl",
            "-severity", sev, "-rate-limit", "150",
            "-o", str(self.out / "nuclei.jsonl"),
        ]
        rc, _ = run(cmd, timeout=self.opts.scan_timeout)
        nf = self.out / "nuclei.jsonl"
        if nf.exists():
            for line in stream_lines(nf.read_text()):
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = d.get("info", {})
                self.f.vulns.append({
                    "name": info.get("name", ""),
                    "severity": info.get("severity", "info"),
                    "url": d.get("matched-at", d.get("host", "")),
                    "template": d.get("template-id", ""),
                })
        self._print_vulns()

    def _print_vulns(self):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        cols = {"critical": C.R + C.BOLD, "high": C.R, "medium": C.Y,
                "low": C.B, "info": C.GR}
        self.f.vulns.sort(key=lambda v: order.get(v["severity"], 9))
        if not self.f.vulns:
            log("+", "no template matches")
            return
        log("+", f"{len(self.f.vulns)} matches")
        for v in self.f.vulns[:30]:
            c = cols.get(v["severity"], C.W)
            print(f"    {c}{v['severity']:>8}{C.RST}  "
                  f"{v['name']}  {C.GR}{v['url']}{C.RST}")

    # report
    def report(self):
        (self.out / "findings.json").write_text(self.f.json())
        self._markdown()
        log("+", f"report written to {C.BOLD}{self.out}{C.RST}")

    def _markdown(self):
        v = self.f.vulns
        crit = sum(1 for x in v if x["severity"] == "critical")
        high = sum(1 for x in v if x["severity"] == "high")
        lines = [
            f"# Recon report - {self.target}",
            f"_generated {self.f.started}_\n",
            "## Summary",
            f"- Subdomains: **{len(self.f.subdomains)}**",
            f"- Live hosts: **{len(self.f.hosts)}**",
            f"- URLs harvested: **{len(self.f.urls)}**",
            f"- Findings: **{len(v)}** "
            f"(critical {crit}, high {high})\n",
            "## Findings",
        ]
        if v:
            lines.append("| severity | name | url |")
            lines.append("|---|---|---|")
            for x in v:
                lines.append(
                    f"| {x['severity']} | {x['name']} | {x['url']} |"
                )
        else:
            lines.append("_none_")
        (self.out / "report.md").write_text("\n".join(lines) + "\n")

    def run_all(self):
        t0 = time.time()
        self.enum_subdomains()
        self.probe()
        self.port_scan()
        self.harvest_urls()
        self.scan()
        self.report()
        dt = time.time() - t0
        log("+", f"done in {dt:.1f}s "
                 f"{C.GR}({len(self.f.vulns)} findings){C.RST}")


# cli 

def preflight():
    core = [Tool("subfinder"), Tool("httpx"), Tool("nuclei")]
    missing = [t.name for t in core if not t.available]
    if missing:
        log("!", f"recommended tools missing: {', '.join(missing)} "
                 f"{C.GR}(stages will degrade){C.RST}")


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="reconx", description="web attack-surface recon pipeline")
    p.add_argument("target", help="root domain, e.g. example.com")
    p.add_argument("-o", "--output", default="results",
                   help="output directory (default: results)")
    p.add_argument("-t", "--threads", type=int, default=40)
    p.add_argument("--severity", default="low,medium,high,critical",
                   help="nuclei severities")
    p.add_argument("--scan-timeout", type=int, default=1800)
    p.add_argument("--deep", action="store_true",
                   help="add amass passive enum")
    p.add_argument("--no-ports", action="store_true")
    p.add_argument("--no-urls", action="store_true")
    p.add_argument("--no-scan", action="store_true",
                   help="skip nuclei stage")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    if args.no_color or not sys.stdout.isatty():
        if args.no_color:
            C.strip()
    print(banner())

    target = args.target.strip().lower().removeprefix("http://").removeprefix(
        "https://").rstrip("/")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = Path(args.output) / f"{target}-{stamp}"
    outdir.mkdir(parents=True, exist_ok=True)

    log("*", f"target {C.BOLD}{target}{C.RST}  =>  {outdir}")
    preflight()

    rec = Recon(target, outdir, args.threads, args)
    try:
        rec.run_all()
    except KeyboardInterrupt:
        log("x", "interrupted - writing partial results")
        rec.report()
        sys.exit(130)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    main()
