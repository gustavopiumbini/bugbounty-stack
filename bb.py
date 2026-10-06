#!/usr/bin/env python3
"""Conservative, scope-aware helpers for authorized bug bounty research."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PROGRAMS = ROOT / "programs"
BIN = ROOT / "tools" / "bin"
ACK_TEXT = "I_HAVE_AUTHORIZATION"
PROGRAM_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


def normalize_host(value: str) -> str:
    value = value.strip()
    if "://" in value:
        value = urllib.parse.urlsplit(value).hostname or ""
    else:
        value = value.split("/", 1)[0].split(":", 1)[0]
    value = value.rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


@dataclass(frozen=True)
class ScopeRule:
    pattern: str
    excluded: bool
    wildcard: bool

    def matches(self, host: str) -> bool:
        if self.wildcard:
            suffix = self.pattern[2:]
            return host.endswith("." + suffix) and host != suffix
        return host == self.pattern


class Scope:
    def __init__(self, path: Path):
        self.path = path
        self.rules: list[ScopeRule] = []
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            excluded = line.startswith("!")
            if excluded:
                line = line[1:].strip()
            wildcard = line.startswith("*.")
            host = normalize_host(line[2:] if wildcard else line)
            if not host or "*" in host:
                raise ValueError(f"invalid scope rule at {path}:{number}")
            pattern = "*." + host if wildcard else host
            self.rules.append(ScopeRule(pattern, excluded, wildcard))
        if not any(not rule.excluded for rule in self.rules):
            raise ValueError(f"scope has no allow rules: {path}")

    def allowed(self, value: str) -> bool:
        host = normalize_host(value)
        if not host:
            return False
        if any(rule.excluded and rule.matches(host) for rule in self.rules):
            return False
        return any(not rule.excluded and rule.matches(host) for rule in self.rules)


def program_dir(name: str) -> Path:
    if not PROGRAM_RE.fullmatch(name):
        raise ValueError("program name must contain only letters, numbers, ., _ or -")
    return PROGRAMS / name


def load_defaults() -> dict:
    return json.loads((ROOT / "config" / "defaults.json").read_text(encoding="utf-8"))


def require_authorization(value: str | None) -> None:
    supplied = value or os.environ.get("BB_ACK_AUTHORIZED")
    if supplied != ACK_TEXT:
        raise ValueError(f"active network action requires --ack {ACK_TEXT}")


def cmd_init(args: argparse.Namespace) -> int:
    base = program_dir(args.program)
    if base.exists():
        raise ValueError(f"program already exists: {base}")
    for child in ("input", "output", "logs"):
        (base / child).mkdir(parents=True, exist_ok=True)
    (base / "scope.txt").write_text(
        "# Copy the program's exact authorized scope below.\n"
        "# See ../../config/scope.example.txt for syntax.\n",
        encoding="utf-8",
    )
    (base / "README.txt").write_text(
        "Copy the program policy and scope into scope.txt before any network action.\n",
        encoding="utf-8",
    )
    print(base)
    return 0


def get_scope(program: str) -> tuple[Path, Scope]:
    base = program_dir(program)
    scope_path = base / "scope.txt"
    if not scope_path.is_file():
        raise ValueError(f"missing scope file: {scope_path}; run init first")
    return base, Scope(scope_path)


def cmd_scope_check(args: argparse.Namespace) -> int:
    _, scope = get_scope(args.program)
    denied = False
    for target in args.targets:
        allowed = scope.allowed(target)
        print(f"{'ALLOW' if allowed else 'DENY '}\t{target}")
        denied |= not allowed
    return 2 if denied else 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    tools = ["subfinder", "httpx", "katana", "nuclei", "dnsx"]
    print(f"root\t{ROOT}")
    print(f"http_proxy\t{'set' if os.environ.get('HTTP_PROXY') else 'missing'}")
    print(f"https_proxy\t{'set' if os.environ.get('HTTPS_PROXY') else 'missing'}")
    for tool in tools:
        path = BIN / tool
        print(f"{tool}\t{'installed' if path.is_file() else 'missing'}")
    return 0


def cmd_passive(args: argparse.Namespace) -> int:
    require_authorization(args.ack)
    base, scope = get_scope(args.program)
    domain = normalize_host(args.domain)
    if not scope.allowed(domain):
        raise ValueError(f"domain is outside scope: {domain}")
    tool = BIN / "subfinder"
    if not tool.is_file():
        raise ValueError("subfinder is not installed; run scripts/install-tools.sh subfinder")
    result = subprocess.run(
        [str(tool), "-silent", "-d", domain, "-timeout", str(args.timeout)],
        check=False,
        capture_output=True,
        text=True,
        timeout=args.timeout + 30,
        env=os.environ.copy(),
    )
    if result.returncode:
        sys.stderr.write(result.stderr)
        return result.returncode
    hosts = sorted({normalize_host(line) for line in result.stdout.splitlines()})
    hosts = [host for host in hosts if host and scope.allowed(host)]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = base / "output" / f"subdomains-{stamp}.txt"
    output.write_text("".join(host + "\n" for host in hosts), encoding="utf-8")
    print(f"saved {len(hosts)} in-scope hosts to {output}")
    return 0


def fetch_url(url: str, config: dict) -> dict:
    started = time.monotonic()
    request = urllib.request.Request(
        url,
        headers={"User-Agent": config["user_agent"], "Accept": "text/html,*/*;q=0.8"},
        method="GET",
    )
    opener = urllib.request.build_opener()
    if not config["allow_redirects"]:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)
    record = {"url": url, "timestamp": datetime.now(timezone.utc).isoformat()}
    try:
        with opener.open(request, timeout=config["timeout_seconds"]) as response:
            body = response.read(config["max_response_bytes"])
            record.update(
                status=response.status,
                content_type=response.headers.get("Content-Type"),
                bytes_read=len(body),
                body_sha256=hashlib.sha256(body).hexdigest(),
                location=response.headers.get("Location"),
            )
    except urllib.error.HTTPError as exc:
        body = exc.read(config["max_response_bytes"])
        record.update(status=exc.code, bytes_read=len(body), body_sha256=hashlib.sha256(body).hexdigest(), location=exc.headers.get("Location"))
    except Exception as exc:  # diagnostic record; no automatic retries
        record.update(error=f"{type(exc).__name__}: {exc}")
    record["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return record


def cmd_probe(args: argparse.Namespace) -> int:
    require_authorization(args.ack)
    base, scope = get_scope(args.program)
    config = load_defaults()
    config["concurrency"] = args.concurrency or config["concurrency"]
    if not 1 <= config["concurrency"] <= 10:
        raise ValueError("concurrency must be between 1 and 10")
    lines = Path(args.input).read_text(encoding="utf-8").splitlines()
    urls: list[str] = []
    denied: list[str] = []
    for raw in lines:
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        if not scope.allowed(item):
            denied.append(item)
            continue
        if "://" in item:
            parsed = urllib.parse.urlsplit(item)
            if parsed.scheme not in ("http", "https"):
                denied.append(item)
                continue
            urls.append(item)
        else:
            urls.extend((f"https://{normalize_host(item)}/", f"http://{normalize_host(item)}/"))
    if denied:
        print(f"skipped {len(denied)} out-of-scope or invalid entries", file=sys.stderr)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = base / "output" / f"http-{stamp}.jsonl"
    records: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=config["concurrency"]) as pool:
        futures = []
        for url in sorted(set(urls)):
            futures.append(pool.submit(fetch_url, url, config))
            time.sleep(config["delay_ms"] / 1000)
        for future in concurrent.futures.as_completed(futures):
            records.append(future.result())
    records.sort(key=lambda record: record["url"])
    output.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8")
    print(f"saved {len(records)} results to {output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="create an isolated program workspace")
    init.add_argument("program")
    init.set_defaults(func=cmd_init)
    doctor = commands.add_parser("doctor", help="show local stack readiness")
    doctor.set_defaults(func=cmd_doctor)
    check = commands.add_parser("scope-check", help="evaluate targets against scope")
    check.add_argument("program")
    check.add_argument("targets", nargs="+")
    check.set_defaults(func=cmd_scope_check)
    passive = commands.add_parser("passive", help="run passive subdomain discovery")
    passive.add_argument("program")
    passive.add_argument("--domain", required=True)
    passive.add_argument("--timeout", type=int, default=30)
    passive.add_argument("--ack")
    passive.set_defaults(func=cmd_passive)
    probe = commands.add_parser("probe", help="perform low-rate HTTP GET probes")
    probe.add_argument("program")
    probe.add_argument("--input", required=True)
    probe.add_argument("--concurrency", type=int)
    probe.add_argument("--ack")
    probe.set_defaults(func=cmd_probe)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        return args.func(args)
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
