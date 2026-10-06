# Bug bounty stack

A conservative, scope-aware CLI workspace for authorized security research.

## Safety model

- Every program has an explicit `scope.txt` allowlist.
- Exclusions (`!host` or `!*.domain`) override allow rules.
- Network actions require `--ack I_HAVE_AUTHORIZATION`.
- HTTP probing defaults to concurrency 4, a 250 ms pacing delay, no redirects,
  a 10 second timeout, and at most 1 MiB read per response.
- There is no port scanning or automatic exploitation in the default pipeline.

Always follow the target program's policy. The acknowledgement is a guardrail,
not proof of authorization.

## Install

ProjectDiscovery releases are pinned in `tools/versions.lock.json`, downloaded
over verified TLS, and checked against upstream SHA-256 manifests:

```bash
cd /workspace/bugbounty-stack
./scripts/install-tools.sh
./bb.py doctor
```

## Start a program

```bash
./bb.py init example-program
$EDITOR programs/example-program/scope.txt
./bb.py scope-check example-program example.com api.example.com evil.test
```

After copying and reviewing the official policy and scope:

```bash
./bb.py passive example-program \
  --domain example.com \
  --ack I_HAVE_AUTHORIZATION

./bb.py probe example-program \
  --input programs/example-program/output/subdomains-TIMESTAMP.txt \
  --ack I_HAVE_AUTHORIZATION
```

Results are timestamped under each program's `output/` directory. HTTP records
are JSON Lines and include status, body hash, response size, timing, and selected
headers without storing response bodies.

## Cloud runtime note

This environment supports proxied HTTP/HTTPS. Raw TCP/UDP access is not currently
granted, so `dnsx`, `naabu`, Nmap, and other direct-network tools may not function
here even if installed. They are included for portability but are not invoked by
the safe default workflow.
