# dnstt_resolve_probe.py
FAST + DEEP DNS Resolver Probe for DNSTT usage (single script, one output file)

This repository provides a single-file Python tool for testing DNS resolvers for DNSTT-style tunneling, with one output file per run (CSV by default, XLSX optional).

The probe runs in two phases:

- **FAST (parallel):** DNS-only checks to quickly rank/filter resolvers and figure out which UDP/EDNS payload sizes are stable.
- **DEEP (sequential):** For each resolver (one at a time), it launches `dnstt-client`, confirms the local endpoint actually works (SSH or SOCKS), then picks the best MTU candidate.

The goal is to find resolvers that behave like the ones that work inside apps such as **HTTP Injector**.

---

## What it does

1) You provide a list of DNS resolvers.  
2) **FAST** runs parallel DNS-only probes:
   - basic responsiveness
   - anti-hijack / wildcard hints
   - tunnel-domain payload stability (MTU candidates)
3) **DEEP (optional)** starts `dnstt-client` per resolver and verifies the tunnel endpoint works.  
4) The tool writes **one final output file** containing FAST + DEEP results and a recommended MTU.

---

## Requirements

- Python **3.9+**
- `dnspython`

Install:

    pip install dnspython

If you want true Excel output:

    pip install openpyxl

---

## Input

### dns_list.txt

A text file with one resolver per line.

- IPv4 only
- `:53` is allowed but ignored (port is always 53)
- empty lines and comments (`#`) are ignored

Example:

    1.1.1.1
    8.8.8.8
    9.9.9.9:53
    # comments are fine

---

## Quickstart

### FAST only (quick filtering)

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --out results_fast.csv

### FAST + DEEP (recommended)

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --dnstt-client-path /path/to/dnstt-client \
      --dnstt-pubkey-file /path/to/server.pub \
      --dnstt-mode ssh

DEEP runs sequentially because each resolver needs its own `dnstt-client` session.

---

## FAST Mode (DNS-only)

FAST runs in parallel and never starts a tunnel.

It checks:

- **Liveness** (simple “does this resolver answer normally?” check)
- **NXDOMAIN integrity** (wildcard/hijack hints)
- **Tunnel-domain payload stability** (EDNS payload candidates like 512/900/1232)
- **Zone visibility** (NS lookup for tunnel-domain; helpful for debugging but not always decisive)

### DNSTT-friendly defaults

Some DNSTT setups work even if tunnel-domain lookups return `NXDOMAIN`. Because of that, the tool defaults to treating both of these as “success” for the tunnel-domain probe:

- `NOERROR`
- `NXDOMAIN`

You can override it any time:

    --tunnel-success-rcodes NOERROR

---

## DEEP Mode (real tunnel test)

DEEP starts `dnstt-client` one resolver at a time and verifies the local endpoint.

- **Deep-1:** confirms the endpoint is usable
  - SSH mode: waits for a real SSH banner (with retries)
  - SOCKS mode: SOCKS5 handshake + TCP connect checks
- **Deep-2:** probes payload sizes again and selects the best MTU using:
  - success rate
  - timeouts
  - TCP fallback usage
  - latency

If Deep-1 fails, Deep-2 is skipped.

---

## DNSTT logs (kept out of stdout)

`dnstt-client` output is redirected into per-resolver log files:

- `results/dnstt_<resolver>_<port>.log`

To keep your terminal clean, log tails are **not printed to stdout**.  
Instead, the output file includes these columns:

- `dnstt_log_path`
- `dnstt_log_tail` (last ~4000 bytes)

That way you can sort/filter results in Excel and still see exactly what happened for failures.

---

## Output file

You get exactly **one output file** per run:

- CSV by default (Excel can open it)
- XLSX if you pass `--xlsx` or use `--out something.xlsx`

Common columns include:

FAST:
- `fast_pass`, `score`
- `live_ok`, `live_median_ms`
- `nxd_ok`, `nxd_hint`
- `zone_ok`, `zone_note`
- `fast_ok_payloads`, `fast_notes`

DEEP:
- `deep_ran`
- `deep1_ok`, `deep1_mode`, `deep1_detail`
- `deep2_ok`, `deep2_mtu_matrix`
- `best_mtu`, `best_mtu_reason`

Logs:
- `dnstt_log_path`
- `dnstt_log_tail`

---

## Useful flags

Output:
- `--out <path>` choose output path
- `--xlsx` write XLSX instead of CSV (or use `--out results.xlsx`)

Compatibility and gating:
- `--compat-mode` (default) FAST-pass is based mainly on payload stability
- `--no-compat-mode` stricter FAST-pass (includes zone visibility)
- `--require-live` require liveness for FAST-pass
- `--require-nxd` require NXDOMAIN integrity for FAST-pass

Tunnel-domain success definition:
- `--tunnel-success-rcodes NOERROR,NXDOMAIN` (default)
- `--tunnel-success-rcodes NOERROR` (stricter)
- `--require-txt-answer` require non-empty TXT when rcode=NOERROR (strict)

DEEP reliability (useful on slow/bad networks):
- `--dnstt-ready-timeout 30` wait longer for the local port to appear
- `--deep1-total-wait 20` keep retrying SSH banner longer
- `--ready-check port` (default) tunnel readiness = port open
- `--ready-check ssh` stricter readiness = banner must appear

---

## Safety & authorization

Use this tool only on resolvers you own/administer or where you have explicit permission.

FAST uses DNS queries. DEEP starts a tunnel client and checks a local endpoint.

---

## More examples

See `Examples.md` for tuned command lines, recipes, and troubleshooting.
