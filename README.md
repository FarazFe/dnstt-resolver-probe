# dnstt_resolver_probe.py

FAST + DEEP DNS Resolver Probe for DNSTT usage  
(single script, one output file)

This repository provides a single-file Python tool for testing DNS resolvers for DNSTT-style tunneling.  
Each run produces exactly one output file (CSV by default, XLSX optional).

The probe runs in two phases:

- FAST (parallel): DNS-only checks to quickly filter and rank resolvers, and to find which EDNS / payload sizes are stable.
- DEEP (sequential): For each resolver (one at a time), it launches dnstt-client, verifies that the tunnel actually works (SSH or SOCKS), and selects the best MTU.

The goal is to find resolvers that behave like the ones that actually work in real-world tools such as HTTP Injector, not just resolvers that reply to simple DNS queries.

---

## Requirements

You should already have these installed:

- Python 3.9+  
  https://www.python.org/downloads/

- dnstt-client (official DNSTT client)  
  https://dnstt.network/

Python dependencies (install once):

pip install dnspython

Optional, for real Excel output:

pip install openpyxl

---

## Input

### DNS resolver list

The tool expects a plain text file containing DNS resolvers, one per line.

This repository includes a ready-to-use example file:

sample_dns_list.txt

You can use it as-is, or edit it to add, remove, or replace DNS servers with your own list.

Rules:
- IPv4 only
- “:53” is allowed but ignored (port is always 53)
- empty lines and comments (#) are ignored

---

## Quickstart (short and simple)

If Python and dnstt-client are already installed, this is all you need.

FAST only (quick filtering):

python3 dnstt_resolver_probe.py --dns-list sample_dns_list.txt --tunnel-domain t.example.com --out results_fast.csv

What this does:
- checks which resolvers are alive
- detects resolvers that break DNSTT-style DNS queries
- finds payload sizes that are likely to work

You can freely edit sample_dns_list.txt and add your own DNS servers.

FAST mode is recommended if you do NOT know details such as the server public key, tunnel domain internals, or DNSTT server configuration.  
It works with minimal information and still provides useful, practical results.

FAST + DEEP (recommended for advanced users):

python3 dnstt_resolver_probe.py --dns-list sample_dns_list.txt --tunnel-domain t.example.com --run-deep --dnstt-client-path /path/to/dnstt-client --dnstt-pubkey-file /path/to/server.pub --dnstt-mode ssh

This does everything FAST does, plus:
- actually starts a DNSTT tunnel per resolver
- verifies that the local endpoint really works
- chooses the best MTU based on real tunnel behavior

DEEP mode is intended for users who know their DNSTT setup details (such as server public key and tunnel domain).  
It provides much more precise, end-to-end validation.

DEEP runs sequentially because each resolver needs its own dnstt-client session.

---

## Important concepts (brief)

### tunnel-domain

This is the domain used for DNSTT queries (for example: t.example.com).

- If you know what it is and set it correctly, results will be more accurate
- If you don’t fully understand it, that’s fine — FAST mode still works well
- Many users simply copy this value from an existing DNSTT configuration

### MTU (payload size)

In simple terms, MTU is the largest DNS payload size that works without breaking.

- Too small: tunnel is slow
- Too large: packets get dropped or truncated

For most end users (consumers), MTU is not something you need to worry about.  
The tool automatically selects a good value.

MTU becomes more useful if you are setting up or tuning a DNSTT server and want more precise control.

---

## FAST Mode (DNS-only)

FAST mode never starts a tunnel and runs fully in parallel.

It checks:
- resolver liveness
- NXDOMAIN integrity (wildcard / hijack hints)
- tunnel-domain payload stability (EDNS sizes like 512, 900, 1232)
- zone visibility (NS lookup, mainly for debugging)

By default, both NOERROR and NXDOMAIN are treated as valid tunnel responses.

---

## DEEP Mode (real tunnel test)

DEEP mode starts dnstt-client for each resolver and verifies real usability.

Deep-1:
- SSH mode: waits for a real SSH banner
- SOCKS mode: SOCKS5 handshake and TCP connect

Deep-2:
- re-tests payload sizes
- selects the best MTU based on success rate, timeouts, TCP fallback usage, and latency

If Deep-1 fails, Deep-2 is skipped.

---

## Logs

dnstt-client output is saved per resolver:

results/dnstt_<resolver>_<port>.log

Logs are not printed to stdout.  
Instead, the output file includes the log path and the last part of the log for inspection.

---

## Output file

Each run produces one output file:
- CSV by default
- XLSX if --xlsx is used

---

## Safety & authorization

Use this tool only on DNS resolvers you own, administer, or have explicit permission to test.

FAST sends DNS queries.  
DEEP starts a real DNSTT tunnel.
