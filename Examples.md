# Examples & Detailed Behavior

This file contains practical examples and notes for `dnstt_resolve_probe.py`.

Quick mental model:

- FAST is a filter/ranker.
- DEEP is the real proof that a resolver works for DNSTT.

---

## Table of contents

- Recommended workflow (FAST → DEEP)
- FAST Mode
  - 1) Liveness
  - 2) NXDOMAIN integrity
  - 3) Tunnel-domain payload tests (EDNS / MTU candidates)
  - 4) Zone visibility (NS lookup)
  - FAST-pass logic
- DEEP Mode
  - Deep-1: endpoint verification (SSH / SOCKS)
  - Deep-2: MTU selection
- How to read results quickly
- Output formats (CSV vs XLSX)
- Common scenarios
- Troubleshooting notes

---

## Recommended workflow (FAST → DEEP)

If you’re scanning a lot of resolvers, this approach saves time and avoids chasing noise:

1) **Run FAST-only first** to quickly find the “top candidates”.
2) **Run FAST + DEEP** to confirm end-to-end tunneling and pick a final MTU.
3) If your network is unstable or blocks DNS in weird ways, use:
   - `--deep-even-if-fast-fail`, or
   - `--deep-only <ip>` to test a resolver you care about.

Example “two-step” workflow:

Step 1 (FAST-only):

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --out results_fast.csv

Step 2 (DEEP confirmation):

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --dnstt-client-path /path/to/dnstt-client \
      --dnstt-pubkey-file /path/to/server.pub \
      --dnstt-mode ssh \
      --out results_full.csv

---

## FAST Mode

FAST runs DNS-only checks in parallel. It never starts a tunnel.

### 1) Liveness

What it’s trying to answer: does this resolver behave like a normal resolver?

- Query: `A google.com`
- Default payload: `--live-payload 512`
- Pass criteria: stable `NOERROR` and real `A` answers in most tries

Example:

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --live-tries 3 \
      --live-payload 512

---

### 2) NXDOMAIN integrity

What it’s trying to catch: resolvers that wildcard/hijack fake domains.

- Generates random names like `nope-<random>.invalid`
- Expected: stable `NXDOMAIN`

Example:

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --nxd-tries 5 \
      --nxd-suffix invalid

If you’re scanning on a bad network, don’t be surprised if NXDOMAIN is noisy.
That’s why compat-mode doesn’t force NXDOMAIN as a hard gate by default.

---

### 3) Tunnel-domain payload tests (EDNS / MTU candidates)

This is the most important FAST signal for DNSTT.

- Query: `random-label.<tunnel-domain>`
- QTYPE: TXT
- Payload candidates: `--payloads 512,900,1232` by default
- Default success RCODES: `NOERROR,NXDOMAIN`

That default exists because some DNSTT setups still tunnel fine even if the resolver returns NXDOMAIN on the tunnel-domain probe.

Default behavior:

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com

Stricter behavior (NOERROR only):

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --tunnel-success-rcodes NOERROR

Require real TXT answers (only when rcode=NOERROR):

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --require-txt-answer

---

### 4) Zone visibility (NS lookup)

FAST also tries:

- `NS <tunnel-domain>`

This is useful for diagnosing delegation/propagation problems, but it’s not always a reliable “will DNSTT work” signal. In compat-mode, it influences scoring and notes but isn’t a hard gate.

---

### FAST-pass logic

Default behavior (`--compat-mode` ON):

- FAST-pass if at least one payload candidate passes

Stricter gating options:

- `--no-compat-mode` (includes zone visibility in the gate)
- `--require-live`
- `--require-nxd`

Example: strict FAST-pass

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --no-compat-mode \
      --require-live \
      --require-nxd

---

## DEEP Mode

DEEP starts `dnstt-client` one resolver at a time and checks whether the local endpoint actually works.

Enable DEEP with `--run-deep`.

### Deep-1: endpoint verification

#### SSH mode

In SSH mode, the tool tries to confirm the local port is really serving SSH by reading a banner.
Two knobs matter here:

- `--dnstt-ready-timeout`: how long to wait for the local port to appear
- `--deep1-total-wait`: how long to keep retrying the SSH banner

Example:

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --dnstt-client-path /path/to/dnstt-client \
      --dnstt-pubkey-file /path/to/server.pub \
      --dnstt-mode ssh \
      --dnstt-ready-timeout 25 \
      --deep1-total-wait 12

Readiness check detail:
- By default, SSH readiness is a simple “port open” check (`--ready-check port`).
- If you want it stricter (don’t continue unless a banner is already visible), use `--ready-check ssh`.

#### SOCKS mode

If your server exposes SOCKS instead:

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --dnstt-client-path /path/to/dnstt-client \
      --dnstt-pubkey-file /path/to/server.pub \
      --dnstt-mode socks \
      --socks-targets "1.1.1.1:443,9.9.9.9:443,8.8.8.8:53"

---

### Deep-2: MTU selection

Deep-2 repeats the tunnel-domain payload probes and picks the best MTU using:

- success rate
- timeout rate
- TCP fallback usage
- latency

Example (more strict/slow but higher confidence):

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --deep2-repeats 11 \
      --deep2-pass 9 \
      --deep2-timeout 4.0

---

## How to read results quickly

If your goal is “what should I actually use in HTTP Injector?”, these fields are the fastest way to decide:

### Best signal (confirmed working)

A resolver is “confirmed working” if:

- `deep_ran == True`
- `deep1_ok == True`
- `deep2_ok == True`
- `best_mtu` is set (not empty)

That combination means:
- the tunnel endpoint really came up (Deep-1),
- the resolver handled repeated payload probes reliably (Deep-2),
- and the tool picked an MTU that worked best on your network.

### FAST-only signal (not confirmed end-to-end)

If you did not run DEEP, then the best hint is:

- `fast_pass == True`
- `fast_ok_payloads` is not empty (e.g., `512|900|1232`)
- `score` is high relative to your list

This is useful for finding candidates, but it’s not a guarantee of real tunneling until DEEP is tested.

### Mapping to HTTP Injector settings (practical)

- **DNSTT Resolver (IP):** use `dns_ip`
- **MTU / payload hint:** use `best_mtu` (if DEEP succeeded)
- If DEEP didn’t run, start with the smallest passing payload in `fast_ok_payloads` (often `512`) and test upward.

### When DEEP fails but FAST looked good

If you see errors like `SSH_NOT_READY`, the resolver might still be “DNS-good” but unusable for tunneling from your network.

In those cases, check:
- `dnstt_log_tail` (quick clue),
- and the full log at `dnstt_log_path`.

---

## Output formats (CSV vs XLSX)

CSV is the default (Excel can open it):

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --out results.csv

XLSX output:

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --xlsx \
      --out results.xlsx

The output includes:

- `dnstt_log_path` (full path to the resolver log file)
- `dnstt_log_tail` (last ~4000 bytes)

So you can debug failures later without printing logs into your terminal.

---

## Common scenarios

### Scenario 1: FAST-only scan

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --out results_fast.csv

### Scenario 2: Full scan (FAST + DEEP)

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --dnstt-client-path /path/to/dnstt-client \
      --dnstt-pubkey-file /path/to/server.pub \
      --dnstt-mode ssh

### Scenario 3: Only test one resolver deeply

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --deep-only 8.8.8.8 \
      --dnstt-client-path /path/to/dnstt-client \
      --dnstt-pubkey-file /path/to/server.pub \
      --dnstt-mode ssh

### Scenario 4: Run DEEP even if FAST is unhappy (bad networks)

    python3 dnstt_resolve_probe.py \
      --dns-list dns_list.txt \
      --tunnel-domain t.example.com \
      --run-deep \
      --deep-even-if-fast-fail \
      --dnstt-client-path /path/to/dnstt-client \
      --dnstt-pubkey-file /path/to/server.pub \
      --dnstt-mode ssh

---

## Troubleshooting notes

### “SSH_NOT_READY” but the resolver looked fine in FAST

That usually means `dnstt-client` started a session but never managed to bring up a usable local endpoint.

Check:
- `dnstt_log_tail` in the output file
- the full log under `results/dnstt_<resolver>_<port>.log`

A common clue is an extremely small “effective MTU” (like 128). That usually points to heavy DNS interference or a very unstable path.

### Too much noise / false negatives on a bad network

Give it more time:

- raise `--dnstt-ready-timeout` (try 30–40)
- raise `--deep1-total-wait` (try 20)
- raise `--deep2-timeout` (try 5)

### You want stricter scoring (less “maybe” resolvers)

Use:

- `--no-compat-mode`
- `--require-live`
- `--require-nxd`
- `--tunnel-success-rcodes NOERROR`
- `--require-txt-answer`
