#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
dnstt_resolver_probe.py

FAST + DEEP DNSTT resolver probe, tuned for "HTTP Injector DNSTT Resolver" compatibility.

Key defaults (public tool friendly):
- tunnel-success-rcodes default: NOERROR,NXDOMAIN  (Option A)
- require_txt_answer default: False
- compat-mode default: True (FAST-pass focuses on payload stability, not zone NS visibility)
- tcp_retry_on_timeout default: True
- edns_downgrade default: True

Output:
- CSV by default (Excel can open it)
- If --xlsx is set OR --out ends with .xlsx, it writes XLSX via openpyxl

DISCLAIMER:
- Use only on resolvers you own/administer or have explicit authorization to test.
"""

import argparse
import csv
import ipaddress
import random
import socket
import string
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from statistics import median as stat_median
from typing import Dict, List, Optional, Tuple, Set

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

import os
import signal
import subprocess


# -----------------------------
# Utilities
# -----------------------------

def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def rand_label(n: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def jitter_sleep(base: float = 0.12, jitter: float = 0.08) -> None:
    lo = max(0.0, base - jitter)
    hi = base + jitter
    time.sleep(random.uniform(lo, hi))


def read_dns_list(path: str) -> List[str]:
    """
    IPv4 only. Allows lines like:
      1.2.3.4
      1.2.3.4:53  (port ignored)
    De-duplicates IPs.
    """
    out: List[str] = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            ip = s.split(":")[0].strip()
            try:
                obj = ipaddress.ip_address(ip)
                if obj.version != 4:
                    continue
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


def make_query(qname: str, qtype: str, payload: int) -> dns.message.Message:
    rdtype = dns.rdatatype.from_text(qtype)
    msg = dns.message.make_query(qname, rdtype, use_edns=True)
    try:
        msg.use_edns(edns=0, payload=payload)
    except Exception:
        pass
    return msg


def udp_query(
        server: str,
        qname: str,
        qtype: str,
        timeout: float,
        payload: int,
        tcp_retry_on_timeout: bool = True,
) -> Tuple[str, Optional[float], Optional[bool], Optional[dns.message.Message], str, bool]:
    """
    Query behavior:
      1) Try UDP (udp_with_fallback will TCP fallback on truncation)
      2) If UDP times out and tcp_retry_on_timeout=True -> try TCP explicitly

    Returns:
      (rcode_text, latency_ms, truncated_flag, response_message, err_name, used_tcp)

    Notes:
      - If TCP is used, truncated_flag = None
    """
    msg = make_query(qname, qtype, payload)

    t0 = time.perf_counter()
    try:
        resp, used_tcp = dns.query.udp_with_fallback(msg, server, timeout=timeout)
        latency_ms = (time.perf_counter() - t0) * 1000
        rcode_text = dns.rcode.to_text(resp.rcode())
        truncated = None if used_tcp else bool(resp.flags & dns.flags.TC)
        return rcode_text, latency_ms, truncated, resp, "", used_tcp

    except dns.exception.Timeout:
        if not tcp_retry_on_timeout:
            return "TIMEOUT", None, None, None, "Timeout", False

        try:
            t1 = time.perf_counter()
            resp = dns.query.tcp(msg, server, timeout=timeout)
            latency_ms = (time.perf_counter() - t1) * 1000
            rcode_text = dns.rcode.to_text(resp.rcode())
            return rcode_text, latency_ms, None, resp, "", True
        except dns.exception.Timeout:
            return "TIMEOUT", None, None, None, "Timeout", False
        except Exception as e:
            return "ERROR", None, None, None, type(e).__name__, False

    except Exception as e:
        return "ERROR", None, None, None, type(e).__name__, False


def random_nxdomain(suffix: str = "invalid") -> str:
    return f"nope-{rand_label(16)}.{suffix}"


def median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    v = sorted(values)
    mid = len(v) // 2
    if len(v) % 2:
        return float(v[mid])
    return float((v[mid - 1] + v[mid]) / 2)


def p95(values: List[float]) -> Optional[float]:
    if not values:
        return None
    v = sorted(values)
    idx = int(round(0.95 * (len(v) - 1)))
    return float(v[idx])


def rcode_histogram(rcodes: List[str]) -> str:
    if not rcodes:
        return ""
    counts: Dict[str, int] = {}
    for r in rcodes:
        counts[r] = counts.get(r, 0) + 1
    items = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    return ",".join(f"{k}={v}" for k, v in items)


def parse_rcode_set(s: str) -> Set[str]:
    out: Set[str] = set()
    for part in (s or "").split(","):
        p = part.strip().upper()
        if p:
            out.add(p)
    return out or {"NOERROR", "NXDOMAIN"}


def has_nonempty_txt_answer(resp: Optional[dns.message.Message]) -> bool:
    if resp is None:
        return False
    for rrset in (resp.answer or []):
        if rrset.rdtype == dns.rdatatype.TXT:
            for item in rrset:
                strings = getattr(item, "strings", None)
                if strings and any(len(s) > 0 for s in strings):
                    return True
    return False


def extract_log_path_from_meta(meta: str) -> str:
    """
    meta format example:
      "log=/path/to/log cmd=... pid=..."
    """
    if not meta:
        return ""
    for part in meta.split():
        if part.startswith("log="):
            return part.split("=", 1)[1]
    return ""


def read_log_tail(path: str, max_bytes: int = 4000) -> str:
    try:
        p = Path(path)
        if not p.exists():
            return ""
        with open(p, "rb") as f:
            data = f.read()[-max_bytes:]
        return data.decode(errors="ignore")
    except Exception:
        return ""


def compute_recommendation(
        deep_ran: bool,
        deep1_ok: bool,
        deep2_ok: bool,
        best_mtu: Optional[int],
        fast_pass: bool,
        fast_ok_payloads: str,
        fast_lite: bool,
        deep1_detail: str,
        deep2_reason: str,
) -> Tuple[str, str]:
    """
    Recommendation logic:

    If DEEP ran:
      - WORKING      : deep1_ok and deep2_ok and best_mtu exists
      - PARTIAL      : deep1_ok but deep2 not ok (or no best_mtu)
      - NOT_WORKING  : deep1 failed
    If DEEP did not run:
      - If FAST-LITE -> UNKNOWN (because DNSTT-style payload checks were skipped)
      - Else:
          - LIKELY_OK_FAST : fast_pass and has at least one ok payload
          - UNKNOWN        : otherwise
    """
    if deep_ran:
        if deep1_ok:
            if deep2_ok and best_mtu:
                return "WORKING", f"deep1_ok+deep2_ok mtu={best_mtu}"
            reason = deep2_reason or "deep2_failed"
            return "PARTIAL", f"deep1_ok but deep2_not_ok ({reason})"
        detail = deep1_detail or "deep1_failed"
        short = detail if len(detail) <= 120 else (detail[:120] + "...")
        return "NOT_WORKING", f"deep1_fail ({short})"

    if fast_lite:
        return "UNKNOWN", "fast_lite (no tunnel-domain)"

    if fast_pass and (fast_ok_payloads or "").strip():
        return "LIKELY_OK_FAST", f"fast_pass payloads={fast_ok_payloads}"
    if fast_pass:
        return "UNKNOWN", "fast_pass but no payloads"
    return "UNKNOWN", "no_deep"


# -----------------------------
# Models
# -----------------------------

@dataclass
class MTUCheck:
    payload: int
    ok_count: int
    total: int
    success_rate: float
    timeout_rate: float
    tc_rate: float
    timeouts: int
    formerr: int
    servfail: int
    refused: int
    truncated: int
    tcp_used: int
    median_ms: Optional[float]
    p95_ms: Optional[float]
    pass_payload: bool
    rcode_hist: str
    note: str


@dataclass
class ZoneCheck:
    ns_rcode: str = ""
    ns_latency_ms: Optional[float] = None
    ns_used_tcp: bool = False
    note: str = ""


@dataclass
class ResolverFastResult:
    dns_ip: str
    live_ok: bool
    live_rcode: str
    live_median_ms: Optional[float]

    nxd_ok: bool
    nxd_rcode_mode: str
    nxd_hijack_hint: str

    zone_ok: bool
    zone_note: str

    fast_ok_any_payload: bool
    fast_ok_payload_list: str
    score: int
    notes: str


@dataclass
class Deep1Result:
    ok: bool
    mode: str
    detail: str
    targets_ok: str
    median_connect_ms: Optional[float]


@dataclass
class Deep2Result:
    ok: bool
    mtu_matrix: str
    best_mtu: Optional[int]
    best_reason: str


@dataclass
class FinalResult:
    dns_ip: str

    recommendation: str
    recommend_reason: str

    fast_pass: bool
    score: int
    live_ok: bool
    live_median_ms: Optional[float]
    nxd_ok: bool
    nxd_hint: str
    zone_ok: bool
    zone_note: str
    fast_ok_payloads: str
    fast_notes: str

    deep_ran: bool
    deep1_ok: bool
    deep1_mode: str
    deep1_detail: str
    deep1_targets_ok: str
    deep1_median_connect_ms: Optional[float]

    deep2_ok: bool
    deep2_mtu_matrix: str
    best_mtu: Optional[int]
    best_mtu_reason: str

    dnstt_log_path: str
    dnstt_log_tail: str


# -----------------------------
# FAST logic
# -----------------------------

def liveness_check(dns_ip: str, timeout: float, tries: int, payload: int, tcp_retry_on_timeout: bool) -> Tuple[
    bool, str, Optional[float]]:
    rcodes: List[str] = []
    lats: List[float] = []
    a_ok = 0

    for _ in range(tries):
        r, ms, _tc, resp, _err, _used_tcp = udp_query(
            dns_ip, "google.com", "A", timeout, payload=payload, tcp_retry_on_timeout=tcp_retry_on_timeout
        )
        rcodes.append(r)
        if r == "NOERROR" and resp is not None:
            got_a = any(rrset.rdtype == dns.rdatatype.A and len(rrset) > 0 for rrset in list(resp.answer or []))
            if got_a:
                a_ok += 1
                if ms is not None:
                    lats.append(ms)
        jitter_sleep(0.08, 0.05)

    rmode = max(set(rcodes), key=rcodes.count) if rcodes else "ERROR"
    ok = (rmode == "NOERROR") and (a_ok >= max(1, int(0.6 * tries)))
    return ok, rmode, (round(median(lats), 1) if lats else None)


def nxdomain_integrity_check(dns_ip: str, timeout: float, tries: int, suffix: str, tcp_retry_on_timeout: bool) -> Tuple[
    bool, str, str]:
    rcodes: List[str] = []
    noerror_with_answer = 0
    noerror_empty = 0
    cname_present = 0
    timeouts_or_errors = 0

    for _ in range(tries):
        q = random_nxdomain(suffix)
        r, _ms, _tc, resp, _err, _used_tcp = udp_query(
            dns_ip, q, "A", timeout, payload=1232, tcp_retry_on_timeout=tcp_retry_on_timeout
        )
        rcodes.append(r)

        if r in ("TIMEOUT", "ERROR"):
            timeouts_or_errors += 1
            jitter_sleep(0.10, 0.08)
            continue

        if r == "NOERROR":
            if resp is not None:
                ans_rrsets = list(resp.answer or [])
                if ans_rrsets:
                    noerror_with_answer += 1
                    for rrset in ans_rrsets:
                        if rrset.rdtype == dns.rdatatype.CNAME:
                            cname_present += 1
                else:
                    noerror_empty += 1
            else:
                noerror_empty += 1

        jitter_sleep(0.10, 0.08)

    rmode = max(set(rcodes), key=rcodes.count) if rcodes else "ERROR"
    nxd_count = sum(1 for r in rcodes if r == "NXDOMAIN")
    stable = (nxd_count >= max(1, int(0.75 * tries)))
    ok = (rmode == "NXDOMAIN") and stable

    if rmode == "NXDOMAIN" and stable:
        hint = "OK"
    elif rmode == "REFUSED":
        hint = "RCODE_REFUSED"
    elif rmode == "SERVFAIL":
        hint = "RCODE_SERVFAIL"
    elif timeouts_or_errors == tries:
        hint = "TIMEOUT_OR_ERROR"
    elif cname_present > 0:
        hint = "NOERROR_WITH_CNAME"
    elif noerror_with_answer > 0:
        hint = "NOERROR_WITH_ANSWER"
    elif noerror_empty > 0:
        hint = "NOERROR_EMPTY_ANSWER"
    else:
        hint = "INCONSISTENT_RCODE"

    return ok, rmode, hint


def zone_visibility_check(dns_ip: str, tunnel_domain: str, timeout: float, tcp_retry_on_timeout: bool) -> ZoneCheck:
    z = ZoneCheck()
    r, ms, _tc, _resp, err, used_tcp = udp_query(
        dns_ip, tunnel_domain, "NS", timeout, payload=1232, tcp_retry_on_timeout=tcp_retry_on_timeout
    )
    z.ns_rcode = r
    z.ns_latency_ms = ms
    z.ns_used_tcp = used_tcp
    if r == "NOERROR":
        z.note = "OK" + (":TCP" if used_tcp else "")
    else:
        z.note = f"{r}" + (":TCP" if used_tcp else "") + (f":{err}" if err else "")
    return z


def tunnel_payload_stability_check(
        dns_ip: str,
        tunnel_domain: str,
        payload: int,
        timeout: float,
        repeats: int,
        pass_threshold: int,
        success_rcodes: Set[str],
        qtype: str = "TXT",
        require_txt_answer: bool = False,
        enable_edns_downgrade: bool = True,
        downgrade_payload: int = 512,
        tcp_retry_on_timeout: bool = True,
) -> MTUCheck:
    ok = 0
    timeouts = 0
    formerr = 0
    servfail = 0
    refused = 0
    truncated = 0
    tcp_used = 0

    lats: List[float] = []
    rcodes: List[str] = []

    for _ in range(repeats):
        qname = f"{rand_label(10)}.{tunnel_domain}"

        rcode_text, ms, tc, resp, _err, used_tcp = udp_query(
            dns_ip, qname, qtype, timeout, payload=payload, tcp_retry_on_timeout=tcp_retry_on_timeout
        )

        if enable_edns_downgrade and payload > downgrade_payload and rcode_text in ("FORMERR", "TIMEOUT"):
            r2, ms2, tc2, resp2, _err2, used_tcp2 = udp_query(
                dns_ip, qname, qtype, timeout, payload=downgrade_payload, tcp_retry_on_timeout=tcp_retry_on_timeout
            )
            if r2 not in ("FORMERR", "TIMEOUT", "ERROR"):
                rcode_text, ms, tc, resp, used_tcp = r2, ms2, tc2, resp2, used_tcp2

        rcodes.append(rcode_text)

        if rcode_text == "TIMEOUT":
            timeouts += 1
        elif rcode_text == "FORMERR":
            formerr += 1
        elif rcode_text == "SERVFAIL":
            servfail += 1
        elif rcode_text == "REFUSED":
            refused += 1

        if tc is True:
            truncated += 1
        if used_tcp:
            tcp_used += 1

        if rcode_text in success_rcodes:
            ok_transport = used_tcp or (tc is False) or (tc is None and used_tcp)

            if require_txt_answer and qtype.upper() == "TXT" and rcode_text == "NOERROR":
                ok_content = has_nonempty_txt_answer(resp)
            else:
                ok_content = True

            if ok_transport and ok_content:
                ok += 1
                if ms is not None:
                    lats.append(ms)

        jitter_sleep(0.12, 0.08)

    pass_payload = ok >= pass_threshold
    med = round(median(lats), 1) if lats else None
    p_95 = round(p95(lats), 1) if lats else None

    total = repeats
    success_rate = (ok / total) if total else 0.0
    timeout_rate = (timeouts / total) if total else 0.0
    tc_rate = (truncated / total) if total else 0.0

    note_parts = []
    if timeouts:
        note_parts.append(f"timeout={timeouts}")
    if formerr:
        note_parts.append(f"formerr={formerr}")
    if servfail:
        note_parts.append(f"servfail={servfail}")
    if refused:
        note_parts.append(f"refused={refused}")
    if truncated:
        note_parts.append(f"tc={truncated}")
    if tcp_used:
        note_parts.append(f"tcp={tcp_used}")

    note = "OK" if pass_payload else (";".join(note_parts) if note_parts else "insufficient_ok")

    return MTUCheck(
        payload=payload,
        ok_count=ok,
        total=repeats,
        success_rate=round(success_rate, 3),
        timeout_rate=round(timeout_rate, 3),
        tc_rate=round(tc_rate, 3),
        timeouts=timeouts,
        formerr=formerr,
        servfail=servfail,
        refused=refused,
        truncated=truncated,
        tcp_used=tcp_used,
        median_ms=med,
        p95_ms=p_95,
        pass_payload=pass_payload,
        rcode_hist=rcode_histogram(rcodes),
        note=note,
    )


def score_fast(live_ok: bool, zone_ok: bool, checks: List[MTUCheck]) -> int:
    score = 0
    if live_ok:
        score += 2
    if zone_ok:
        score += 1

    if not checks:
        return score - 10

    best_sr = max((c.success_rate for c in checks), default=0.0)
    worst_to = max((c.timeout_rate for c in checks), default=1.0)
    total_refused = sum(c.refused for c in checks)
    total_servfail = sum(c.servfail for c in checks)
    total_formerr = sum(c.formerr for c in checks)
    total_tcp = sum(c.tcp_used for c in checks)

    score += int(best_sr * 10)
    score -= int(worst_to * 12)
    score -= min(6, total_refused)
    score -= min(4, total_servfail)
    score -= min(3, total_formerr)
    score -= min(3, total_tcp // 3)

    return score


def score_fast_lite(live_ok: bool, live_median_ms: Optional[float], nxd_ok: bool, nxd_hint: str) -> int:
    """
    Simple score for FAST-LITE:
      - prioritize live_ok
      - favor lower latency
      - penalize NXDOMAIN hijack hints
    """
    score = 0
    if live_ok:
        score += 10
    else:
        score -= 20

    # latency bonus (coarse)
    if live_median_ms is not None:
        if live_median_ms <= 80:
            score += 6
        elif live_median_ms <= 150:
            score += 4
        elif live_median_ms <= 300:
            score += 2
        else:
            score += 0

    if nxd_ok:
        score += 4
    else:
        # penalize common bad patterns
        bad = {"NOERROR_WITH_ANSWER", "NOERROR_WITH_CNAME", "INCONSISTENT_RCODE", "TIMEOUT_OR_ERROR"}
        score -= 6 if (nxd_hint in bad) else 3

    return score


def run_fast_for_resolver_full(
        dns_ip: str,
        tunnel_domain: str,
        payloads: List[int],
        timeout: float,
        live_tries: int,
        nxd_tries: int,
        payload_repeats: int,
        payload_pass_threshold: int,
        live_payload: int,
        nxd_suffix: str,
        tunnel_success_rcodes: Set[str],
        require_txt_answer: bool,
        enable_edns_downgrade: bool,
        downgrade_payload: int,
        tcp_retry_on_timeout: bool,
) -> Tuple[ResolverFastResult, List[MTUCheck], ZoneCheck]:
    notes: List[str] = []

    live_ok, live_rcode, live_med = liveness_check(
        dns_ip, timeout, live_tries, payload=live_payload, tcp_retry_on_timeout=tcp_retry_on_timeout
    )
    if not live_ok:
        notes.append(f"live={live_rcode}")

    nxd_ok, nxd_mode, nxd_hint = nxdomain_integrity_check(
        dns_ip, timeout, nxd_tries, suffix=nxd_suffix, tcp_retry_on_timeout=tcp_retry_on_timeout
    )
    if not nxd_ok:
        notes.append(f"nxd={nxd_mode}({nxd_hint})")

    zc = zone_visibility_check(dns_ip, tunnel_domain, timeout, tcp_retry_on_timeout=tcp_retry_on_timeout)
    zone_ok = (zc.ns_rcode == "NOERROR")
    if not zone_ok:
        notes.append(f"zone={zc.note}")

    payload_checks: List[MTUCheck] = []
    ok_payload: List[int] = []

    for p in payloads:
        chk = tunnel_payload_stability_check(
            dns_ip=dns_ip,
            tunnel_domain=tunnel_domain,
            payload=p,
            timeout=timeout,
            repeats=payload_repeats,
            pass_threshold=payload_pass_threshold,
            success_rcodes=tunnel_success_rcodes,
            qtype="TXT",
            require_txt_answer=require_txt_answer,
            enable_edns_downgrade=enable_edns_downgrade,
            downgrade_payload=downgrade_payload,
            tcp_retry_on_timeout=tcp_retry_on_timeout,
        )
        payload_checks.append(chk)
        if chk.pass_payload:
            ok_payload.append(p)

    fast_ok_any = len(ok_payload) > 0
    if not fast_ok_any:
        notes.append("no_payload_pass")

    sc = score_fast(live_ok, zone_ok, payload_checks)

    res = ResolverFastResult(
        dns_ip=dns_ip,
        live_ok=live_ok,
        live_rcode=live_rcode,
        live_median_ms=live_med,
        nxd_ok=nxd_ok,
        nxd_rcode_mode=nxd_mode,
        nxd_hijack_hint=nxd_hint,
        zone_ok=zone_ok,
        zone_note=zc.note,
        fast_ok_any_payload=fast_ok_any,
        fast_ok_payload_list="|".join(str(x) for x in ok_payload),
        score=sc,
        notes="; ".join(notes) if notes else "OK",
    )
    return res, payload_checks, zc


def run_fast_for_resolver_lite(
        dns_ip: str,
        timeout: float,
        live_tries: int,
        live_payload: int,
        nxd_tries: int,
        nxd_suffix: str,
        tcp_retry_on_timeout: bool,
) -> Tuple[ResolverFastResult, List[MTUCheck], ZoneCheck]:
    """
    FAST-LITE: no tunnel-domain -> do only liveness + NXDOMAIN integrity.
    Zone + payload checks are skipped.
    """
    notes: List[str] = [
        "MODE=FAST_LITE",
        "SCORE=LIVE_LAT_NXD(0..20)",
        "SKIPPED=ZONE,PAYLOAD",
    ]

    live_ok, live_rcode, live_med = liveness_check(
        dns_ip, timeout, live_tries, payload=live_payload, tcp_retry_on_timeout=tcp_retry_on_timeout
    )
    if not live_ok:
        notes.append(f"live={live_rcode}")

    nxd_ok, nxd_mode, nxd_hint = nxdomain_integrity_check(
        dns_ip, timeout, nxd_tries, suffix=nxd_suffix, tcp_retry_on_timeout=tcp_retry_on_timeout
    )
    if not nxd_ok:
        notes.append(f"nxd={nxd_mode}({nxd_hint})")

    zc = ZoneCheck(ns_rcode="", ns_latency_ms=None, ns_used_tcp=False, note="SKIPPED_NO_TUNNEL_DOMAIN")

    sc = score_fast_lite(live_ok, live_med, nxd_ok, nxd_hint)

    res = ResolverFastResult(
        dns_ip=dns_ip,
        live_ok=live_ok,
        live_rcode=live_rcode,
        live_median_ms=live_med,
        nxd_ok=nxd_ok,
        nxd_rcode_mode=nxd_mode,
        nxd_hijack_hint=nxd_hint,
        zone_ok=False,
        zone_note=zc.note,
        fast_ok_any_payload=False,
        fast_ok_payload_list="",
        score=sc,
        notes="; ".join(notes),
    )

    return res, [], zc


# -----------------------------
# Tunnel Adapter + DEEP
# -----------------------------

@dataclass
class TunnelHandle:
    resolver_ip: str
    mode: str  # "socks" or "ssh", depending on the server config
    local_host: str
    local_port: int
    meta: str = ""


class TunnelAdapter:
    def __init__(self, args: argparse.Namespace):
        self.args = args

    def _get_arg(self, name: str, default=None):
        return getattr(self.args, name, default)

    def _pick_free_port(self, host: str) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, 0))
            return int(s.getsockname()[1])

    def _wait_ready(self, proc: subprocess.Popen, mode: str, host: str, port: int, deadline_s: float) -> None:
        mode = (mode or "").strip().lower()
        ready_check = (self._get_arg("ready_check", "port") or "port").strip().lower()

        t0 = time.time()
        last_err = "NOT_READY"

        while time.time() - t0 < deadline_s:
            rc = proc.poll()
            if rc is not None:
                raise RuntimeError(f"dnstt-client exited early rc={rc} (see log)")

            try:
                if mode == "ssh":
                    if ready_check == "ssh":
                        ok, _detail = ssh_banner_check(host, port, timeout=0.8)
                        if ok:
                            return
                        last_err = "SSH_NOT_READY"
                    else:
                        with socket.create_connection((host, port), timeout=0.8):
                            return
                elif mode == "socks":
                    with socket.create_connection((host, port), timeout=0.8) as s:
                        s.settimeout(0.8)
                        s.sendall(b"\x05\x01\x00")
                        resp = s.recv(2)
                        if len(resp) == 2 and resp[0] == 0x05:
                            return
                        last_err = "SOCKS_NOT_READY"
                else:
                    with socket.create_connection((host, port), timeout=0.8):
                        return
            except Exception as e:
                last_err = type(e).__name__

            time.sleep(0.15)

        raise RuntimeError(f"tunnel not ready after {deadline_s}s ({last_err})")

    def start_tunnel(self, resolver_ip: str) -> TunnelHandle:
        client_path = self._get_arg("dnstt_client_path", None)
        pubkey_file = self._get_arg("dnstt_pubkey_file", None)
        mode = (self._get_arg("dnstt_mode", "ssh") or "ssh").strip().lower()
        local_host = (self._get_arg("dnstt_local_host", "127.0.0.1") or "127.0.0.1").strip()
        local_port = self._get_arg("dnstt_local_port", 0) or 0
        ready_timeout = float(self._get_arg("dnstt_ready_timeout", 20.0) or 20.0)
        extra_args = self._get_arg("dnstt_extra_args", "") or ""

        if not client_path:
            raise RuntimeError("Missing --dnstt-client-path (required for DEEP)")
        if not pubkey_file:
            raise RuntimeError("Missing --dnstt-pubkey-file (required for DEEP)")

        client_path = str(Path(client_path).expanduser())
        pubkey_file = str(Path(pubkey_file).expanduser())
        if not Path(client_path).exists():
            raise RuntimeError(f"dnstt-client not found: {client_path}")
        if not Path(pubkey_file).exists():
            raise RuntimeError(f"pubkey file not found: {pubkey_file}")

        tunnel_domain = (self.args.tunnel_domain or "").strip().rstrip(".")
        if not tunnel_domain:
            raise RuntimeError("Missing --tunnel-domain (required for DEEP)")

        if local_port <= 0:
            local_port = self._pick_free_port(local_host)

        cmd = [
            client_path,
            "-udp", f"{resolver_ip}:53",
            "-pubkey-file", pubkey_file,
            tunnel_domain,
            f"{local_host}:{local_port}",
        ]

        if extra_args.strip():
            import shlex
            cmd[1:1] = shlex.split(extra_args)

        outdir = Path(getattr(self.args, "outdir", "results"))
        outdir.mkdir(parents=True, exist_ok=True)

        log_path = outdir / f"dnstt_{resolver_ip.replace('.', '_')}_{local_port}.log"
        log_f = open(log_path, "ab", buffering=0)

        proc = subprocess.Popen(
            cmd,
            stdout=log_f,
            stderr=log_f,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

        handle = TunnelHandle(
            resolver_ip=resolver_ip,
            mode=mode,
            local_host=local_host,
            local_port=int(local_port),
            meta=f"log={log_path} cmd={' '.join(cmd)} pid={proc.pid}",
        )
        handle._proc = proc  # type: ignore[attr-defined]
        handle._log_f = log_f  # type: ignore[attr-defined]

        try:
            self._wait_ready(proc, mode, local_host, int(local_port), ready_timeout)
            return handle
        except Exception as e:
            try:
                self.stop_tunnel(handle)
            except Exception:
                pass
            raise RuntimeError(f"{e} | {handle.meta}")

    def stop_tunnel(self, handle: TunnelHandle) -> None:
        proc = getattr(handle, "_proc", None)
        log_f = getattr(handle, "_log_f", None)

        if proc is None:
            try:
                if log_f:
                    log_f.close()
            except Exception:
                pass
            return

        stop_timeout = float(self._get_arg("dnstt_stop_timeout", 3.5) or 3.5)

        try:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    proc.terminate()

                try:
                    proc.wait(timeout=stop_timeout)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        proc.kill()
                    try:
                        proc.wait(timeout=1.5)
                    except Exception:
                        pass
        finally:
            try:
                if log_f:
                    log_f.close()
            except Exception:
                pass


def socks5_connect_via_local_proxy(proxy_host: str, proxy_port: int, target_ip: str, target_port: int,
                                   timeout: float) -> Tuple[bool, str, Optional[float]]:
    t0 = time.perf_counter()
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
                return False, "SOCKS_GREETING_FAIL", None

            ip_bytes = socket.inet_aton(target_ip)
            req = b"\x05\x01\x00\x01" + ip_bytes + struct.pack("!H", target_port)
            s.sendall(req)

            rep = s.recv(4)
            if len(rep) != 4 or rep[0] != 0x05:
                return False, "SOCKS_BAD_REPLY", None

            rep_code = rep[1]
            atyp = rep[3]

            if atyp == 0x01:
                s.recv(4)
            elif atyp == 0x03:
                ln = s.recv(1)
                if ln:
                    s.recv(ln[0])
            elif atyp == 0x04:
                s.recv(16)
            s.recv(2)

            if rep_code != 0x00:
                return False, f"SOCKS_CONNECT_REP={rep_code}", None

            latency_ms = (time.perf_counter() - t0) * 1000
            return True, "OK", latency_ms
    except Exception as e:
        return False, type(e).__name__, None


def ssh_banner_check(local_host: str, local_port: int, timeout: float) -> Tuple[bool, str]:
    try:
        with socket.create_connection((local_host, local_port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(128)
            if not data:
                return False, "NO_DATA"
            line = data.split(b"\n", 1)[0].strip()
            if line.startswith(b"SSH-2.0-") or line.startswith(b"SSH-1.99-"):
                return True, f"OK:{line.decode(errors='ignore')}"
            return False, f"BAD_BANNER:{line.decode(errors='ignore')}"
    except Exception as e:
        return False, type(e).__name__


def deep1_ssh_banner_retry(local_host: str, local_port: int, per_try_timeout: float, total_wait: float) -> Tuple[
    bool, str]:
    t0 = time.time()
    last = "NO_TRY"
    while time.time() - t0 < total_wait:
        ok, detail = ssh_banner_check(local_host, local_port, timeout=per_try_timeout)
        if ok:
            return True, detail
        last = detail
        time.sleep(0.25)
    return False, f"TIMEOUT_WAITING_BANNER:last={last}"


def deep1_check(mode: str, local_host: str, local_port: int, per_try_timeout: float,
                socks_targets: List[Tuple[str, int]], ssh_total_wait: float) -> Deep1Result:
    mode = (mode or "").strip().lower()

    if mode == "ssh":
        ok, detail = deep1_ssh_banner_retry(local_host, local_port, per_try_timeout, ssh_total_wait)
        return Deep1Result(ok=ok, mode="ssh", detail=detail, targets_ok="", median_connect_ms=None)

    if mode == "socks":
        ok_targets: List[str] = []
        lats: List[float] = []
        for ip, port in socks_targets:
            ok, _detail, lat = socks5_connect_via_local_proxy(local_host, local_port, ip, port, per_try_timeout)
            if ok:
                ok_targets.append(f"{ip}:{port}")
                if lat is not None:
                    lats.append(lat)
            jitter_sleep(0.06, 0.04)

        required = 1 if len(socks_targets) <= 1 else 2
        passed = len(ok_targets) >= min(required, len(socks_targets))

        return Deep1Result(
            ok=passed,
            mode="socks",
            detail="OK" if passed else "TCP_CONNECT_FAIL",
            targets_ok="|".join(ok_targets),
            median_connect_ms=round(stat_median(lats), 1) if lats else None
        )

    return Deep1Result(ok=False, mode=mode, detail="UNKNOWN_MODE", targets_ok="", median_connect_ms=None)


def pick_best_mtu(checks: List[MTUCheck]) -> Tuple[Optional[int], str]:
    passed = [c for c in checks if c.pass_payload]
    if not passed:
        return None, "NO_MTU_PASSED"

    def key(c: MTUCheck):
        med = c.median_ms if c.median_ms is not None else 1e9
        p95v = c.p95_ms if c.p95_ms is not None else 1e9
        return (-c.success_rate, c.timeout_rate, c.tcp_used, med, p95v, c.payload)

    best = sorted(passed, key=key)[0]
    return best.payload, f"sr={best.success_rate} to={best.timeout_rate} tcp={best.tcp_used} med={best.median_ms} p95={best.p95_ms}"


def deep2_mtu_test(
        dns_ip: str,
        tunnel_domain: str,
        payloads: List[int],
        timeout: float,
        repeats: int,
        pass_threshold: int,
        tunnel_success_rcodes: Set[str],
        qtype: str = "TXT",
        require_txt_answer: bool = False,
        enable_edns_downgrade: bool = True,
        downgrade_payload: int = 512,
        tcp_retry_on_timeout: bool = True,
) -> Tuple[Deep2Result, List[MTUCheck]]:
    checks: List[MTUCheck] = []
    parts: List[str] = []

    for p in payloads:
        chk = tunnel_payload_stability_check(
            dns_ip=dns_ip,
            tunnel_domain=tunnel_domain,
            payload=p,
            timeout=timeout,
            repeats=repeats,
            pass_threshold=pass_threshold,
            success_rcodes=tunnel_success_rcodes,
            qtype=qtype,
            require_txt_answer=require_txt_answer,
            enable_edns_downgrade=enable_edns_downgrade,
            downgrade_payload=downgrade_payload,
            tcp_retry_on_timeout=tcp_retry_on_timeout,
        )
        checks.append(chk)
        parts.append(
            f"{p}:{'pass' if chk.pass_payload else 'fail'}"
            f"(sr={chk.success_rate},to={chk.timeout_rate},tc={chk.tc_rate},tcp={chk.tcp_used},med={chk.median_ms})"
        )

    best, reason = pick_best_mtu(checks)
    ok = best is not None
    return Deep2Result(ok=ok, mtu_matrix=";".join(parts), best_mtu=best, best_reason=reason), checks


def parse_socks_targets(s: str) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    for part in (s or "").split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        ip, ps = part.split(":", 1)
        ip = ip.strip()
        try:
            port = int(ps.strip())
            ipaddress.ip_address(ip)
            if 1 <= port <= 65535:
                out.append((ip, port))
        except Exception:
            continue
    return out


# -----------------------------
# Output writers
# -----------------------------

def write_csv(path: Path, rows: List[FinalResult]) -> None:
    if not rows:
        return
    dict_rows = [asdict(r) for r in rows]
    fieldnames = list(dict_rows[0].keys())
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in dict_rows:
            w.writerow(r)


def write_xlsx(path: Path, rows: List[FinalResult]) -> None:
    from openpyxl import Workbook
    if not rows:
        return
    dict_rows = [asdict(r) for r in rows]
    headers = list(dict_rows[0].keys())
    wb = Workbook()
    ws = wb.active
    ws.title = "results"
    ws.append(headers)
    for r in dict_rows:
        ws.append([r.get(h, "") for h in headers])
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="FAST+DEEP DNSTT resolver probe (Option A + store logs + recommendation).")
    ap.add_argument("--dns-list", required=True, help="Path to dns_list.txt (one resolver IPv4 per line)")

    # ✅ tunnel-domain is now optional (FAST-LITE if missing)
    ap.add_argument("--tunnel-domain", required=False, default="",
                    help="Your tunnel delegated domain, e.g. t.example.com (optional; if omitted -> FAST-LITE)")

    # FAST settings
    ap.add_argument("--payloads", default="512,900,1232",
                    help="Comma-separated EDNS payload sizes (default: 512,900,1232)")
    ap.add_argument("--timeout", type=float, default=2.8, help="FAST DNS timeout seconds (default: 2.8)")
    ap.add_argument("--workers", type=int, default=30, help="FAST parallel workers (default: 30)")
    ap.add_argument("--live-tries", type=int, default=3, help="FAST liveness repeats (default: 3)")
    ap.add_argument("--live-payload", type=int, default=512, help="FAST liveness EDNS payload (default: 512)")
    ap.add_argument("--nxd-tries", type=int, default=3, help="FAST NXDOMAIN repeats (default: 3)")
    ap.add_argument("--nxd-suffix", default="invalid", help="FAST NXDOMAIN suffix (default: invalid)")
    ap.add_argument("--payload-repeats", type=int, default=4, help="FAST per-payload repeats (default: 4)")
    ap.add_argument("--payload-pass", type=int, default=2, help="FAST pass threshold per payload (default: 2)")

    ap.add_argument("--tunnel-success-rcodes", default="NOERROR,NXDOMAIN",
                    help="Success rcodes for tunnel-domain checks (default: NOERROR,NXDOMAIN).")
    ap.add_argument("--require-txt-answer", action="store_true", default=False,
                    help="Strict mode: require non-empty TXT only when rcode=NOERROR (default: disabled).")

    ap.add_argument("--edns-downgrade", action="store_true", default=True,
                    help="Retry smaller payload on FORMERR/TIMEOUT for big payload (default: enabled).")
    ap.add_argument("--no-edns-downgrade", action="store_false", dest="edns_downgrade",
                    help="Disable EDNS downgrade retry.")
    ap.add_argument("--downgrade-payload", type=int, default=512, help="Downgrade payload size (default: 512)")

    ap.add_argument("--tcp-retry-on-timeout", action="store_true", default=True,
                    help="If UDP times out, retry query over TCP (default: enabled).")
    ap.add_argument("--no-tcp-retry-on-timeout", action="store_false", dest="tcp_retry_on_timeout",
                    help="Disable TCP retry on UDP timeout.")

    # Compatibility mode
    ap.add_argument("--compat-mode", action="store_true", default=True,
                    help="Compatibility mode (default ON): FAST-pass focuses on payload stability (not zone NS visibility).")
    ap.add_argument("--no-compat-mode", action="store_false", dest="compat_mode",
                    help="Disable compat-mode and use stricter gating.")
    ap.add_argument("--require-live", action="store_true", help="Require live_ok for FAST-pass")
    ap.add_argument("--require-nxd", action="store_true", help="Require nxd_ok for FAST-pass (usually not needed)")

    ap.add_argument("--debug-resolver", default="", help="Comma-separated resolver IPs to print debug info")

    # DEEP settings
    ap.add_argument("--run-deep", action="store_true", help="Run DEEP stage.")
    ap.add_argument("--deep-timeout", type=float, default=2.0,
                    help="Deep-1 per-try socket timeout seconds (default: 2.0)")
    ap.add_argument("--deep1-total-wait", type=float, default=12.0,
                    help="Deep-1 total wait window for SSH banner retries (default: 12.0)")
    ap.add_argument("--socks-targets", default="1.1.1.1:443,8.8.8.8:53", help="SOCKS targets (if mode=socks)")
    ap.add_argument("--deep2-timeout", type=float, default=3.5, help="Deep-2 DNS timeout (default: 3.5)")
    ap.add_argument("--deep2-repeats", type=int, default=7, help="Deep-2 repeats per payload (default: 7)")
    ap.add_argument("--deep2-pass", type=int, default=5, help="Deep-2 pass threshold per payload (default: 5)")
    ap.add_argument("--deep-qtype", default="TXT", help="Deep-2 qtype (default: TXT)")

    ap.add_argument("--deep-even-if-fast-fail", action="store_true",
                    help="Run DEEP even when FAST fails (useful on networks with DNS problems).")
    ap.add_argument("--deep-only", default="",
                    help="Comma-separated resolver IPs to run DEEP on (overrides FAST gating). Example: --deep-only 8.8.8.8,9.9.9.9")

    ap.add_argument("--out", default="", help="Output file path. If empty -> results_<stamp>.csv in outdir.")
    ap.add_argument("--outdir", default="results", help="Output directory (default: results)")
    ap.add_argument("--xlsx", action="store_true", help="Write XLSX (Excel) instead of CSV.")

    # DNSTT client settings (optional unless --run-deep)
    ap.add_argument("--dnstt-client-path", required=False, default="",
                    help="Path to dnstt-client binary (required only when --run-deep)")
    ap.add_argument("--dnstt-pubkey-file", required=False, default="",
                    help="Path to server.pub (required only when --run-deep)")
    ap.add_argument("--dnstt-mode", default="ssh", choices=["socks", "ssh"], help="Local endpoint mode (default: ssh)")
    ap.add_argument("--dnstt-local-host", default="127.0.0.1")
    ap.add_argument("--dnstt-local-port", type=int, default=0)
    ap.add_argument("--dnstt-ready-timeout", type=float, default=20.0,
                    help="Seconds to wait for tunnel readiness (default: 20)")
    ap.add_argument("--dnstt-stop-timeout", type=float, default=3.5)
    ap.add_argument("--dnstt-extra-args", default="")

    # Readiness check style (reduces false negatives)
    ap.add_argument("--ready-check", choices=["port", "ssh"], default="port",
                    help="Tunnel readiness check for SSH mode: 'port' (default) or 'ssh' (banner).")

    args = ap.parse_args()

    dns_list = read_dns_list(args.dns_list)
    if not dns_list:
        raise SystemExit("No valid resolver IPv4s found in dns-list input.")

    tunnel_domain = (args.tunnel_domain or "").strip().rstrip(".")
    has_tunnel_domain = bool(tunnel_domain)

    # DEEP fail-fast requirements
    if args.run_deep:
        missing = []
        if not has_tunnel_domain:
            missing.append("--tunnel-domain")
        if not (args.dnstt_client_path or "").strip():
            missing.append("--dnstt-client-path")
        if not (args.dnstt_pubkey_file or "").strip():
            missing.append("--dnstt-pubkey-file")
        if missing:
            raise SystemExit(f"DEEP requested (--run-deep) but missing required args: {', '.join(missing)}")

    payloads: List[int] = []
    for x in args.payloads.split(","):
        x = x.strip()
        if not x:
            continue
        try:
            v = int(x)
            if 256 <= v <= 2000:
                payloads.append(v)
        except ValueError:
            continue
    if not payloads:
        payloads = [512, 900, 1232]

    tunnel_success_rcodes = parse_rcode_set(args.tunnel_success_rcodes)
    socks_targets = parse_socks_targets(args.socks_targets)

    debug_set = set(p.strip() for p in args.debug_resolver.split(",") if p.strip())
    deep_only_set: Set[str] = set(p.strip() for p in args.deep_only.split(",") if p.strip())

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if args.out:
        out_path = Path(args.out)
    else:
        ext = ".xlsx" if args.xlsx else ".csv"
        out_path = outdir / f"results_{now_stamp()}{ext}"

    if out_path.suffix.lower() == ".xlsx":
        args.xlsx = True

    if has_tunnel_domain:
        print(f"START | resolvers={len(dns_list)} | tunnel_domain={tunnel_domain}")
        print(
            f"FAST(FULL) payloads={payloads} | success_rcodes={','.join(sorted(tunnel_success_rcodes))} | compat_mode={args.compat_mode}")
    else:
        print(f"START | resolvers={len(dns_list)} | tunnel_domain=-")
        print("FAST(LITE): tunnel-domain not provided -> skipping zone/payload checks (results are NOT DNSTT-accurate)")

    print(
        f"FAST require_txt_answer={args.require_txt_answer} | edns_downgrade={args.edns_downgrade} | tcp_retry_on_timeout={args.tcp_retry_on_timeout}")
    if args.run_deep:
        print(
            f"DEEP enabled | dnstt_mode={args.dnstt_mode} | deep2_repeats={args.deep2_repeats} | deep_even_if_fast_fail={args.deep_even_if_fast_fail} | deep_only={args.deep_only or '-'}")

    # ---------- FAST
    fast_map: Dict[str, ResolverFastResult] = {}
    fast_payload_ok: Dict[str, List[int]] = {}
    zone_map: Dict[str, ZoneCheck] = {}

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {}
        for dns_ip in dns_list:
            if has_tunnel_domain:
                futures[ex.submit(
                    run_fast_for_resolver_full,
                    dns_ip,
                    tunnel_domain,
                    payloads,
                    args.timeout,
                    args.live_tries,
                    args.nxd_tries,
                    args.payload_repeats,
                    args.payload_pass,
                    args.live_payload,
                    args.nxd_suffix,
                    tunnel_success_rcodes,
                    args.require_txt_answer,
                    args.edns_downgrade,
                    args.downgrade_payload,
                    args.tcp_retry_on_timeout,
                )] = dns_ip
            else:
                futures[ex.submit(
                    run_fast_for_resolver_lite,
                    dns_ip,
                    args.timeout,
                    args.live_tries,
                    args.live_payload,
                    args.nxd_tries,
                    args.nxd_suffix,
                    args.tcp_retry_on_timeout,
                )] = dns_ip

        for fut in as_completed(futures):
            dns_ip = futures[fut]
            try:
                res, payload_checks, zc = fut.result()
                fast_map[dns_ip] = res
                zone_map[dns_ip] = zc
                okp = [c.payload for c in payload_checks if c.pass_payload]
                fast_payload_ok[dns_ip] = okp

                print(
                    f"FAST {dns_ip:>16} score={res.score:3d} "
                    f"live={res.live_ok} zone={res.zone_ok}({res.zone_note}) "
                    f"payload_ok={res.fast_ok_payload_list or '-':>10}"
                )

                if dns_ip in debug_set and has_tunnel_domain:
                    for chk in payload_checks:
                        print(
                            f"DBG  {dns_ip} payload={chk.payload} pass={chk.pass_payload} ok={chk.ok_count}/{chk.total} rcode_hist={chk.rcode_hist} note={chk.note}")

            except Exception as e:
                fast_map[dns_ip] = ResolverFastResult(
                    dns_ip=dns_ip,
                    live_ok=False, live_rcode="ERROR", live_median_ms=None,
                    nxd_ok=False, nxd_rcode_mode="ERROR", nxd_hijack_hint="CRASH",
                    zone_ok=False, zone_note="CRASH",
                    fast_ok_any_payload=False, fast_ok_payload_list="",
                    score=-999, notes=f"crash:{type(e).__name__}",
                )
                zone_map[dns_ip] = ZoneCheck(ns_rcode="ERROR", note="CRASH")
                fast_payload_ok[dns_ip] = []

    # determine FAST-pass list
    fast_pass: List[str] = []
    for ip, res in fast_map.items():
        if not has_tunnel_domain:
            # FAST-LITE pass: pre-filter only (DNS liveness), optionally require_nxd if user asked
            base_ok = res.live_ok
            if args.require_nxd:
                base_ok = base_ok and res.nxd_ok
        else:
            if args.compat_mode:
                base_ok = res.fast_ok_any_payload
            else:
                base_ok = res.zone_ok and res.fast_ok_any_payload

            if args.require_live:
                base_ok = base_ok and res.live_ok
            if args.require_nxd:
                base_ok = base_ok and res.nxd_ok

        if base_ok:
            fast_pass.append(ip)

    fast_pass.sort(key=lambda ip: (-fast_map[ip].score, fast_map[ip].live_median_ms or 1e9))

    print("---")
    print(f"FAST PASS: {len(fast_pass)}/{len(dns_list)}")

    # ---------- DEEP
    adapter = TunnelAdapter(args)
    final_rows: List[FinalResult] = []

    for ip in dns_list:
        res = fast_map[ip]
        zc = zone_map.get(ip, ZoneCheck())
        is_fast_pass = ip in fast_pass

        deep_ran = False
        deep1 = Deep1Result(ok=False, mode="", detail="", targets_ok="", median_connect_ms=None)
        deep2 = Deep2Result(ok=False, mtu_matrix="", best_mtu=None, best_reason="")

        dnstt_log_path = ""
        dnstt_log_tail = ""

        # should_deep only possible if args.run_deep and has_tunnel_domain (already enforced above)
        if deep_only_set:
            should_deep = args.run_deep and (ip in deep_only_set)
        else:
            should_deep = args.run_deep and (is_fast_pass or args.deep_even_if_fast_fail)

        if should_deep:
            deep_ran = True
            handle: Optional[TunnelHandle] = None
            try:
                handle = adapter.start_tunnel(ip)
                dnstt_log_path = extract_log_path_from_meta(getattr(handle, "meta", "") or "")

                deep1 = deep1_check(
                    handle.mode,
                    handle.local_host,
                    handle.local_port,
                    args.deep_timeout,
                    socks_targets,
                    ssh_total_wait=args.deep1_total_wait,
                )
                print(f"DEEP1 {ip:>16} mode={deep1.mode} ok={deep1.ok} detail={deep1.detail}")

                if deep1.ok:
                    candidate_payloads = fast_payload_ok.get(ip) or payloads
                    deep2, _checks = deep2_mtu_test(
                        dns_ip=ip,
                        tunnel_domain=tunnel_domain,
                        payloads=candidate_payloads,
                        timeout=args.deep2_timeout,
                        repeats=args.deep2_repeats,
                        pass_threshold=args.deep2_pass,
                        tunnel_success_rcodes=tunnel_success_rcodes,
                        qtype=args.deep_qtype,
                        require_txt_answer=args.require_txt_answer,
                        enable_edns_downgrade=args.edns_downgrade,
                        downgrade_payload=args.downgrade_payload,
                        tcp_retry_on_timeout=args.tcp_retry_on_timeout,
                    )
                    print(f"DEEP2 {ip:>16} ok={deep2.ok} best_mtu={deep2.best_mtu} matrix={deep2.mtu_matrix}")
                else:
                    deep2 = Deep2Result(ok=False, mtu_matrix="", best_mtu=None, best_reason="SKIP_DEEP2_DEEP1_FAIL")

            except Exception as e:
                detail = f"DEEP_CRASH:{type(e).__name__}:{e}"
                deep1 = Deep1Result(ok=False, mode="", detail=detail, targets_ok="", median_connect_ms=None)
                deep2 = Deep2Result(ok=False, mtu_matrix="", best_mtu=None, best_reason="DEEP_CRASH")

                meta = ""
                try:
                    text = str(e)
                    if "log=" in text and "|" in text:
                        meta = text.split("|", 1)[-1].strip()
                    dnstt_log_path = extract_log_path_from_meta(meta)
                except Exception:
                    pass

                print(f"DEEP  {ip:>16} FAILED {detail}")

            finally:
                if handle is not None:
                    try:
                        adapter.stop_tunnel(handle)
                    except Exception:
                        pass

                if dnstt_log_path:
                    dnstt_log_tail = read_log_tail(dnstt_log_path, max_bytes=4000)

        recommendation, recommend_reason = compute_recommendation(
            deep_ran=deep_ran,
            deep1_ok=deep1.ok,
            deep2_ok=deep2.ok,
            best_mtu=deep2.best_mtu,
            fast_pass=is_fast_pass,
            fast_ok_payloads=res.fast_ok_payload_list,
            fast_lite=(not has_tunnel_domain),
            deep1_detail=deep1.detail,
            deep2_reason=deep2.best_reason,
        )

        final_rows.append(FinalResult(
            dns_ip=ip,

            recommendation=recommendation,
            recommend_reason=recommend_reason,

            fast_pass=is_fast_pass,
            score=res.score,
            live_ok=res.live_ok,
            live_median_ms=res.live_median_ms,
            nxd_ok=res.nxd_ok,
            nxd_hint=res.nxd_hijack_hint,
            zone_ok=res.zone_ok,
            zone_note=zc.note,
            fast_ok_payloads=res.fast_ok_payload_list,
            fast_notes=res.notes,

            deep_ran=deep_ran,
            deep1_ok=deep1.ok,
            deep1_mode=deep1.mode,
            deep1_detail=deep1.detail,
            deep1_targets_ok=deep1.targets_ok,
            deep1_median_connect_ms=deep1.median_connect_ms,

            deep2_ok=deep2.ok,
            deep2_mtu_matrix=deep2.mtu_matrix,
            best_mtu=deep2.best_mtu,
            best_mtu_reason=deep2.best_reason,

            dnstt_log_path=dnstt_log_path,
            dnstt_log_tail=dnstt_log_tail,
        ))

    if args.xlsx:
        write_xlsx(out_path, final_rows)
    else:
        write_csv(out_path, final_rows)

    print("---")
    print(f"DONE. Output: {out_path}")


if __name__ == "__main__":
    main()
