#!/usr/bin/env python3
import argparse
import ctypes
import json
import os
import sys
import hashlib
import datetime
from pathlib import Path
from typing import Optional

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"; BLD = "\033[1m"; RST = "\033[0m"

BANNER = f"""
{M}╔══════════════════════════════════════════════════════════════════╗
║ {W}{BLD}RedOps{RST}{M} · Red Team Campaign Intelligence Platform ║
║ {DIM}Python + C hybrid · MITRE ATT&CK · Kill-Chain Analysis{RST}{M} ║
╚══════════════════════════════════════════════════════════════════╝{RST}
"""

SEV_COLOR = {0: DIM+W, 1: G, 2: Y, 3: R, 4: M+BLD}
SEV_NAME = {0: "INFO", 1: "LOW", 2: "MED", 3: "HIGH", 4: "CRIT"}
TOOL_HINTS = {"auto": 0, "nmap": 1, "cme": 2, "cred": 3}

MITRE_MAP = {
    "open_port": ("TA0007", "T1046", "Network Service Discovery",
                           "Open port identified via active scanning"),
    "os_detection": ("TA0007", "T1082", "System Information Discovery",
                           "OS fingerprinting via banner/TTL analysis"),
    "service_version": ("TA0007", "T1046", "Network Service Discovery",
                           "Service version enumerated"),
    "sam_dump": ("TA0006", "T1003.002", "OS Credential Dumping: SAM",
                           "NTLM hashes extracted from SAM database"),
    "weak_cred": ("TA0006", "T1110.001", "Brute Force: Password Guessing",
                           "Weak/default credential successfully authenticated"),
    "local_admin": ("TA0004", "T1078.003", "Valid Accounts: Local Accounts",
                           "Local administrator access via valid credentials"),
    "smb_signing_disabled": ("TA0008", "T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS",
                             "SMB signing not required — relay attacks possible"),
    "null_session": ("TA0007", "T1135", "Network Share Discovery",
                             "Anonymous SMB session enumeration possible"),
    "rdp_open": ("TA0001", "T1133", "External Remote Services",
                           "RDP exposed — brute force / credential stuffing vector"),
    "ssh_open": ("TA0001", "T1133", "External Remote Services",
                           "SSH exposed"),
    "winrm_open": ("TA0008", "T1021.006", "Remote Services: Windows Remote Management",
                           "WinRM available for lateral movement"),
    "mssql_open": ("TA0008", "T1021", "Remote Services",
                           "MSSQL accessible — potential for xp_cmdshell abuse"),
}

SERVICE_FINDING_MAP = {
    "rdp": "rdp_open", "ms-wbt-server": "rdp_open",
    "ssh": "ssh_open",
    "winrm": "winrm_open", "wsman": "winrm_open",
    "ms-sql-s": "mssql_open", "mssql": "mssql_open",
}

class RedOpsEngine:
    def __init__(self, lib_path: str = "./redops_engine.so"):
        try:
            self._lib = ctypes.CDLL(lib_path)
        except OSError as e:
            sys.exit(f"{R}[!] Engine load failed: {e}{RST}\n"
                     " Compile: gcc -shared -fPIC -O2 -o redops_engine.so redops_engine.c")
        self._lib.parse_and_serialize.restype = ctypes.c_size_t
        self._lib.parse_and_serialize.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_int
        ]
        self._lib.quick_stats.restype = None
        self._lib.quick_stats.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                           ctypes.c_char_p, ctypes.c_int]

    def parse(self, text: str, tool_hint: int = 0) -> dict:
        encoded = text.encode("utf-8", errors="replace")
        buf_size = max(len(encoded) * 20, 512 * 1024)
        out_buf = ctypes.create_string_buffer(buf_size)
        written = self._lib.parse_and_serialize(
            encoded, len(encoded), out_buf, buf_size, tool_hint)
        raw = out_buf.raw[:written].decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"hosts": [], "vulns": [], "creds": [], "meta": {"lines": 0, "errors": 1}}

    def quick_stats(self, text: str, tool_hint: int = 0) -> tuple[int, int, int, int]:
        encoded = text.encode("utf-8", errors="replace")
        out = ctypes.create_string_buffer(64)
        self._lib.quick_stats(encoded, len(encoded), out, tool_hint)
        parts = out.value.decode().split(",")
        return tuple(int(p) for p in parts) if len(parts) == 4 else (0, 0, 0, 0)

STORE_DIR = Path.home() / ".redops" / "campaigns"

def load_campaign(name: str) -> dict:
    path = STORE_DIR / f"{name}.json"
    if path.exists():
        return json.loads(path.read_text())
    return {
        "name": name,
        "created": datetime.datetime.utcnow().isoformat(),
        "updated": datetime.datetime.utcnow().isoformat(),
        "hosts": [], "vulns": [], "creds": [],
        "ingested_files": [], "ttps": [],
    }

def save_campaign(data: dict):
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    data["updated"] = datetime.datetime.utcnow().isoformat()
    path = STORE_DIR / f"{data['name']}.json"
    path.write_text(json.dumps(data, indent=2))

def list_campaigns() -> list[str]:
    if not STORE_DIR.exists():
        return []
    return [p.stem for p in STORE_DIR.glob("*.json")]

def enrich_host(host: dict) -> list[dict]:
    extra = []
    svc = host.get("service", "").lower()
    for k, v in SERVICE_FINDING_MAP.items():
        if k in svc:
            extra.append({
                "type": v, "host": host.get("ip", ""),
                "detail": f"Port {host.get('port','?')}/{host.get('proto','tcp')} "
                          f"({host.get('service','?')} {host.get('version','')})".strip(),
                "sev": 2,
            })
    if host.get("port") in ("80", "443", "8080", "8443"):
        extra.append({
            "type": "web_service", "host": host.get("ip", ""),
            "detail": f"Web service on port {host.get('port','')}",
            "sev": 1,
        })
    return extra

def dedup(items: list[dict], key_fields: list[str]) -> list[dict]:
    seen, out = set(), []
    for item in items:
        k = tuple(item.get(f, "") for f in key_fields)
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out

def compute_ttps(campaign: dict) -> list[dict]:
    ttps: dict[str, dict] = {}
    all_vulns = campaign.get("vulns", [])
    for v in all_vulns:
        ftype = v.get("type", "")
        if ftype == "open_port":
            ftype = SERVICE_FINDING_MAP.get(v.get("detail","").split()[0].lower(), "open_port")
        if ftype in MITRE_MAP:
            tactic_id, tech_id, tech_name, tech_desc = MITRE_MAP[ftype]
            key = tech_id
            if key not in ttps:
                ttps[key] = {
                    "tactic_id": tactic_id, "tech_id": tech_id,
                    "tech_name": tech_name, "description": tech_desc,
                    "count": 0, "hosts": set(),
                }
            ttps[key]["count"] += 1
            ttps[key]["hosts"].add(v.get("host", "unknown"))
    result = []
    for t in sorted(ttps.values(), key=lambda x: x["tactic_id"]):
        result.append({**t, "hosts": sorted(t["hosts"])})
    return result

TACTIC_ORDER = {
    "TA0001": 1, "TA0002": 2, "TA0003": 3, "TA0004": 4,
    "TA0005": 5, "TA0006": 6, "TA0007": 7, "TA0008": 8,
    "TA0009": 9, "TA0010": 10, "TA0011": 11,
}

TACTIC_NAMES = {
    "TA0001": "Initial Access", "TA0002": "Execution",
    "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access",
    "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0010": "Exfiltration",
    "TA0011": "C2",
}

def analyze_attack_path(campaign: dict) -> list[str]:
    vulns = {v["type"] for v in campaign.get("vulns", [])}
    creds = campaign.get("creds", [])
    hosts = campaign.get("hosts", [])
    paths = []
    indent = " "
    has_smb_relay = "smb_signing_disabled" in vulns
    has_local_admin= "local_admin" in vulns
    has_creds = len(creds) > 0
    has_hashes = any("sam_dump" in c.get("proto","") for c in creds)
    has_rdp = "rdp_open" in vulns
    has_winrm = "winrm_open" in vulns
    has_mssql = "mssql_open" in vulns
    open_ports = {h.get("port","") for h in hosts}

    if has_smb_relay:
        paths.append(f"{Y}[RELAY]{RST} SMB signing disabled on {sum(1 for v in campaign['vulns'] if v['type']=='smb_signing_disabled')} host(s)")
        paths.append(f"{indent}→ Capture NTLM hashes via responder/LLMNR poisoning")
        paths.append(f"{indent}→ Relay to authenticated SMB sessions with ntlmrelayx")
    if has_rdp:
        paths.append(f"{Y}[RDP]{RST} RDP exposed — brute force / password spray vector")
        paths.append(f"{indent}→ Spray against discovered usernames at low rate")
    if has_mssql:
        paths.append(f"{Y}[MSSQL]{RST} MSSQL accessible")
        paths.append(f"{indent}→ Test for sa/default creds, check xp_cmdshell, linked servers")

    if has_creds and has_smb_relay:
        paths.append(f"{G}[LATERAL]{RST} Credentials + SMB relay chain possible")
        paths.append(f"{indent}→ Use obtained creds with ntlmrelayx to pivot")
    if has_local_admin:
        n = sum(1 for v in campaign["vulns"] if v["type"] == "local_admin")
        paths.append(f"{G}[LATERAL]{RST} Local admin confirmed on {n} host(s)")
        paths.append(f"{indent}→ Use wmiexec/psexec/smbexec for lateral movement")
        if has_winrm:
            paths.append(f"{indent}→ WinRM available — use evil-winrm for interactive shell")

    if has_local_admin and not has_hashes:
        paths.append(f"{C}[CREDS]{RST} Local admin available — consider credential extraction")
        paths.append(f"{indent}→ Dump LSA secrets, LSASS (with EDR awareness)")
        paths.append(f"{indent}→ Consider safer in-memory techniques")
    if has_hashes:
        paths.append(f"{M}[HASHES]{RST} NTLM hashes captured")
        paths.append(f"{indent}→ Attempt pass-the-hash against discovered SMB hosts")
        paths.append(f"{indent}→ Submit to cracking — check for reuse across hosts")

    domain_hosts = [h for h in hosts if h.get("service","").lower() in ("kerberos","ldap","msrpc")]
    if domain_hosts:
        paths.append(f"{R}[DOMAIN]{RST} Domain services visible ({len(domain_hosts)} hosts)")
        paths.append(f"{indent}→ Enumerate with BloodHound/ldapdomaindump")
        paths.append(f"{indent}→ Check for Kerberoastable SPNs, AS-REP roasting")
        paths.append(f"{indent}→ Review ACL paths to Domain Admin")

    if not paths:
        paths.append(f"{DIM}No clear attack paths derived yet. Ingest more tool output.{RST}")
    return paths

def render_text_report(campaign: dict) -> str:
    lines = []
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines += [
        "═"*70,
        f" RED TEAM CAMPAIGN REPORT — {campaign['name'].upper()}",
        f" Generated: {ts}",
        "═"*70, "",
        f" Campaign Created : {campaign.get('created','?')[:10]}",
        f" Last Updated : {campaign.get('updated','?')[:10]}",
        f" Files Ingested : {len(campaign.get('ingested_files',[]))}",
        "",
        "─"*70,
        " SUMMARY",
        "─"*70,
        f" Hosts identified : {len(set(h.get('ip','') for h in campaign.get('hosts',[])) - {''})}",
        f" Vulnerabilities : {len(campaign.get('vulns',[]))} "
          f"(CRIT:{sum(1 for v in campaign.get('vulns',[]) if v.get('sev',0)==4)} "
          f"HIGH:{sum(1 for v in campaign.get('vulns',[]) if v.get('sev',0)==3)})",
        f" Credentials : {len(campaign.get('creds',[]))}",
        "",
    ]

    lines += ["─"*70, " FINDINGS (by severity)", "─"*70]
    for sev in [4, 3, 2, 1, 0]:
        vlist = [v for v in campaign.get("vulns", []) if v.get("sev", 0) == sev]
        if vlist:
            lines.append(f"\n [{SEV_NAME[sev]}]")
            for v in vlist:
                lines.append(f" {v.get('host','?'):18} {v.get('type','?'):<28} {v.get('detail','')[:40]}")

    ttps = compute_ttps(campaign)
    if ttps:
        lines += ["", "─"*70, " MITRE ATT&CK COVERAGE", "─"*70]
        for t in ttps:
            tname = TACTIC_NAMES.get(t["tactic_id"], t["tactic_id"])
            lines.append(f" {t['tech_id']:<14} {t['tech_name']:<42} [{tname}]")
            lines.append(f" Observed on: {', '.join(t['hosts'][:5])}"
                        + ("…" if len(t["hosts"]) > 5 else ""))

    creds = campaign.get("creds", [])
    if creds:
        lines += ["", "─"*70, f" CREDENTIALS ({len(creds)} captured)", "─"*70]
        for c in creds[:20]:
            lines.append(f" {c.get('host','?'):18} {c.get('proto','?'):<14} {c.get('cred','')[:40]}")
        if len(creds) > 20:
            lines.append(f" … and {len(creds)-20} more")

    lines += ["", "═"*70]
    return "\n".join(lines)

def render_html_report(campaign: dict) -> str:
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    ttps = compute_ttps(campaign)
    crit = sum(1 for v in campaign.get("vulns",[]) if v.get("sev",0)==4)
    high = sum(1 for v in campaign.get("vulns",[]) if v.get("sev",0)==3)
    med = sum(1 for v in campaign.get("vulns",[]) if v.get("sev",0)==2)
    ips = len(set(h.get("ip","") for h in campaign.get("hosts",[])) - {""})
    sev_colors = {4:"#c0392b",3:"#e67e22",2:"#f1c40f",1:"#2ecc71",0:"#95a5a6"}
    sev_names = {4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW",0:"INFO"}

    vuln_rows = ""
    for v in sorted(campaign.get("vulns",[]), key=lambda x: -x.get("sev",0)):
        sc = sev_colors.get(v.get("sev",0),"#aaa")
        sn = sev_names.get(v.get("sev",0),"?")
        vuln_rows += f'<tr><td style="color:{sc};font-weight:bold">{sn}</td><td>{v.get("host","")}</td><td>{v.get("type","")}</td><td>{v.get("detail","")[:80]}</td></tr>\n'

    ttp_rows = ""
    for t in ttps:
        tname = TACTIC_NAMES.get(t["tactic_id"], t["tactic_id"])
        ttp_rows += f'<tr><td>{t["tech_id"]}</td><td>{t["tech_name"]}</td><td>{tname}</td><td>{", ".join(t["hosts"][:4])}</td></tr>\n'

    cred_rows = ""
    for c in campaign.get("creds",[])[:30]:
        cred_rows += f'<tr><td>{c.get("host","")}</td><td>{c.get("proto","")}</td><td><code>{c.get("cred","")[:50]}</code></td></tr>\n'

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>RedOps Report — {campaign['name']}</title>
<style>
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;margin:40px;line-height:1.6}}
h1{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px}}
h2{{color:#79c0ff;margin-top:2rem}}
.meta{{color:#8b949e;font-size:0.9em}}
.cards{{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 24px;min-width:140px}}
.card .n{{font-size:2em;font-weight:bold}}
.card .l{{font-size:0.8em;color:#8b949e}}
.crit{{color:#f85149}}.high{{color:#f0883e}}.med{{color:#d29922}}.ok{{color:#3fb950}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th{{background:#161b22;color:#79c0ff;text-align:left;padding:8px 12px;font-size:0.85em;border-bottom:1px solid #30363d}}
td{{padding:7px 12px;border-bottom:1px solid #21262d;font-size:0.9em}}
tr:hover td{{background:#161b22}}
code{{background:#161b22;padding:2px 6px;border-radius:4px;color:#d2a8ff}}
</style></head><body>
<h1>RedOps Campaign Report</h1>
<p class="meta">Campaign: <strong>{campaign['name']}</strong> &nbsp;·&nbsp; Generated: {ts}</p>
<div class="cards">
  <div class="card"><div class="n ok">{ips}</div><div class="l">HOSTS</div></div>
  <div class="card"><div class="n crit">{crit}</div><div class="l">CRITICAL</div></div>
  <div class="card"><div class="n high">{high}</div><div class="l">HIGH</div></div>
  <div class="card"><div class="n med">{med}</div><div class="l">MEDIUM</div></div>
  <div class="card"><div class="n ok">{len(campaign.get('creds',[]))}</div><div class="l">CREDENTIALS</div></div>
  <div class="card"><div class="n" style="color:#58a6ff">{len(ttps)}</div><div class="l">MITRE TTPs</div></div>
</div>
<h2>Vulnerability Findings</h2>
<table><tr><th>SEVERITY</th><th>HOST</th><th>TYPE</th><th>DETAIL</th></tr>
{vuln_rows or '<tr><td colspan=4 style="color:#8b949e">No findings yet</td></tr>'}
</table>
<h2>MITRE ATT&CK Coverage</h2>
<table><tr><th>TECHNIQUE</th><th>NAME</th><th>TACTIC</th><th>HOSTS</th></tr>
{ttp_rows or '<tr><td colspan=4 style="color:#8b949e">No mappings yet</td></tr>'}
</table>
<h2>Captured Credentials</h2>
<table><tr><th>HOST</th><th>PROTOCOL</th><th>CREDENTIAL</th></tr>
{cred_rows or '<tr><td colspan=3 style="color:#8b949e">No credentials yet</td></tr>'}
</table>
</body></html>"""

def cmd_ingest(args, engine: RedOpsEngine):
    path = Path(args.file)
    if not path.exists():
        sys.exit(f"{R}[!] File not found: {path}{RST}")
    text = path.read_text(errors="replace")
    hint = TOOL_HINTS.get(args.tool or "auto", 0)
    file_hash = hashlib.sha256(text.encode()).hexdigest()[:12]
    print(f" {G}[+]{RST} Parsing {path.name} ({len(text):,} chars) via C engine …")
    parsed = engine.parse(text, hint)
    campaign = load_campaign(args.campaign)

    if file_hash in campaign.get("ingested_files", []):
        print(f" {Y}[~]{RST} File already ingested (hash: {file_hash})")
        return

    new_hosts = parsed.get("hosts", [])
    extra_vulns = []
    for h in new_hosts:
        extra_vulns.extend(enrich_host(h))
    new_vulns = parsed.get("vulns", []) + extra_vulns

    campaign["hosts"] = dedup(campaign["hosts"] + new_hosts, ["ip", "port", "proto"])
    campaign["vulns"] = dedup(campaign["vulns"] + new_vulns, ["type", "host"])
    campaign["creds"] = dedup(campaign["creds"] + parsed.get("creds", []), ["cred", "host"])
    campaign.setdefault("ingested_files", []).append(file_hash)
    save_campaign(campaign)

    meta = parsed.get("meta", {})
    print(f" {G}[+]{RST} Lines processed : {meta.get('lines', 0)}")
    print(f" {G}[+]{RST} New hosts : {len(new_hosts)}")
    print(f" {G}[+]{RST} New vulns : {len(new_vulns)}")
    print(f" {G}[+]{RST} New credentials : {len(parsed.get('creds', []))}")
    print(f" {G}[+]{RST} Campaign totals : {len(campaign['hosts'])} hosts / "
          f"{len(campaign['vulns'])} vulns / {len(campaign['creds'])} creds")

def cmd_status(args, _engine):
    camps = [args.campaign] if args.campaign else list_campaigns()
    if not camps:
        print(f" {Y}No campaigns found.{RST} Run: redops.py ingest --campaign <name>")
        return
    print(f"\n {'CAMPAIGN':<24} {'HOSTS':>6} {'VULNS':>6} {'CRIT':>5} {'CREDS':>6} UPDATED")
    print(f" {'─'*24} {'─'*6} {'─'*6} {'─'*5} {'─'*6} {'─'*16}")
    for name in camps:
        c = load_campaign(name)
        crit = sum(1 for v in c.get("vulns",[]) if v.get("sev",0)==4)
        ips = len(set(h.get("ip","") for h in c.get("hosts",[])) - {""})
        cc = SEV_COLOR[4 if crit else 0]
        print(f" {name:<24} {ips:>6} {len(c.get('vulns',[])):>6} "
              f"{cc}{crit:>5}{RST} {len(c.get('creds',[])):>6} "
              f"{c.get('updated','?')[:16]}")

def cmd_findings(args, _engine):
    campaign = load_campaign(args.campaign)
    ftype = getattr(args, "type", None)
    min_sev = int(getattr(args, "sev", 0) or 0)

    if ftype in (None, "vuln"):
        vulns = [v for v in campaign.get("vulns", []) if v.get("sev", 0) >= min_sev]
        print(f"\n {BLD}VULNERABILITIES ({len(vulns)}){RST}")
        print(f" {'SEV':<6} {'HOST':<18} {'TYPE':<30} DETAIL")
        print(f" {'─'*6} {'─'*18} {'─'*30} {'─'*30}")
        for v in sorted(vulns, key=lambda x: -x.get("sev", 0)):
            sc = SEV_COLOR.get(v.get("sev", 0), W)
            sn = SEV_NAME.get(v.get("sev", 0), "?")
            print(f" {sc}{sn:<6}{RST} {v.get('host','?'):<18} "
                  f"{v.get('type','?'):<30} {v.get('detail','')[:40]}")

    if ftype in (None, "cred"):
        creds = campaign.get("creds", [])
        print(f"\n {BLD}CREDENTIALS ({len(creds)}){RST}")
        for c in creds[:30]:
            print(f" {c.get('host','?'):<18} {c.get('proto','?'):<14} {c.get('cred','')[:50]}")
        if len(creds) > 30:
            print(f" … {len(creds)-30} more")

def cmd_ttps(args, _engine):
    campaign = load_campaign(args.campaign)
    ttps = compute_ttps(campaign)
    if not ttps:
        print(f" {Y}No MITRE TTPs mapped yet. Ingest more tool output.{RST}")
        return
    print(f"\n {BLD}MITRE ATT&CK COVERAGE — {campaign['name'].upper()}{RST}\n")
    cur_tactic = None
    for t in ttps:
        tname = TACTIC_NAMES.get(t["tactic_id"], t["tactic_id"])
        if tname != cur_tactic:
            print(f" {C}{BLD}[{t['tactic_id']}] {tname}{RST}")
            cur_tactic = tname
        hosts_str = ", ".join(t["hosts"][:4]) + ("…" if len(t["hosts"]) > 4 else "")
        print(f" {Y}{t['tech_id']:<14}{RST} {t['tech_name']:<44} {DIM}×{t['count']}{RST}")
        print(f" {DIM}{t['description']}{RST}")
        print(f" {DIM}Hosts: {hosts_str}{RST}\n")

def cmd_path(args, _engine):
    campaign = load_campaign(args.campaign)
    paths = analyze_attack_path(campaign)
    print(f"\n {BLD}ATTACK PATH ANALYSIS — {campaign['name'].upper()}{RST}\n")
    for line in paths:
        print(f" {line}")
    print()

def cmd_report(args, _engine):
    campaign = load_campaign(args.campaign)
    fmt = getattr(args, "format", "text") or "text"
    out_path = getattr(args, "out", None)

    if fmt == "json":
        content = json.dumps(campaign, indent=2)
        ext = "json"
    elif fmt == "html":
        content = render_html_report(campaign)
        ext = "html"
    else:
        content = render_text_report(campaign)
        ext = "txt"

    if out_path:
        Path(out_path).write_text(content)
        print(f" {G}[+]{RST} Report written: {out_path}")
    else:
        if ext == "html":
            default = f"redops_{campaign['name']}_report.html"
            Path(default).write_text(content)
            print(f" {G}[+]{RST} HTML report saved: {default}")
        else:
            print(content)

def cmd_clear(args, _engine):
    path = STORE_DIR / f"{args.campaign}.json"
    if path.exists():
        path.unlink()
        print(f" {G}[+]{RST} Campaign '{args.campaign}' cleared.")
    else:
        print(f" {Y}[~]{RST} Campaign not found: {args.campaign}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(prog="redops.py", description="RedOps — Red Team Campaign Intelligence")
    sub = parser.add_subparsers(dest="command")

    p_in = sub.add_parser("ingest")
    p_in.add_argument("--file", required=True)
    p_in.add_argument("--tool", default="auto", choices=["auto","nmap","cme","cred"])
    p_in.add_argument("--campaign", default="default")
    p_in.add_argument("--lib", default="./redops_engine.so")

    p_st = sub.add_parser("status")
    p_st.add_argument("--campaign", default=None)
    p_st.add_argument("--lib", default="./redops_engine.so")

    p_fi = sub.add_parser("findings")
    p_fi.add_argument("--campaign", default="default")
    p_fi.add_argument("--type", default=None, choices=["host","vuln","cred"])
    p_fi.add_argument("--sev", default=0, type=int)
    p_fi.add_argument("--lib", default="./redops_engine.so")

    p_tt = sub.add_parser("ttps")
    p_tt.add_argument("--campaign", default="default")
    p_tt.add_argument("--lib", default="./redops_engine.so")

    p_pa = sub.add_parser("path")
    p_pa.add_argument("--campaign", default="default")
    p_pa.add_argument("--lib", default="./redops_engine.so")

    p_rp = sub.add_parser("report")
    p_rp.add_argument("--campaign", default="default")
    p_rp.add_argument("--format", default="text", choices=["text","json","html"])
    p_rp.add_argument("--out", default=None)
    p_rp.add_argument("--lib", default="./redops_engine.so")

    p_cl = sub.add_parser("clear")
    p_cl.add_argument("--campaign", required=True)
    p_cl.add_argument("--lib", default="./redops_engine.so")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    lib_path = getattr(args, "lib", "./redops_engine.so")
    engine = RedOpsEngine(lib_path)
    print(f" {G}[+]{RST} Engine loaded : {lib_path}")
    if hasattr(args, "campaign") and args.campaign:
        print(f" {G}[+]{RST} Campaign : {args.campaign}")
    print()

    dispatch = {
        "ingest": cmd_ingest,
        "status": cmd_status,
        "findings": cmd_findings,
        "ttps": cmd_ttps,
        "path": cmd_path,
        "report": cmd_report,
        "clear": cmd_clear,
    }
    dispatch[args.command](args, engine)

if __name__ == "__main__":
    main()
