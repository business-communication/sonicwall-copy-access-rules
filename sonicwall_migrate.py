#!/usr/bin/env python3
"""
SonicWall access-rule cloner — sonicwall_migrace_v12_3.py

Delta vs v12.2:
- **Human‑friendly logging** for *both* [SKIP] Duplicate and [OK] Created lines.
  Each line now includes **source**, **destination** (AO or Group), **service** (service or service group),
  and **ports** (if present) so you can see exactly what was acted on.
- Keeps shape‑mirroring and negotiation logic from v12.2 for address/service groups.

Author: M365 Copilot for Libor Klepáč
"""
import argparse
import json
import re
from typing import Dict, List, Optional, Set, Tuple

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
requests.packages.urllib3.disable_warnings()

API_ROOT = "/api/sonicos"

# ----------------------------- Utilities -----------------------------

def _norm(s: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).casefold() if s is not None else ""

def _check_ok(resp: requests.Response, err: str) -> None:
    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"{err}. HTTP {resp.status_code}. Body: {resp.text[:2000]}")
    try:
        data = resp.json()
    except Exception:
        return
    if isinstance(data, dict) and "status" in data:
        st = data.get("status") or {}
        if not isinstance(st, dict) or st.get("success") is not True:
            raise RuntimeError(f"{err}. HTTP {resp.status_code}. Body: {resp.text[:2000]}")

def _fail(resp: requests.Response, err: str) -> None:
    hdr = resp.headers.get("WWW-Authenticate", "")
    raise RuntimeError(
        f"{err}. HTTP {resp.status_code}. WWW-Authenticate: {hdr or 'n/a'}. Body: {resp.text[:1000]}"
    )

# -------------------------- GET wrappers (flat/wrapped) --------------------------

def _get_ao_node(entry: Dict, ipver: str) -> Optional[Dict]:
    if not isinstance(entry, dict):
        return None
    wrapped = entry.get("address_object") or {}
    if isinstance(wrapped, dict) and ipver in wrapped:
        return wrapped.get(ipver)
    return entry.get(ipver)

def _get_group_node(entry: Dict, ipver: str) -> Optional[Dict]:
    if not isinstance(entry, dict):
        return None
    wrapped = entry.get("address_group") or {}
    if isinstance(wrapped, dict) and ipver in wrapped:
        return wrapped.get(ipver)
    return entry.get(ipver)

def _get_rule_node(entry: Dict, ipver: str) -> Optional[Dict]:
    if not isinstance(entry, dict):
        return None
    wrapped = entry.get("access_rule") or {}
    if isinstance(wrapped, dict) and ipver in wrapped:
        return wrapped.get(ipver)
    return entry.get(ipver)

# ------------------------------- Auth -------------------------------

def login(session: requests.Session, base_url: str, username: str, password: str,
          verify: bool, auth_method: str = "auto") -> None:
    url = f"{base_url}{API_ROOT}/auth"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    body = {"override": True}

    def try_basic() -> requests.Response:
        return session.post(url, headers=headers, json=body,
                            auth=HTTPBasicAuth(username, password),
                            verify=verify, timeout=30)

    def try_digest() -> requests.Response:
        return session.post(url, headers=headers, json=body,
                            auth=HTTPDigestAuth(username, password),
                            verify=verify, timeout=30)

    am = (auth_method or "auto").lower()
    if am == "basic":
        resp = try_basic()
        try:
            _check_ok(resp, "Login (Basic) failed")
            data = resp.json()
            if isinstance(data, dict) and "status" in data and (data.get("status") or {}).get("success") is not True:
                _fail(resp, "Login (Basic) failed")
        except Exception:
            _fail(resp, "Login (Basic) failed")
        return

    if am == "digest":
        resp = try_digest()
        try:
            _check_ok(resp, "Login (Digest) failed")
            data = resp.json()
            if isinstance(data, dict) and "status" in data and (data.get("status") or {}).get("success") is not True:
                _fail(resp, "Login (Digest) failed")
        except Exception:
            _fail(resp, "Login (Digest) failed")
        return

    resp = try_basic()
    if resp.status_code == 200:
        try:
            data = resp.json()
            if isinstance(data, dict) and "status" in data and (data.get("status") or {}).get("success") is not True:
                _fail(resp, "Login (auto/basic) failed")
        except Exception:
            pass
        return
    www = resp.headers.get("WWW-Authenticate", "")
    if resp.status_code == 401 and "Digest" in (www or ""):
        resp2 = try_digest()
        if resp2.status_code == 200:
            try:
                data = resp2.json()
                if isinstance(data, dict) and "status" in data and (data.get("status") or {}).get("success") is not True:
                    _fail(resp2, "Login (auto→Digest) failed")
            except Exception:
                pass
            return
        _fail(resp2, "Login (auto→Digest) failed")
    else:
        _fail(resp, "Login (auto) failed")


def logout(session: requests.Session, base_url: str, verify: bool) -> None:
    try:
        session.delete(f"{base_url}{API_ROOT}/auth", verify=verify, timeout=30)
    except Exception:
        pass

# ------------------------------- API calls -------------------------------

def get_address_objects(session: requests.Session, base_url: str, verify: bool, ipver: str) -> List[Dict]:
    resp = session.get(f"{base_url}{API_ROOT}/address-objects/{ipver}", headers={"Accept":"application/json"}, verify=verify, timeout=30)
    _check_ok(resp, f"Fetching {ipver} address objects failed")
    return resp.json().get("address_objects", [])


def get_address_groups(session: requests.Session, base_url: str, verify: bool, ipver: str) -> List[Dict]:
    resp = session.get(f"{base_url}{API_ROOT}/address-groups/{ipver}", headers={"Accept":"application/json"}, verify=verify, timeout=30)
    _check_ok(resp, f"Fetching {ipver} address groups failed")
    return resp.json().get("address_groups", [])


def get_access_rules(session: requests.Session, base_url: str, verify: bool, ipver: str) -> List[Dict]:
    resp = session.get(f"{base_url}{API_ROOT}/access-rules/{ipver}", headers={"Accept":"application/json"}, verify=verify, timeout=60)
    _check_ok(resp, f"Fetching {ipver} access rules failed")
    return resp.json().get("access_rules", [])


def commit_pending(session: requests.Session, base_url: str, verify: bool, verbose: bool=False):
    url = f"{base_url}{API_ROOT}/config/pending"
    body = {"pending": {"modified": True}}
    resp = session.post(url, headers={"Accept":"application/json","Content-Type":"application/json"}, json=body, verify=verify, timeout=60)
    _check_ok(resp, "Commit failed")

# === Create (POST) ===

def _post_rule(session: requests.Session, base_url: str, verify: bool, ipver: str, ipv_payload: Dict, verbose: bool=False):
    url = f"{base_url}{API_ROOT}/access-rules/{ipver}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    # Preferred: collection / flat item
    body1 = {"access_rules": [{ipver: ipv_payload}]}
    resp = session.post(url, headers=headers, json=body1, verify=verify, timeout=60)
    if 200 <= resp.status_code < 300:
        _check_ok(resp, f"Creating {ipver} access rule failed: {resp.text}")
        return
    if verbose:
        print("[VERBOSE] POST body1 failed:", resp.status_code, resp.text[:300])
    # Fallback 1: collection / wrapped item
    body2 = {"access_rules": [{"access_rule": {ipver: ipv_payload}}]}
    resp2 = session.post(url, headers=headers, json=body2, verify=verify, timeout=60)
    if 200 <= resp2.status_code < 300:
        _check_ok(resp2, f"Creating {ipver} access rule failed: {resp2.text}")
        return
    if verbose:
        print("[VERBOSE] POST body2 failed:", resp2.status_code, resp2.text[:300])
    # Fallback 2: single object
    body3 = {"access_rule": {ipver: ipv_payload}}
    resp3 = session.post(url, headers=headers, json=body3, verify=verify, timeout=60)
    _check_ok(resp3, f"Creating {ipver} access rule (single-object retry) failed: {resp3.text}")

# ----------------------------- Parsing helpers -----------------------------

def _zone_name(val) -> str:
    if isinstance(val, dict):
        return (val.get("zone") or "").strip()
    if isinstance(val, str):
        return val.strip()
    return ""

def _extract_service_ref(rule_ip: Dict) -> Tuple[str, str, str]:
    """Return (ref_type, name, shape_hint) where shape_hint in {'service.group-str','service.group-name','service.name','service.any'}"""
    svc = rule_ip.get("service")
    if isinstance(svc, dict):
        if "name" in svc and svc.get("name"):
            return ("service", svc.get("name", ""), "service.name")
        grp = svc.get("group")
        if isinstance(grp, str) and grp:
            return ("service_group", grp, "service.group-str")
        if isinstance(grp, dict) and grp.get("name"):
            return ("service_group", grp.get("name", ""), "service.group-name")
        if svc.get("any") is True:
            return ("any", "any", "service.any")
        return ("any", "any", "service.any")
    if isinstance(svc, str):
        s = svc.strip()
        return ("any", "any", "service.any") if s.lower()=="any" else ("service", s, "service.name")
    return ("any", "any", "service.any")


def _extract_addr_ref(block: Dict) -> Tuple[str, str, str]:
    """Return (ref_type, name, shape_hint) where ref_type in {address, address_group, any}
       shape_hint in {'addrgroup','address.group-str','address.group-name','address.name','address.any','any'}
    """
    if not isinstance(block, dict):
        return ("any", "any", "any")
    a = block.get("address") or {}
    if isinstance(a, dict):
        if a.get("any") is True:
            return ("any", "any", "address.any")
        if "name" in a and a.get("name"):
            return ("address", a.get("name", ""), "address.name")
        g = a.get("group")
        if isinstance(g, str) and g:
            return ("address_group", g, "address.group-str")
        if isinstance(g, dict) and g.get("name"):
            return ("address_group", g.get("name", ""), "address.group-name")
    g2 = block.get("address_group") or {}
    if isinstance(g2, dict) and g2.get("name"):
        return ("address_group", g2.get("name", ""), "addrgroup")
    if block.get("any") is True:
        return ("any", "any", "any")
    return ("any", "any", "any")

# ---------------------- Build POST-safe blocks ----------------------

def _addr_block(addr_type: str, name: str, group_shape: str) -> Dict:
    if addr_type == 'address' and name:
        return {'address': {'name': name}}
    if addr_type == 'address_group' and name:
        if group_shape == 'address.group-str':
            return {'address': {'group': name}}
        if group_shape == 'address.group-name':
            return {'address': {'group': {'name': name}}}
        return {'address_group': {'name': name}}
    return {'address': {'any': True}}


def _service_block(v_type: str, v_name: str, svc_shape: str) -> dict:
    if v_type == 'service' and v_name:
        return {'name': v_name}
    if v_type == 'service_group' and v_name:
        if svc_shape == 'service.group-str':
            return {'group': v_name}
        else:
            return {'group': {'name': v_name}}
    return {'any': True}


def _extract_port_block(block: Dict) -> Optional[Dict]:
    if not isinstance(block, dict):
        return None
    p = block.get("port")
    if isinstance(p, dict) and p.get("any") is True:
        return {"any": True}
    return None


def _strip_volatile(ipnode: Dict):
    for k in ("uuid", "id", "statistics", "hit_counters"):
        ipnode.pop(k, None)

# ---------------------- Signature ----------------------

def build_rule_signature(rule_ip: Dict) -> Tuple:
    action = _norm(rule_ip.get("action"))
    fz = _norm(_zone_name(rule_ip.get("from")))
    tz = _norm(_zone_name(rule_ip.get("to")))
    s_type, s_name, _ = _extract_addr_ref(rule_ip.get("source") or {})
    d_type, d_name, _ = _extract_addr_ref(rule_ip.get("destination") or {})
    v_type, v_name, _ = _extract_service_ref(rule_ip)
    return (action, fz, tz, _norm(s_type), _norm(s_name), _norm(d_type), _norm(d_name), _norm(v_type), _norm(v_name))

# ---------------------- Friendly logging helpers ----------------------

def _fmt_side(ref_type: str, name: str, side_label: str) -> str:
    if ref_type == 'address' and name:
        return f"{side_label}=AO:'{name}'"
    if ref_type == 'address_group' and name:
        return f"{side_label}=Group:'{name}'"
    if ref_type == 'any':
        return f"{side_label}=any"
    return f"{side_label}=<unknown>"


def _fmt_service(v_type: str, v_name: str) -> str:
    if v_type == 'service' and v_name:
        return f"service='{v_name}'"
    if v_type == 'service_group' and v_name:
        return f"service-group='{v_name}'"
    return "service=any"


def _fmt_ports(src_block: Dict, dst_block: Dict) -> str:
    src_p = _extract_port_block(src_block or {})
    dst_p = _extract_port_block(dst_block or {})
    bits = []
    if src_p is not None:
        bits.append("src_port=any")
    if dst_p is not None:
        bits.append("dst_port=any")
    return (" | "+", ".join(bits)) if bits else ""

# ---------------------- Builders ----------------------

def build_payload_change_source(orig: Dict, ipver: str, new_from_zone: str, new_source_ao: str,
                                d_type: str, d_name: str, d_shape_hint: str,
                                v_type: str, v_name: str, svc_shape: str, group_shape: str,
                                copy_ports: bool, copy_name: bool, copy_comment: bool, name_prefix: str) -> Dict:
    to_zone = _zone_name(orig.get("to"))
    dest_block = _addr_block(d_type, d_name, group_shape)
    service = _service_block(v_type, v_name, svc_shape)
    action = orig.get("action") or "allow"
    ipv = {
        "from": new_from_zone,
        "to": to_zone,
        "action": action,
        "source": {"address": {"name": new_source_ao}},
        "destination": dest_block,
        "service": service,
        "enable": True,
    }
    if copy_ports:
        sp = _extract_port_block(orig.get("source") or {})
        if sp:
            ipv["source"]["port"] = sp
        dp = _extract_port_block(orig.get("destination") or {})
        if dp:
            ipv.setdefault("destination", dest_block)["port"] = dp
    if copy_name and isinstance(orig.get("name"), str) and orig.get("name").strip():
        nm = orig.get("name").strip()
        ipv["name"] = f"{name_prefix}{nm}" if name_prefix else nm
    if copy_comment and isinstance(orig.get("comment"), str):
        ipv["comment"] = orig.get("comment")
    _strip_volatile(ipv)
    return ipv


def build_payload_change_destination(orig: Dict, ipver: str, new_to_zone: str, new_dest_ao: str,
                                     s_type: str, s_name: str, s_shape_hint: str,
                                     v_type: str, v_name: str, svc_shape: str, group_shape: str,
                                     copy_ports: bool, copy_name: bool, copy_comment: bool, name_prefix: str) -> Dict:
    from_zone = _zone_name(orig.get("from"))
    src_block = _addr_block(s_type, s_name, group_shape)
    service = _service_block(v_type, v_name, svc_shape)
    action = orig.get("action") or "allow"
    ipv = {
        "from": from_zone,
        "to": new_to_zone,
        "action": action,
        "source": src_block,
        "destination": {"address": {"name": new_dest_ao}},
        "service": service,
        "enable": True,
    }
    if copy_ports:
        sp = _extract_port_block(orig.get("source") or {})
        if sp:
            ipv["source"]["port"] = sp
        dp = _extract_port_block(orig.get("destination") or {})
        if dp:
            ipv["destination"]["port"] = dp
    if copy_name and isinstance(orig.get("name"), str) and orig.get("name").strip():
        nm = orig.get("name").strip()
        ipv["name"] = f"{name_prefix}{nm}" if name_prefix else nm
    if copy_comment and isinstance(orig.get("comment"), str):
        ipv["comment"] = orig.get("comment")
    _strip_volatile(ipv)
    return ipv

# ---------------------- Main ----------------------

def main():
    ap = argparse.ArgumentParser(description="Clone SonicWall access rules (v12.3: friendly logging + shape mirroring)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--source-ao", required=True)
    ap.add_argument("--target-ao", required=True)
    ap.add_argument("--verify-ssl", type=str, default="false", help="true|false")
    ap.add_argument("--commit", type=str, default="false", help="true|false")
    ap.add_argument("--dry-run", type=str, default="true", help="true|false")
    ap.add_argument("--include-destination", type=str, default="true")
    ap.add_argument("--include-groups", type=str, default="true")
    ap.add_argument("--copy-ports", type=str, default="true")
    ap.add_argument("--copy-name", type=str, default="true")
    ap.add_argument("--copy-comment", type=str, default="true")
    ap.add_argument("--name-prefix", type=str, default="")
    ap.add_argument("--auth-method", type=str, default="auto", help="basic|digest|auto")
    ap.add_argument("--group-post-order", type=str, default="address.group-str,address.group-name,addrgroup")
    ap.add_argument("--service-group-post-order", type=str, default="service.group-str,service.group-name")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    verify = args.verify_ssl.lower() == "true"
    do_commit = args.commit.lower() == "true"
    dry_run = args.dry_run.lower() == "true"
    include_dst = args.include_destination.lower() == "true"
    include_groups = args.include_groups.lower() == "true"
    copy_ports = args.copy_ports.lower() == "true"
    copy_name = args.copy_name.lower() == "true"
    copy_comment = args.copy_comment.lower() == "true"
    name_prefix = args.name_prefix

    group_shapes = [s.strip() for s in (args.group_post_order or "").split(',') if s.strip()]
    if not group_shapes:
        group_shapes = ["address.group-str", "address.group-name", "addrgroup"]
    svc_shapes = [s.strip() for s in (args.service_group_post_order or "").split(',') if s.strip()]
    if not svc_shapes:
        svc_shapes = ["service.group-str", "service.group-name"]

    base_url = f"https://{args.host}:{args.port}"

    with requests.Session() as s:
        try:
            # Login
            url_auth = f"{base_url}{API_ROOT}/auth"
            headers = {"Accept":"application/json","Content-Type":"application/json"}
            body = {"override": True}
            # auto basic->digest
            resp = s.post(url_auth, headers=headers, json=body, auth=HTTPBasicAuth(args.username, args.password), verify=verify, timeout=30)
            if resp.status_code == 401 and 'Digest' in (resp.headers.get('WWW-Authenticate') or ''):
                resp = s.post(url_auth, headers=headers, json=body, auth=HTTPDigestAuth(args.username, args.password), verify=verify, timeout=30)
            _check_ok(resp, "Login failed")

            # Discover AO family and zones (ipv4/ipv6)
            def detect_family(ao_name: str) -> Tuple[str, Dict]:
                r = s.get(f"{base_url}{API_ROOT}/address-objects/ipv4", headers={"Accept":"application/json"}, verify=verify, timeout=30)
                _check_ok(r, "Fetch AO IPv4 failed")
                for e in r.json().get("address_objects", []):
                    v = e.get('ipv4') or e.get('address_object',{}).get('ipv4')
                    if v and _norm(v.get('name')) == _norm(ao_name):
                        return 'ipv4', v
                r6 = s.get(f"{base_url}{API_ROOT}/address-objects/ipv6", headers={"Accept":"application/json"}, verify=verify, timeout=30)
                _check_ok(r6, "Fetch AO IPv6 failed")
                for e in r6.json().get("address_objects", []):
                    v = e.get('ipv6') or e.get('address_object',{}).get('ipv6')
                    if v and _norm(v.get('name')) == _norm(ao_name):
                        return 'ipv6', v
                raise SystemExit(f"AO not found: {ao_name}")

            fam_src, src_ao = detect_family(args.source_ao)
            fam_tgt, tgt_ao = detect_family(args.target_ao)
            if fam_src != fam_tgt:
                raise SystemExit("Address family mismatch between source and target AO")
            ipver = fam_src
            src_zone = src_ao.get('zone'); tgt_zone = tgt_ao.get('zone')
            print(f"[INFO] Operating family: {ipver.upper()}")
            print(f"[INFO] Source AO '{src_ao.get('name')}' zone: {src_zone}")
            print(f"[INFO] Target AO '{tgt_ao.get('name')}' zone: {tgt_zone}")

            # Get rules
            rules = get_access_rules(s, base_url, verify, ipver)

            # Build dedupe set
            existing_sigs: Set[Tuple] = set()
            for item in rules:
                rnode = _get_rule_node(item or {}, ipver)
                if rnode:
                    existing_sigs.add(build_rule_signature(rnode))

            def zone_eq(z, want):
                return _norm(_zone_name(z)) == _norm(want)

            created = 0

            # SOURCE-as-AO (mirror/try group shape on DEST if group)
            src_ao_rules = []
            for item in rules:
                rnode = _get_rule_node(item or {}, ipver)
                if not rnode: continue
                if not zone_eq(rnode.get('from'), src_zone): continue
                s_type, s_name, s_hint = _extract_addr_ref(rnode.get('source') or {})
                if s_type=='address' and _norm(s_name)==_norm(args.source_ao):
                    src_ao_rules.append(item)
            print(f"[INFO] SOURCE-as-AO matches: {len(src_ao_rules)}")

            for item in src_ao_rules:
                orig = _get_rule_node(item or {}, ipver) or {}
                # Destination may be a group — mirror its shape
                d_type, d_name, d_hint = _extract_addr_ref(orig.get('destination') or {})
                v_type, v_name, v_hint = _extract_service_ref(orig)

                # service shapes order: mirror first if applicable
                svc_order = []
                if v_type=='service_group':
                    if v_hint in ('service.group-str','service.group-name'):
                        svc_order.append(v_hint)
                svc_order.extend([x for x in svc_shapes if x not in svc_order])

                # group shapes order: mirror first if dest is group
                grp_order = []
                if d_type=='address_group' and d_hint in ('address.group-str','address.group-name','addrgroup'):
                    grp_order.append(d_hint)
                grp_order.extend([x for x in group_shapes if x not in grp_order])

                posted=False; last_err=None
                for sshape in svc_order:
                    # Friendly log context (original rule fields)
                    src_disp = _fmt_side('address', args.target_ao, 'src')
                    dst_disp = _fmt_side(d_type, d_name, 'dst')
                    svc_disp = _fmt_service(v_type, v_name)
                    ports_disp = _fmt_ports(orig.get('source') or {}, orig.get('destination') or {})

                    if d_type=='address_group':
                        for gshape in grp_order:
                            ipv = build_payload_change_source(orig, ipver, tgt_zone, args.target_ao,
                                                              d_type, d_name, d_hint,
                                                              v_type, v_name, sshape, gshape,
                                                              copy_ports, copy_name, copy_comment, name_prefix)
                            sig = build_rule_signature(ipv)
                            if sig in existing_sigs:
                                print(f"[SKIP] Duplicate (SOURCE-as-AO) | {src_disp} | {dst_disp} | {svc_disp}{ports_disp}")
                                posted=True; break
                            try:
                                if dry_run:
                                    print(json.dumps({"access_rules":[{ipver: ipv}]}, indent=2)); posted=True
                                else:
                                    _post_rule(s, base_url, verify, ipver, ipv, verbose=args.verbose); posted=True
                                existing_sigs.add(sig); created+=1
                                print(f"[OK] Created SOURCE-as-AO clone | {src_disp} | {dst_disp} | {svc_disp}{ports_disp} (destgrp={gshape}, svc={sshape})")
                                break
                            except Exception as e:
                                last_err=e; continue
                        if posted: break
                    else:
                        ipv = build_payload_change_source(orig, ipver, tgt_zone, args.target_ao,
                                                          d_type, d_name, d_hint,
                                                          v_type, v_name, sshape, group_shapes[0],
                                                          copy_ports, copy_name, copy_comment, name_prefix)
                        sig = build_rule_signature(ipv)
                        if sig in existing_sigs:
                            print(f"[SKIP] Duplicate (SOURCE-as-AO) | {src_disp} | {dst_disp} | {svc_disp}{ports_disp}")
                            posted=True; break
                        try:
                            if dry_run:
                                print(json.dumps({"access_rules":[{ipver: ipv}]}, indent=2)); posted=True
                            else:
                                _post_rule(s, base_url, verify, ipver, ipv, verbose=args.verbose); posted=True
                            existing_sigs.add(sig); created+=1
                            print(f"[OK] Created SOURCE-as-AO clone | {src_disp} | {dst_disp} | {svc_disp}{ports_disp} (svc={sshape})")
                        except Exception as e:
                            last_err=e; continue
                if not posted and last_err:
                    print(f"[ERROR] SOURCE-as-AO clone failed: {last_err}")

            # SOURCE-in-GROUP
            src_grp_rules: List[Tuple[Dict, str]] = []
            for item in rules:
                rnode = _get_rule_node(item or {}, ipver)
                if not rnode: continue
                if not zone_eq(rnode.get('from'), src_zone): continue
                s_type, g_name, s_hint = _extract_addr_ref(rnode.get('source') or {})
                if s_type=='address_group':
                    src_grp_rules.append((item, g_name))
            print(f"[INFO] SOURCE-in-GROUP matches: {len(src_grp_rules)}")

            for item, grp_name in src_grp_rules:
                orig = _get_rule_node(item or {}, ipver) or {}
                d_type, d_name, d_hint = _extract_addr_ref(orig.get('destination') or {})
                v_type, v_name, v_hint = _extract_service_ref(orig)

                svc_order = []
                if v_type=='service_group' and v_hint in ('service.group-str','service.group-name'):
                    svc_order.append(v_hint)
                svc_order.extend([x for x in svc_shapes if x not in svc_order])

                grp_order = []
                if d_type=='address_group' and d_hint in ('address.group-str','address.group-name','addrgroup'):
                    grp_order.append(d_hint)
                grp_order.extend([x for x in group_shapes if x not in grp_order])

                posted=False; last_err=None
                for sshape in svc_order:
                    src_disp = _fmt_side('address_group', grp_name, 'src')
                    dst_disp = _fmt_side(d_type, d_name, 'dst')
                    svc_disp = _fmt_service(v_type, v_name)
                    ports_disp = _fmt_ports(orig.get('source') or {}, orig.get('destination') or {})

                    if d_type=='address_group':
                        for gshape in grp_order:
                            ipv = build_payload_change_source(orig, ipver, tgt_zone, args.target_ao,
                                                              d_type, d_name, d_hint,
                                                              v_type, v_name, sshape, gshape,
                                                              copy_ports, copy_name, copy_comment, name_prefix)
                            sig = build_rule_signature(ipv)
                            if sig in existing_sigs:
                                print(f"[SKIP] Duplicate (SOURCE-in-GROUP) | {src_disp} | {dst_disp} | {svc_disp}{ports_disp}")
                                posted=True; break
                            try:
                                if dry_run:
                                    print(json.dumps({"access_rules":[{ipver: ipv}]}, indent=2)); posted=True
                                else:
                                    _post_rule(s, base_url, verify, ipver, ipv, verbose=args.verbose); posted=True
                                existing_sigs.add(sig); created+=1
                                print(f"[OK] Created SOURCE-in-GROUP clone | {src_disp} | {dst_disp} | {svc_disp}{ports_disp} (grp={gshape}, svc={sshape})")
                                break
                            except Exception as e:
                                last_err=e; continue
                        if posted: break
                    else:
                        ipv = build_payload_change_source(orig, ipver, tgt_zone, args.target_ao,
                                                          d_type, d_name, d_hint,
                                                          v_type, v_name, sshape, group_shapes[0],
                                                          copy_ports, copy_name, copy_comment, name_prefix)
                        sig = build_rule_signature(ipv)
                        if sig in existing_sigs:
                            print(f"[SKIP] Duplicate (SOURCE-in-GROUP) | {src_disp} | {dst_disp} | {svc_disp}{ports_disp}")
                            posted=True; break
                        try:
                            if dry_run:
                                print(json.dumps({"access_rules":[{ipver: ipv}]}, indent=2)); posted=True
                            else:
                                _post_rule(s, base_url, verify, ipver, ipv, verbose=args.verbose); posted=True
                            existing_sigs.add(sig); created+=1
                            print(f"[OK] Created SOURCE-in-GROUP clone | {src_disp} | {dst_disp} | {svc_disp}{ports_disp} (svc={sshape})")
                        except Exception as e:
                            last_err=e; continue
                if not posted and last_err:
                    print(f"[ERROR] Could not create SOURCE-in-GROUP clone for group '{grp_name}': {last_err}")

            # DESTINATION-as-AO (mirror/try group shape on SOURCE if group)
            if include_dst:
                dst_ao_rules=[]
                for item in rules:
                    rnode = _get_rule_node(item or {}, ipver)
                    if not rnode: continue
                    if not zone_eq(rnode.get('to'), src_zone): continue
                    d_type2, d_name2, d_hint2 = _extract_addr_ref(rnode.get('destination') or {})
                    if d_type2=='address' and _norm(d_name2)==_norm(args.source_ao):
                        dst_ao_rules.append(item)
                print(f"[INFO] DESTINATION-as-AO matches: {len(dst_ao_rules)}")

                for item in dst_ao_rules:
                    orig = _get_rule_node(item or {}, ipver) or {}
                    s_type2, s_name2, s_hint2 = _extract_addr_ref(orig.get('source') or {})
                    v_type2, v_name2, v_hint2 = _extract_service_ref(orig)

                    svc_order = []
                    if v_type2=='service_group' and v_hint2 in ('service.group-str','service.group-name'):
                        svc_order.append(v_hint2)
                    svc_order.extend([x for x in svc_shapes if x not in svc_order])

                    grp_order = []
                    if s_type2=='address_group' and s_hint2 in ('address.group-str','address.group-name','addrgroup'):
                        grp_order.append(s_hint2)
                    grp_order.extend([x for x in group_shapes if x not in grp_order])

                    posted=False; last_err=None
                    for sshape in svc_order:
                        src_disp = _fmt_side(s_type2, s_name2, 'src')
                        dst_disp = _fmt_side('address', args.target_ao, 'dst')
                        svc_disp = _fmt_service(v_type2, v_name2)
                        ports_disp = _fmt_ports(orig.get('source') or {}, orig.get('destination') or {})

                        if s_type2=='address_group':
                            for gshape in grp_order:
                                ipv = build_payload_change_destination(orig, ipver, tgt_zone, args.target_ao,
                                                                       s_type2, s_name2, s_hint2,
                                                                       v_type2, v_name2, sshape, gshape,
                                                                       copy_ports, copy_name, copy_comment, name_prefix)
                                sig = build_rule_signature(ipv)
                                if sig in existing_sigs:
                                    print(f"[SKIP] Duplicate (DESTINATION-as-AO) | {src_disp} | {dst_disp} | {svc_disp}{ports_disp}")
                                    posted=True; break
                                try:
                                    if dry_run:
                                        print(json.dumps({"access_rules":[{ipver: ipv}]}, indent=2)); posted=True
                                    else:
                                        _post_rule(s, base_url, verify, ipver, ipv, verbose=args.verbose); posted=True
                                    existing_sigs.add(sig); created+=1
                                    print(f"[OK] Created DESTINATION-as-AO clone | {src_disp} | {dst_disp} | {svc_disp}{ports_disp} (srcgrp={gshape}, svc={sshape})")
                                    break
                                except Exception as e:
                                    last_err=e; continue
                            if posted: break
                        else:
                            ipv = build_payload_change_destination(orig, ipver, tgt_zone, args.target_ao,
                                                                   s_type2, s_name2, s_hint2,
                                                                   v_type2, v_name2, sshape, group_shapes[0],
                                                                   copy_ports, copy_name, copy_comment, name_prefix)
                            sig = build_rule_signature(ipv)
                            if sig in existing_sigs:
                                print(f"[SKIP] Duplicate (DESTINATION-as-AO) | {src_disp} | {dst_disp} | {svc_disp}{ports_disp}")
                                posted=True; break
                            try:
                                if dry_run:
                                    print(json.dumps({"access_rules":[{ipver: ipv}]}, indent=2)); posted=True
                                else:
                                    _post_rule(s, base_url, verify, ipver, ipv, verbose=args.verbose); posted=True
                                existing_sigs.add(sig); created+=1
                                print(f"[OK] Created DESTINATION-as-AO clone | {src_disp} | {dst_disp} | {svc_disp}{ports_disp} (svc={sshape})")
                            except Exception as e:
                                last_err=e; continue
                    if not posted and last_err:
                        print(f"[ERROR] DESTINATION-as-AO clone failed: {last_err}")

            # DESTINATION-in-GROUP
            if include_dst and include_groups:
                dst_grp_rules: List[Tuple[Dict, str]] = []
                for item in rules:
                    rnode = _get_rule_node(item or {}, ipver)
                    if not rnode: continue
                    if not zone_eq(rnode.get('to'), src_zone): continue
                    d_type3, g_name3, d_hint3 = _extract_addr_ref(rnode.get('destination') or {})
                    if d_type3=='address_group':
                        dst_grp_rules.append((item, g_name3))
                print(f"[INFO] DESTINATION-in-GROUP matches: {len(dst_grp_rules)}")

                for item, grp_name in dst_grp_rules:
                    orig = _get_rule_node(item or {}, ipver) or {}
                    s_type3, s_name3, s_hint3 = _extract_addr_ref(orig.get('source') or {})
                    v_type3, v_name3, v_hint3 = _extract_service_ref(orig)

                    svc_order = []
                    if v_type3=='service_group' and v_hint3 in ('service.group-str','service.group-name'):
                        svc_order.append(v_hint3)
                    svc_order.extend([x for x in svc_shapes if x not in svc_order])

                    grp_order = []
                    grp_order.append('address.group-str')
                    for x in group_shapes:
                        if x not in grp_order:
                            grp_order.append(x)

                    posted=False; last_err=None
                    for sshape in svc_order:
                        src_disp = _fmt_side(s_type3, s_name3, 'src')
                        dst_disp = _fmt_side('address_group', grp_name, 'dst')
                        svc_disp = _fmt_service(v_type3, v_name3)
                        ports_disp = _fmt_ports(orig.get('source') or {}, orig.get('destination') or {})
                        for gshape in grp_order:
                            ipv = build_payload_change_destination(orig, ipver, tgt_zone, args.target_ao,
                                                                   s_type3, s_name3, s_hint3,
                                                                   v_type3, v_name3, sshape, gshape,
                                                                   copy_ports, copy_name, copy_comment, name_prefix)
                            sig = build_rule_signature(ipv)
                            if sig in existing_sigs:
                                print(f"[SKIP] Duplicate (DESTINATION-in-GROUP) | {src_disp} | {dst_disp} | {svc_disp}{ports_disp}")
                                posted=True; break
                            try:
                                if dry_run:
                                    print(json.dumps({"access_rules":[{ipver: ipv}]}, indent=2)); posted=True
                                else:
                                    _post_rule(s, base_url, verify, ipver, ipv, verbose=args.verbose); posted=True
                                existing_sigs.add(sig); created+=1
                                print(f"[OK] Created DESTINATION-in-GROUP clone | {src_disp} | {dst_disp} | {svc_disp}{ports_disp} (grp={gshape}, svc={sshape})")
                                break
                            except Exception as e:
                                last_err=e; continue
                        if posted: break
                    if not posted and last_err:
                        print(f"[ERROR] Could not create DESTINATION-in-GROUP clone for group '{grp_name}': {last_err}")

            if created>0 and not dry_run and do_commit:
                commit_pending(s, base_url, verify, verbose=args.verbose)
                print("[OK] Committed pending changes.")
            elif created==0 and not dry_run and do_commit:
                print("[INFO] No new rules created; skipping commit.")

        finally:
            logout(s, base_url, verify)

if __name__ == '__main__':
    main()
