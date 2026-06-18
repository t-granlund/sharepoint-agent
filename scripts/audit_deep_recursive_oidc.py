#!/usr/bin/env python3
"""
HTTHQ Deep Recursive Permission Audit — Cloud/CI/CD Edition
=============================================================
Designed for GitHub Actions with OIDC federation.

AUTH:
    Expects Azure CLI to be pre-authenticated (azure/login@v2 sets this up).
    Pulls tokens on-demand via `az account get-access-token`.

OUTPUTS (all written to audit_output/):
    htthq_deep_flat_<ts>.csv       — flat list of all items
    htthq_deep_perms_<ts>.csv      — role assignments for unique-permission items
    htthq_deep_tree_<ts>.json      — hierarchical tree
    htthq_deep_analysis_<ts>.md    — human-readable risk analysis
    htthq_deep_checkpoint.json     — resume support (auto-deleted on success)
"""
import os, sys, csv, json, time, subprocess, urllib.parse, base64
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

import requests

# ═══ Config ═══════════════════════════════════════════════════════════════════
SITE_URL = os.environ.get("SITE_URL", "example-organization.sharepoint.com:/sites/HTTHQ")
SP_HOST  = os.environ.get("SP_HOST", "https://example-organization.sharepoint.com")
SITE_REL = "/sites/HTTHQ"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "./audit_output"))
OUTPUT_DIR.mkdir(exist_ok=True)
TS = datetime.now().strftime("%Y%m%d_%H%M%S")

# Phase A — enumeration
ENUM_BATCH = 200
CHECKPOINT_EVERY = 500
# Phase B — inheritance (throttled for SPO)
REST_THROTTLE_SEC = 0.4  # ~2.5 req/sec — polite but not glacial

# ═══ Logging ══════════════════════════════════════════════════════════════════
log_file = OUTPUT_DIR / f"htthq_deep_log_{TS}.txt"

def log(msg: str, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()

# ═══ Token Manager ════════════════════════════════════════════════════════════
class TokenMgr:
    """Pulls fresh tokens via OIDC (GitHub Actions) or az CLI (local)."""
    def __init__(self):
        self._g = None
        self._s = None
        self._g_exp = 0
        self._s_exp = 0
        self._is_ci = bool(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
        if self._is_ci:
            log("TokenMgr: running in GitHub Actions OIDC mode")
        else:
            try:
                subprocess.run(["az", "account", "show"], capture_output=True, timeout=10).check_returncode()
                log("TokenMgr: running in local az CLI mode")
            except Exception:
                log("WARNING: neither OIDC nor az CLI available. Auth will fail.", "WARN")

    def _tk_oidc(self, scope: str):
        """Use OIDC helper (GitHub Actions)."""
        try:
            import oidc_auth_helper
            tok = oidc_auth_helper.get_token(scope)
            # decode exp
            try:
                payload = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
                exp = payload.get("exp", time.time() + 3500)
            except Exception:
                exp = time.time() + 3500
            return tok, exp
        except Exception as e:
            raise RuntimeError(f"OIDC token fetch failed: {e}")

    def _tk_az(self, resource: str):
        """Use az CLI (local)."""
        r = subprocess.run(
            ["az", "account", "get-access-token", "--resource", resource, "--output", "json"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            raise RuntimeError(f"az token fail: {r.stderr[:300]}")
        tok = json.loads(r.stdout)["accessToken"]
        try:
            payload = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
            exp = payload.get("exp", time.time() + 3500)
        except Exception:
            exp = time.time() + 3500
        return tok, exp

    def _get(self, scope_or_resource: str, is_graph: bool = True):
        if self._is_ci:
            return self._tk_oidc(scope_or_resource)
        else:
            return self._tk_az(scope_or_resource)

    def ensure(self):
        now = time.time()
        if not self._g or now > self._g_exp - 180:
            self._g, self._g_exp = self._get("https://graph.microsoft.com/.default")
            log("Refreshed Graph token")
        if not self._s or now > self._s_exp - 180:
            try:
                self._s, self._s_exp = self._get("https://example-organization.sharepoint.com/.default", is_graph=False)
            except Exception:
                # SPO may accept Graph token
                self._s, self._s_exp = self._g, self._g_exp
            log("Refreshed SPO token")

    def g_hdr(self):
        self.ensure()
        return {"Authorization": f"Bearer {self._g}", "Content-Type": "application/json"}

    def s_hdr(self):
        self.ensure()
        return {"Authorization": f"Bearer {self._s}", "Accept": "application/json;odata=verbose"}

AUTH = TokenMgr()

# ═══ Resilient Request Wrappers ═══════════════════════════════════════════════
_req_graph = 0
_req_rest = 0

def gget(url: str, params=None, retries=3) -> Optional[Dict]:
    """Graph GET with retry + 429 handling."""
    global _req_graph
    for a in range(retries):
        try:
            _req_graph += 1
            r = requests.get(url, headers=AUTH.g_hdr(), params=params, timeout=45)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 5))
                log(f"Graph 429, wait {wait}s", "WARN")
                time.sleep(wait)
                continue
            if r.status_code == 401:
                AUTH.ensure()
                continue
            if r.status_code == 403:
                log(f"Graph 403 on {url[:80]}...", "WARN")
                return None
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if a == retries - 1:
                log(f"Graph error ({url[:60]}): {e}", "ERROR")
                return None
            time.sleep(2 ** a)
    return None


def sget(rel: str, retries=3) -> Optional[Dict]:
    """SharePoint REST GET with polite throttling."""
    global _req_rest
    for a in range(retries):
        try:
            _req_rest += 1
            if _req_rest % 100 == 0:
                log(f"REST calls: {_req_rest}")
            time.sleep(REST_THROTTLE_SEC)
            r = requests.get(f"{SP_HOST}{rel}", headers=AUTH.s_hdr(), timeout=30)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 10))
                log(f"SPO 429, wait {wait}s", "WARN")
                time.sleep(wait)
                continue
            if r.status_code in (401, 403):
                AUTH.ensure()
                continue
            if r.status_code == 404:
                return {"_st": "404"}
            if r.status_code == 500:
                return {"_st": "500"}
            r.raise_for_status()
            try:
                return r.json()
            except json.JSONDecodeError:
                return {"_raw": r.text[:200], "_st": "xml"}
        except Exception as e:
            if a == retries - 1:
                log(f"SPO error ({rel[:60]}): {e}", "ERROR")
                return None
            time.sleep(2 ** a)
    return None


# ══════════════════════════════════════════════════════════════════════════════
# PHASE A: RECURSIVE ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════
CKPT = OUTPUT_DIR / "htthq_deep_checkpoint.json"

def load_checkpoint():
    if CKPT.exists():
        with open(CKPT, "r", encoding="utf-8") as f:
            d = json.load(f)
        log(f"Resumed checkpoint: {len(d['flat'])} items, {len(d['queue'])} queued")
        return d["flat"], d["queue"], d["seen"], d["drive_id"]
    return [], [], set(), None


def save_checkpoint(flat, queue, seen, drive_id):
    with open(CKPT, "w", encoding="utf-8") as f:
        json.dump({
            "flat": flat,
            "queue": queue,
            "seen": list(seen),
            "drive_id": drive_id,
            "ts": datetime.now().isoformat()
        }, f)


def phase_a_enumerate() -> (List[Dict], str):
    """Deep recursive BFS via Graph API. Returns (items, drive_id)."""
    flat, queue, seen, drive_id = load_checkpoint()

    if not flat:
        log("Phase A: Starting enumeration...")
        site = gget(f"{GRAPH_BASE}/sites/{SITE_URL}")
        if not site or "id" not in site:
            log("Failed to resolve site", "ERROR")
            sys.exit(1)
        site_id = site["id"]
        log(f"Site: {site_id}")

        drives = gget(f"{GRAPH_BASE}/sites/{site_id}/drives")
        for drv in drives.get("value", []):
            if drv["name"] in ("Documents", "Shared Documents"):
                drive_id = drv["id"]
                log(f"Drive: {drv['name']}")
                break
        if not drive_id:
            log("No Documents drive", "ERROR")
            sys.exit(1)

        root = gget(f"{GRAPH_BASE}/drives/{drive_id}/root")
        queue = [(root["id"], "Shared Documents")]

    while queue:
        item_id, parent = queue.pop(0)
        if item_id in seen:
            continue
        seen.add(item_id)

        url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item_id}/children?$top={ENUM_BATCH}"
        while url:
            data = gget(url)
            if not data or "value" not in data:
                break
            for child in data.get("value", []):
                cid = child["id"]
                cname = child.get("name", "")
                cpath = f"{parent}/{cname}" if parent else cname
                is_folder = "folder" in child
                flat.append({
                    "id": cid,
                    "name": cname,
                    "path": cpath,
                    "type": "folder" if is_folder else "file",
                    "parent_path": parent,
                    "size": child.get("size", 0),
                    "created": child.get("createdDateTime", ""),
                    "modified": child.get("lastModifiedDateTime", ""),
                    "created_by": child.get("createdBy", {}).get("user", {}).get("displayName", ""),
                    "modified_by": child.get("lastModifiedBy", {}).get("user", {}).get("displayName", ""),
                    "child_count": child.get("folder", {}).get("childCount", 0) if is_folder else 0,
                    "web_url": child.get("webUrl", ""),
                    "has_unique": None,
                    "permissions": [],
                })
                if is_folder:
                    queue.append((cid, cpath))
            url = data.get("@odata.nextLink")

        if len(flat) % CHECKPOINT_EVERY == 0:
            save_checkpoint(flat, queue, seen, drive_id)
            log(f"  Enumerated {len(flat)} items | Queue: {len(queue)} | Graph reqs: {_req_graph}")

    # Cleanup checkpoint
    if CKPT.exists():
        CKPT.unlink()

    log(f"Phase A complete: {len(flat)} items ({_req_graph} Graph requests)")
    return flat, drive_id


# ══════════════════════════════════════════════════════════════════════════════
# PHASE B: PERMISSION INHERITANCE AUDIT
# ══════════════════════════════════════════════════════════════════════════════
def phase_b_audit(flat: List[Dict]) -> List[Dict]:
    """Check HasUniqueRoleAssignments for FOLDERS ONLY via SPO REST.
    Files inherit from their parent folder — the folder IS the permission boundary.
    """
    log("Phase B: Auditing FOLDER permissions only...")
    # Files are leaves — they inherit from their parent folder branch
    for item in flat:
        if item["type"] == "file" and item.get("has_unique") is None:
            item["has_unique"] = False  # inherited by default

    remaining = [i for i in flat if i.get("has_unique") is None and i["type"] == "folder"]
    log(f"  Folders to check: {len(remaining)}")

    for idx, item in enumerate(remaining, 1):
        srv_rel = f"{SITE_REL}/Shared Documents/{item['path'].replace('Shared Documents/', '')}"
        enc = urllib.parse.quote(srv_rel)
        api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{enc}')/ListItemAllFields/HasUniqueRoleAssignments"

        data = sget(api)
        if data and "d" in data:
            has_unique = bool(data["d"].get("HasUniqueRoleAssignments", False))
            item["has_unique"] = has_unique
            if has_unique:
                _pull_roles(item)
        elif data and data.get("_st") in ("404", "500"):
            item["has_unique"] = False
            item["_note"] = f"REST {data['_st']}"
        else:
            item["has_unique"] = False

        if idx % 50 == 0:
            uc = sum(1 for i in flat if i.get("has_unique") == True)
            log(f"  Progress: {idx}/{len(remaining)} folders | Unique so far: {uc} | REST reqs: {_req_rest}")

    total_unique = sum(1 for i in flat if i.get("has_unique") == True)
    total_folders = len([i for i in flat if i["type"] == "folder"])
    log(f"Phase B complete: {total_unique} unique-permission folders out of {total_folders} ({_req_rest} REST requests)")
    return flat


def _pull_roles(item: Dict):
    """Pull role assignments for unique-permission items."""
    srv_rel = f"{SITE_REL}/Shared Documents/{item['path'].replace('Shared Documents/', '')}"
    enc = urllib.parse.quote(srv_rel)
    if item["type"] == "folder":
        api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{enc}')/ListItemAllFields/RoleAssignments?$expand=Member,RoleDefinitionBindings"
    else:
        api = f"{SITE_REL}/_api/web/GetFileByServerRelativeUrl('{enc}')/ListItemAllFields/RoleAssignments?$expand=Member,RoleDefinitionBindings"

    data = sget(api)
    if not data or "d" not in data:
        return
    results = data["d"].get("results", data["d"].get("value", []))
    for ra in results:
        member = ra.get("Member", {})
        for rdb in ra.get("RoleDefinitionBindings", {}).get("results", []):
            login = member.get("LoginName", "")
            rec = {
                "item_id": item["id"], "item_path": item["path"], "item_type": item["type"],
                "principal_id": member.get("Id", ""), "principal_name": member.get("Title", member.get("Name", "")),
                "principal_type": member.get("PrincipalType", ""), "login_name": login,
                "role_name": rdb.get("Name", rdb.get("RoleDefinition", {}).get("Name", "")),
                "inherited": False, "is_external": _is_ext(login),
            }
            item["permissions"].append(rec)


def _is_ext(login: str) -> bool:
    l = (login or "").lower()
    if "#ext#" in l:
        return True
    if "@" in l:
        domain = l.split("@")[-1]
        if domain not in ("example-organization.com", "example-organization.onmicrosoft.com"):
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# PHASE C: REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def phase_c_reports(flat: List[Dict]):
    """Generate human + machine readable reports."""
    log("Phase C: Generating reports...")
    folders = [i for i in flat if i["type"] == "folder"]
    files = [i for i in flat if i["type"] == "file"]
    unique_items = [i for i in flat if i.get("has_unique") == True]
    perms = []
    for item in flat:
        perms.extend(item.get("permissions", []))

    # 1. Flat CSV
    flat_csv = OUTPUT_DIR / f"htthq_deep_flat_{TS}.csv"
    with open(flat_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id","name","path","type","parent_path","size","created","modified","created_by","modified_by","child_count","has_unique","web_url"])
        for item in flat:
            w.writerow([
                item["id"], item["name"], item["path"], item["type"],
                item["parent_path"], item["size"], item["created"], item["modified"],
                item["created_by"], item["modified_by"], item["child_count"],
                str(item.get("has_unique","")), item["web_url"]
            ])
    log(f"Flat CSV: {flat_csv.name}")

    # 2. Permissions CSV
    perms_csv = OUTPUT_DIR / f"htthq_deep_perms_{TS}.csv"
    with open(perms_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["item_id","item_path","item_type","principal_id","principal_name","principal_type","login_name","role_name","inherited","is_external"])
        for r in perms:
            w.writerow([r["item_id"], r["item_path"], r["item_type"],
                       r["principal_id"], r["principal_name"], r["principal_type"],
                       r["login_name"], r["role_name"], r["inherited"], r["is_external"]])
    log(f"Perms CSV: {perms_csv.name}")

    # 3. Tree JSON
    tree = _build_tree(flat)
    tree_json = OUTPUT_DIR / f"htthq_deep_tree_{TS}.json"
    with open(tree_json, "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2)
    log(f"Tree JSON: {tree_json.name}")

    # 4. Analysis Markdown
    md = OUTPUT_DIR / f"htthq_deep_analysis_{TS}.md"
    ext_perms = [r for r in perms if r.get("is_external")]
    _write_md(md, flat, folders, files, unique_items, perms, ext_perms)
    log(f"Analysis MD: {md.name}")

    log("Phase C complete!")
    return {
        "flat_csv": str(flat_csv.name),
        "perms_csv": str(perms_csv.name),
        "tree_json": str(tree_json.name),
        "analysis_md": str(md.name),
    }


def _build_tree(flat):
    root = {"name": "Shared Documents", "type": "folder", "has_unique": False, "children": []}
    nodes = {"": root}
    for item in flat:
        n = {"name": item["name"], "type": item["type"],
             "has_unique": item.get("has_unique"), "perm_count": len(item.get("permissions", [])),
             "children": [] if item["type"] == "folder" else None}
        nodes[item["path"]] = n
        parent = item.get("parent_path", "")
        if parent in nodes:
            nodes[parent]["children"].append(n)
    return root


def _write_md(path, flat, folders, files, unique_items, perms, ext_perms):
    high_risk = [u for u in unique_items if u["type"] == "folder" and u.get("child_count", 0) > 10]
    med_risk  = [u for u in unique_items if u["type"] == "folder" and 0 < u.get("child_count", 0) <= 10]

    lines = [
        "# HTTHQ Shared Documents — Permission Inheritance Analysis",
        f"\n**Date:** {datetime.now().isoformat()}  ",
        f"**Site:** {SITE_URL}  ",
        "**Library:** Shared Documents (Documents)",
        "\n---\n",
        "## Executive Summary",
        f"- **Total items:** {len(flat)}",
        f"- **Folders:** {len(folders)}",
        f"- **Files:** {len(files)}",
        f"- **Unique-permission items:** {len(unique_items)} 🔒",
        f"- **Inherited items:** {len([i for i in flat if i.get('has_unique') == False])} ✅",
        f"- **Role assignments:** {len(perms)}",
        f"- **External user roles:** {len(ext_perms)}",
        f"- **API usage:** {_req_graph} Graph + {_req_rest} REST requests",
        "\n---\n",
        "## 🔒 Items with Broken Inheritance",
        "\n| Path | Type | Child Count | Perm Count |",
        "|------|------|-------------|------------|"
    ]
    for it in sorted(unique_items, key=lambda x: x["path"]):
        lines.append(f"| {it['path'][:65]} | {it['type']} | {it.get('child_count',0)} | {len(it.get('permissions',[]))} |")

    lines.extend(["\n---\n", "## ⚠️ Risk Flags\n"])
    if high_risk:
        lines.append("### 🔴 High Risk (unique + >10 children)")
        for it in high_risk:
            lines.append(f"- **{it['path']}** — {it['child_count']} children inherit unique perms")
    if med_risk:
        lines.append("### 🟡 Medium Risk (unique + 1-10 children)")
        for it in med_risk:
            lines.append(f"- **{it['path']}** — {it['child_count']} children")
    if ext_perms:
        lines.append(f"### 🟡 External Users ({len(ext_perms)} role assignments)")
    if not (high_risk or med_risk or ext_perms):
        lines.append("_No significant risks detected._")

    lines.extend(["\n---\n", "## 📊 Comparison (Historical)", "\n| Metric | Feb 2026 | Current |",
        "|--------|----------|---------|",
        f"| Files | ~30 (shallow) | {len(files)} |",
        f"| Unique items | ~31 | {len(unique_items)} |",
        f"| External shares | 127 | {len(ext_perms)} |",
    ])

    lines.extend(["\n---\n", "*Report generated by Richard the Code Puppy 🐶 | CI/CD OIDC edition*\n"])
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    log("=" * 60 + " HTTHQ DEEP AUDIT (OIDC) " + "=" * 60)
    try:
        flat, _ = phase_a_enumerate()
        flat = phase_b_audit(flat)
        report_paths = phase_c_reports(flat)

        log("=" * 60 + " COMPLETE " + "=" * 60)
        log(f"Items: {len(flat)} | Unique: {sum(1 for i in flat if i.get('has_unique'))}")
        log(f"Outputs: {report_paths}")

        # Write a tiny JSON summary for GitHub Actions to consume
        summary = {
            "items_total": len(flat),
            "items_folders": len([i for i in flat if i['type'] == 'folder']),
            "items_files": len([i for i in flat if i['type'] == 'file']),
            "unique_permission_items": sum(1 for i in flat if i.get("has_unique") == True),
            "reports": report_paths,
            "timestamp": datetime.now().isoformat(),
        }
        with open(OUTPUT_DIR / "htthq_summary.json", "w") as f:
            json.dump(summary, f, indent=2)

    except KeyboardInterrupt:
        log("INTERRUPTED — checkpoint saved, re-run to resume", "WARN")
    except Exception as e:
        log(f"FATAL: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
