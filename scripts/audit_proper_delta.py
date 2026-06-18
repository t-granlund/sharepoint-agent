#!/usr/bin/env python3
"""
HTTHQ Library Audit — Proper Delta Edition
Uses Microsoft Graph /delta for flat enumeration (O(100) calls vs O(20,000))
Then folders-only REST permission audit.

Expected: 5-7 minutes total vs 2+ hours.
"""
import os, sys, csv, json, time, urllib.request, urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests

SITE_URL = os.environ.get("SITE_URL", "example-organization.sharepoint.com:/sites/HTTHQ")
SITE_REL = "/sites/HTTHQ"
SP_HOST = os.environ.get("SP_HOST", "https://example-organization.sharepoint.com")
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "./audit_output"))
OUTPUT_DIR.mkdir(exist_ok=True)
TS = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = OUTPUT_DIR / f"htthq_delta_log_{TS}.txt"

# CI detection
IS_CI = bool(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))

# ═══════════════════════════════════════════════════════════════════════════
# Auth (same dual-mode: OIDC in CI, az CLI locally)
# ═══════════════════════════════════════════════════════════════════════════
class TokenMgr:
    def __init__(self):
        self._t = {}
        self._exp = {}
        self.is_ci = IS_CI

    def _oidc_exchange(self, scope: str) -> str:
        """GitHub Actions OIDC → Graph token exchange."""
        token_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
        if "&audience=" not in token_url and "?audience=" not in token_url:
            sep = "&" if "?" in token_url else "?"
            token_url = f"{token_url}{sep}audience=api://AzureADTokenExchange"

        req = urllib.request.Request(token_url,
            headers={"Authorization": f"bearer {os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            oidc_tok = json.loads(resp.read().decode("utf-8"))["value"]

        data = urllib.parse.urlencode({
            "client_id": os.environ["AZURE_CLIENT_ID"],
            "scope": scope,
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": oidc_tok,
        })
        req = urllib.request.Request(
            f"https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}/oauth2/v2.0/token",
            data=data.encode(), method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))["access_token"]

    def _az_token(self, resource: str) -> str:
        import subprocess
        r = subprocess.run(["az","account","get-access-token","--resource",resource,"--output","json"],
            capture_output=True, text=True, timeout=30)
        r.check_returncode()
        return json.loads(r.stdout)["accessToken"]

    def get(self, scope: str) -> str:
        now = time.time()
        if scope not in self._t or now > self._exp.get(scope, 0) - 180:
            if self.is_ci:
                tok = self._oidc_exchange(scope)
            else:
                res = scope.replace("/.default", "")
                tok = self._az_token(res)
            self._t[scope] = tok
            self._exp[scope] = now + 3500
        return self._t[scope]

    def g_hdr(self): return {"Authorization": f"Bearer {self.get('https://graph.microsoft.com/.default')}"}
    def s_hdr(self): return {"Authorization": f"Bearer {self.get('https://example-organization.sharepoint.com/.default')}"}

AUTH = TokenMgr()

# ═══════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════
def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ═══════════════════════════════════════════════════════════════════════════
# Phase A: Delta Enumeration (FLAT — O(100) calls, not O(20,000))
# ═══════════════════════════════════════════════════════════════════════════
def phase_a_delta() -> List[Dict]:
    """Use Graph /delta to get ALL items in a flat stream with parentReference."""
    log("Phase A: Delta enumeration...")

    # Resolve site
    site = requests.get(f"{GRAPH_BASE}/sites/{SITE_URL}", headers=AUTH.g_hdr(), timeout=30).json()
    site_id = site["id"]
    log(f"Site: {site_id}")

    # Get documents drive
    drives = requests.get(f"{GRAPH_BASE}/sites/{site_id}/drives", headers=AUTH.g_hdr(), timeout=30).json()
    drive_id = next(d["id"] for d in drives.get("value", []) if d["name"] in ("Documents", "Shared Documents"))
    log(f"Drive: {drive_id}")

    # DELTA endpoint: flat list of ALL items, paginated via nextLink/deltaLink
    flat = []
    url = f"{GRAPH_BASE}/drives/{drive_id}/root/delta?select=id,name,folder,file,size,createdDateTime,lastModifiedDateTime,createdBy,lastModifiedBy,parentReference,webUrl&$top=999"
    page = 0

    while url:
        page += 1
        r = requests.get(url, headers=AUTH.g_hdr(), timeout=60)
        if r.status_code == 401:
            url = r.url  # retry with fresh auth on next loop
            continue
        r.raise_for_status()
        data = r.json()

        for item in data.get("value", []):
            # Skip deleted items
            if item.get("deleted"):
                continue

            # Build full path from parentReference
            parent_path = item.get("parentReference", {}).get("path", "")
            # parent_path looks like "/drives/{drive-id}/root:/Shared Documents/Subfolder"
            # Strip the drive prefix to get the relative path
            if ":/" in parent_path:
                rel_parent = parent_path.split(":/", 1)[1]
            else:
                rel_parent = "Shared Documents"  # root items

            name = item.get("name", "")
            full_path = f"{rel_parent}/{name}" if rel_parent else name

            is_folder = "folder" in item
            flat.append({
                "id": item["id"],
                "name": name,
                "path": full_path,
                "type": "folder" if is_folder else "file",
                "parent_path": rel_parent,
                "size": item.get("size", 0),
                "created": item.get("createdDateTime", ""),
                "modified": item.get("lastModifiedDateTime", ""),
                "created_by": item.get("createdBy", {}).get("user", {}).get("displayName", ""),
                "modified_by": item.get("lastModifiedBy", {}).get("user", {}).get("displayName", ""),
                "child_count": item.get("folder", {}).get("childCount", 0) if is_folder else 0,
                "web_url": item.get("webUrl", ""),
                "has_unique": None,
                "permissions": [],
            })

        url = data.get("@odata.nextLink")
        # If deltaLink present, enumeration is complete
        delta_link = data.get("@odata.deltaLink")
        if delta_link:
            log(f"Delta sync complete. Total pages: {page}")
            break

        if page % 10 == 0:
            log(f"  Page {page}: {len(flat)} items collected...")

    log(f"Phase A complete: {len(flat)} items in {page} page(s)")
    return flat

# ═══════════════════════════════════════════════════════════════════════════
# Phase B: Folders-only Permission Audit
# ═══════════════════════════════════════════════════════════════════════════
def phase_b_folders(flat: List[Dict]) -> List[Dict]:
    """Check HasUniqueRoleAssignments for FOLDERS ONLY via SPO REST."""
    log("Phase B: Auditing folder permissions...")

    # Mark files as inherited
    folders = []
    for item in flat:
        if item["type"] == "file":
            item["has_unique"] = False
        else:
            item["has_unique"] = None
            folders.append(item)

    log(f"  Folders to check: {len(folders)}")

    for idx, item in enumerate(folders, 1):
        srv_rel = f"{SITE_REL}/{item['path']}"
        enc = urllib.parse.quote(srv_rel, safe="/")  # keep `/` as path separators
        api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{enc}')/ListItemAllFields/HasUniqueRoleAssignments"

        # No throttle — run at full speed; 429s are handled below
        r = requests.get(f"{SP_HOST}{api}", headers={"Authorization": f"Bearer {AUTH.get('https://example-organization.sharepoint.com/.default')}",
                                                      "Accept": "application/json;odata=verbose"}, timeout=30)
        if r.status_code == 429:
            time.sleep(int(r.headers.get("Retry-After", 3)))
            r = requests.get(f"{SP_HOST}{api}", headers=AUTH.s_hdr(), timeout=30)

        if r.status_code == 200:
            data = r.json()
            has_unique = bool(data.get("d", {}).get("HasUniqueRoleAssignments", False))
            item["has_unique"] = has_unique
            if has_unique:
                _pull_roles(item)
        else:
            item["has_unique"] = False
            item["_note"] = f"HTTP {r.status_code}"

        if idx % 50 == 0:
            uc = sum(1 for f in folders if f.get("has_unique") == True)
            log(f"  Progress: {idx}/{len(folders)} folders | Unique: {uc}")

    total_unique = sum(1 for f in folders if f.get("has_unique") == True)
    log(f"Phase B complete: {total_unique} unique-permission folders out of {len(folders)}")
    return flat


def _pull_roles(item: Dict):
    """Pull role assignments for unique-permission folders."""
    srv_rel = f"{SITE_REL}/{item['path']}"
    enc = urllib.parse.quote(srv_rel, safe="/")
    api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{enc}')/ListItemAllFields/RoleAssignments?$expand=Member,RoleDefinitionBindings"

    r = requests.get(f"{SP_HOST}{api}", headers=AUTH.s_hdr(), timeout=30)
    if r.status_code != 200:
        return
    data = r.json().get("d", {})
    results = data.get("results", data.get("value", []))
    for ra in results:
        member = ra.get("Member", {})
        for rdb in ra.get("RoleDefinitionBindings", {}).get("results", []):
            login = member.get("LoginName", "")
            item["permissions"].append({
                "item_id": item["id"], "item_path": item["path"], "item_type": "folder",
                "principal_id": member.get("Id", ""),
                "principal_name": member.get("Title", member.get("Name", "")),
                "principal_type": member.get("PrincipalType", ""),
                "login_name": login,
                "role_name": rdb.get("Name", rdb.get("RoleDefinition", {}).get("Name", "")),
                "inherited": False,
                "is_external": _is_ext(login),
            })


def _is_ext(login: str) -> bool:
    l = (login or "").lower()
    return "#ext#" in l or ("@" in l and l.split("@")[-1] not in ("example-organization.com", "example-organization.onmicrosoft.com"))

# ═══════════════════════════════════════════════════════════════════════════
# Phase C: Reports
# ═══════════════════════════════════════════════════════════════════════════
def phase_c_reports(flat: List[Dict]):
    log("Phase C: Generating reports...")
    folders = [i for i in flat if i["type"] == "folder"]
    files = [i for i in flat if i["type"] == "file"]
    unique_items = [i for i in flat if i.get("has_unique") == True]
    perms = []
    for item in flat:
        perms.extend(item.get("permissions", []))

    # Flat CSV
    flat_csv = OUTPUT_DIR / f"htthq_delta_flat_{TS}.csv"
    with open(flat_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id","name","path","type","parent_path","size","created","modified","created_by","modified_by","child_count","has_unique","web_url"])
        for item in flat:
            w.writerow([item["id"], item["name"], item["path"], item["type"],
                       item["parent_path"], item["size"], item["created"], item["modified"],
                       item["created_by"], item["modified_by"], item["child_count"],
                       str(item.get("has_unique","")), item["web_url"]])
    log(f"Flat CSV: {flat_csv.name}")

    # Perms CSV
    perms_csv = OUTPUT_DIR / f"htthq_delta_perms_{TS}.csv"
    with open(perms_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["item_id","item_path","item_type","principal_id","principal_name","principal_type","login_name","role_name","inherited","is_external"])
        for r in perms:
            w.writerow([r["item_id"], r["item_path"], r["item_type"],
                       r["principal_id"], r["principal_name"], r["principal_type"],
                       r["login_name"], r["role_name"], r["inherited"], r["is_external"]])
    log(f"Perms CSV: {perms_csv.name}")

    # Tree JSON
    tree = _build_tree(flat)
    tree_json = OUTPUT_DIR / f"htthq_delta_tree_{TS}.json"
    with open(tree_json, "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2)
    log(f"Tree JSON: {tree_json.name}")

    # Analysis MD
    md = OUTPUT_DIR / f"htthq_delta_analysis_{TS}.md"
    _write_md(md, flat, folders, files, unique_items, perms)
    log(f"Analysis MD: {md.name}")

    return {"flat_csv": str(flat_csv.name), "perms_csv": str(perms_csv.name),
            "tree_json": str(tree_json.name), "analysis_md": str(md.name)}


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


def _write_md(path, flat, folders, files, unique_items, perms):
    high_risk = [u for u in unique_items if u["type"] == "folder" and u.get("child_count", 0) > 10]
    med_risk = [u for u in unique_items if u["type"] == "folder" and 0 < u.get("child_count", 0) <= 10]
    ext_perms = [r for r in perms if r.get("is_external")]

    lines = [
        "# HTTHQ Shared Documents — Permission Inheritance Analysis",
        f"\n**Date:** {datetime.now().isoformat()}",
        f"**Site:** {SITE_URL}",
        "**Method:** Microsoft Graph /delta (flat enumeration) + SPO REST (folders only)",
        f"\n**Total Items:** {len(flat)} | **Folders:** {len(folders)} | **Files:** {len(files)}",
        f"**Unique-permission folders:** {len(unique_items)} 🔒",
        f"**Role assignments:** {len(perms)}",
    ]

    if high_risk:
        lines.extend(["\n### 🔴 High Risk (>10 children with unique perms)"])
        for it in high_risk:
            lines.append(f"- **{it['path']}** — {it['child_count']} children inherit unique permissions")
    if med_risk:
        lines.extend(["\n### 🟡 Medium Risk (1-10 children with unique perms)"])
        for it in med_risk:
            lines.append(f"- **{it['path']}** — {it['child_count']} children")
    if ext_perms:
        lines.append(f"\n### 🟡 External Users ({len(ext_perms)} role assignments)")

    lines.append("\n---\n*Report generated by Richard the Code Puppy 🐶 | Delta edition*")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════
def main():
    log("=" * 60 + " HTTHQ DELTA AUDIT " + "=" * 60)
    t0 = time.time()
    flat = phase_a_delta()
    flat = phase_b_folders(flat)
    report_paths = phase_c_reports(flat)
    elapsed = time.time() - t0

    summary = {
        "items_total": len(flat),
        "folders": len([i for i in flat if i["type"] == "folder"]),
        "files": len([i for i in flat if i["type"] == "file"]),
        "unique_folders": sum(1 for i in flat if i.get("has_unique") == True),
        "elapsed_seconds": round(elapsed, 1),
        "reports": report_paths,
        "timestamp": datetime.now().isoformat(),
    }
    with open(OUTPUT_DIR / "htthq_delta_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    log(f"\n{'=' * 50}")
    log(f"DONE in {elapsed/60:.1f} minutes")
    log(f"Items: {summary['items_total']} | Folders: {summary['folders']} | Unique: {summary['unique_folders']}")
    log(f"Reports: {report_paths}")


if __name__ == "__main__":
    main()
