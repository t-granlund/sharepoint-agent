#!/usr/bin/env python3
"""
HTTHQ Full Permissions Audit v2 — Robust recursive enumeration + inheritance analysis.
Uses az account get-access-token --output json for clean token.
"""
import os
import sys
import csv
import json
import time
import subprocess
import urllib.parse
import base64
from datetime import datetime
from typing import Optional, List, Dict, Any

import requests

# ─── Config ──────────────────────────────────────────────────────────────────
SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
SP_HOST = "https://example-organization.sharepoint.com"
SITE_REL = "/sites/HTTHQ"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
OUTPUT_DIR = "audit_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)
TS = datetime.now().strftime("%Y%m%d_%H%M%S")

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_F = f"{OUTPUT_DIR}/htthq_v2_log_{TS}.txt"

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_F, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()

# ─── Token Manager ───────────────────────────────────────────────────────────
class AuthManager:
    def __init__(self):
        self._graph_t = None
        self._spo_t = None
        self._exp = 0
    
    @staticmethod
    def _get_token(resource: str) -> str:
        r = subprocess.run(
            ["az", "account", "get-access-token", "--resource", resource, "--output", "json"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            raise RuntimeError(f"az failed: {r.stderr[:300]}")
        token = json.loads(r.stdout)["accessToken"]
        return token
    
    def refresh(self):
        log("  Refreshing tokens via az CLI...")
        self._graph_t = self._get_token("https://graph.microsoft.com")
        try:
            self._spo_t = self._get_token("00000003-0000-0ff1-ce00-000000000000")
        except Exception:
            self._spo_t = self._graph_t
        try:
            payload = json.loads(base64.urlsafe_b64decode(self._graph_t.split(".")[1] + "=="))
            self._exp = payload.get("exp", 0)
        except Exception:
            self._exp = time.time() + 3000
    
    def ensure(self):
        if not self._graph_t or time.time() > self._exp - 120:
            self.refresh()
    
    def graph_headers(self):
        self.ensure()
        return {"Authorization": f"Bearer {self._graph_t}", "Content-Type": "application/json"}
    
    def spo_headers(self):
        self.ensure()
        return {"Authorization": f"Bearer {self._spo_t}", "Accept": "application/json;odata=verbose"}

AUTH = AuthManager()

# ─── Rate / Throttle ─────────────────────────────────────────────────────────
_req_count = 0

def _rest_delay(response=None):
    global _req_count
    _req_count += 1
    if _req_count % 100 == 0:
        log(f"  Requests so far: {_req_count}")
    if response is not None and response.status_code == 429:
        wait = int(response.headers.get("Retry-After", 5))
        log(f"  Rate limited, waiting {wait}s")
        time.sleep(wait)
        return True
    return False

# ─── Graph GET ───────────────────────────────────────────────────────────────
def graph_get(url: str, params=None, retries=3):
    for att in range(retries):
        try:
            r = requests.get(url, headers=AUTH.graph_headers(), params=params, timeout=30)
            if _rest_delay(r):
                continue
            if r.status_code == 401:
                AUTH.refresh()
                continue
            if r.status_code == 403:
                log(f"  Graph 403: {url[:80]}")
                return None
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            if att == retries - 1:
                log(f"  Graph error: {e}")
                return None
            time.sleep(2 ** att)
    return None

# ─── SP REST GET ─────────────────────────────────────────────────────────────
def spo_get(rel_url: str, retries=3):
    for att in range(retries):
        try:
            r = requests.get(f"{SP_HOST}{rel_url}", headers=AUTH.spo_headers(), timeout=30)
            if _rest_delay(r):
                continue
            if r.status_code in (401, 403):
                AUTH.refresh()
                continue
            if r.status_code == 404:
                return {"_status": "404"}
            if r.status_code == 500:
                return {"_status": "500"}
            r.raise_for_status()
            try:
                return r.json()
            except json.JSONDecodeError:
                return {"_raw_xml": r.text[:200], "_status": "xml"}
        except requests.exceptions.RequestException as e:
            if att == retries - 1:
                log(f"  SPO error: {e}")
                return None
            time.sleep(2 ** att)
    return None

# ─── Globals ─────────────────────────────────────────────────────────────────
flat = []
permissions = []
site_id = None
drive_id = None

# ─── Phase 1: Resolve ─────────────────────────────────────────────────────────
def resolve():
    global site_id, drive_id
    log("Resolving site...")
    data = graph_get(f"{GRAPH_BASE}/sites/{SITE_URL}")
    if not data or "id" not in data:
        log("Site resolution failed")
        sys.exit(1)
    site_id = data["id"]
    log(f"  Site ID: {site_id}")
    drvs = graph_get(f"{GRAPH_BASE}/sites/{site_id}/drives")
    if not drvs:
        log("No drives found")
        sys.exit(1)
    for d in drvs.get("value", []):
        if d["name"] in ("Documents", "Shared Documents"):
            drive_id = d["id"]
            log(f"  Drive: Documents ({drive_id[:40]}...)")
            break
    if not drive_id:
        log("No Documents drive found")
        sys.exit(1)

# ─── Phase 2: Enumerate items ────────────────────────────────────────────────
def enumerate_all():
    log("Enumerating all items recursively...")
    root = graph_get(f"{GRAPH_BASE}/drives/{drive_id}/root")
    if not root:
        log("Cannot get root")
        return
    queue = [(root["id"], "Shared Documents")]
    while queue:
        item_id, parent = queue.pop(0)
        children = []
        url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item_id}/children?$top=200"
        while url:
            data = graph_get(url)
            if not data:
                break
            children.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        for child in children:
            cid = child["id"]
            cname = child.get("name", "")
            cpath = f"{parent}/{cname}" if parent else cname
            is_folder = "folder" in child
            flat.append({
                "id": cid, "name": cname, "path": cpath,
                "type": "folder" if is_folder else "file",
                "parent_path": parent,
                "size": child.get("size", 0),
                "created": child.get("createdDateTime", ""),
                "modified": child.get("lastModifiedDateTime", ""),
                "created_by": child.get("createdBy", {}).get("user", {}).get("displayName", ""),
                "modified_by": child.get("lastModifiedBy", {}).get("user", {}).get("displayName", ""),
                "web_url": child.get("webUrl", ""),
                "child_count": child.get("folder", {}).get("childCount", 0) if is_folder else 0,
                "has_unique": None, "permissions": [],
            })
            if is_folder:
                queue.append((cid, cpath))
        if len(flat) % 200 == 0:
            log(f"  Enumerated {len(flat)} items...")
    log(f"Enumeration complete: {len(flat)} items")

# ─── Phase 3: Inheritance check ──────────────────────────────────────────────
def audit_inheritance():
    log("Checking permission inheritance for all items...")
    remaining = [i for i in flat if i["has_unique"] is None]
    log(f"  Items to audit: {len(remaining)}")
    for idx, item in enumerate(remaining, 1):
        srv_rel = f"{SITE_REL}/Shared Documents/{item['path'].replace('Shared Documents/', '')}"
        encoded = urllib.parse.quote(srv_rel)
        # Folder vs file REST path
        if item["type"] == "folder":
            api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{encoded}')/ListItemAllFields/HasUniqueRoleAssignments"
        else:
            api = f"{SITE_REL}/_api/web/GetFileByServerRelativeUrl('{encoded}')/ListItemAllFields/HasUniqueRoleAssignments"
        
        data = spo_get(api)
        if data and "d" in data:
            has_unique = bool(data["d"].get("HasUniqueRoleAssignments", False))
            item["has_unique"] = has_unique
            if has_unique:
                pull_roles(item)
        else:
            if data and data.get("_status") in ("404", "500"):
                item["has_unique"] = False
                item["_note"] = "REST 404/500 — assumed inherited"
            else:
                item["has_unique"] = False
        
        if idx % 100 == 0:
            unique_cnt = sum(1 for i in flat if i.get("has_unique") == True)
            log(f"  Progress: {idx}/{len(remaining)} — unique found: {unique_cnt}")
    log(f"Inheritance audit complete. Unique-permission items: {sum(1 for i in flat if i.get('has_unique')==True)}")

def pull_roles(item):
    srv_rel = f"{SITE_REL}/Shared Documents/{item['path'].replace('Shared Documents/', '')}"
    enc = urllib.parse.quote(srv_rel)
    if item["type"] == "folder":
        api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{enc}')/ListItemAllFields/RoleAssignments?$expand=Member,RoleDefinitionBindings"
    else:
        api = f"{SITE_REL}/_api/web/GetFileByServerRelativeUrl('{enc}')/ListItemAllFields/RoleAssignments?$expand=Member,RoleDefinitionBindings"
    
    data = spo_get(api)
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
                "inherited": False, "is_external": is_ext(login),
            }
            item["permissions"].append(rec)
            permissions.append(rec)

def is_ext(login: str) -> bool:
    l = (login or "").lower()
    if "#ext#" in l:
        return True
    if "@" in l:
        domain = l.split("@")[-1]
        if domain not in ("example-organization.com", "example-organization.onmicrosoft.com"):
            return True
    return False

# ─── Phase 4: Reports ────────────────────────────────────────────────────────
def generate_reports():
    log("Generating reports...")
    
    # Flat CSV
    with open(f"{OUTPUT_DIR}/htthq_v2_flat_{TS}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "id", "name", "path", "type", "parent_path", "size", "created", "modified",
            "created_by", "modified_by", "child_count", "has_unique", "permissions_count", "web_url"
        ])
        w.writeheader()
        for item in flat:
            w.writerow({
                "id": item["id"], "name": item["name"], "path": item["path"], "type": item["type"],
                "parent_path": item["parent_path"], "size": item["size"], "created": item["created"],
                "modified": item["modified"], "created_by": item["created_by"], "modified_by": item["modified_by"],
                "child_count": item["child_count"], "has_unique": str(item.get("has_unique", "")),
                "permissions_count": len(item.get("permissions", [])), "web_url": item["web_url"],
            })
    
    # Perms CSV
    with open(f"{OUTPUT_DIR}/htthq_v2_perms_{TS}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "item_id", "item_path", "item_type", "principal_id", "principal_name",
            "principal_type", "login_name", "role_name", "inherited", "is_external"
        ])
        w.writeheader()
        for r in permissions:
            w.writerow(r)
    
    # Tree JSON
    tree = build_tree()
    with open(f"{OUTPUT_DIR}/htthq_v2_tree_{TS}.json", "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2)
    
    # MD report
    generate_md(tree)
    log("Reports written.")

def build_tree():
    root = {"name": "Shared Documents", "type": "folder", "has_unique": False, "children": []}
    nodes = {"": root}
    for item in flat:
        n = {
            "name": item["name"], "type": item["type"], "size": item.get("size", 0),
            "has_unique": item.get("has_unique"), "perm_count": len(item.get("permissions", [])),
            "children": [] if item["type"] == "folder" else None
        }
        nodes[item["path"]] = n
        parent = item["parent_path"]
        if parent in nodes:
            nodes[parent]["children"].append(n)
    return root

def generate_md(tree):
    folders = [i for i in flat if i["type"] == "folder"]
    files_l = [i for i in flat if i["type"] == "file"]
    unique_items = [i for i in flat if i.get("has_unique") == True]
    ext_perms = [r for r in permissions if r.get("is_external")]
    lines = [
        "# HTTHQ Shared Documents — Permission Inheritance Analysis",
        f"\n**Generated:** {datetime.now().isoformat()}  ",
        f"**Site:** {SITE_URL}  ",
        f"**Drive:** Documents (Shared Documents)",
        "\n---\n",
        "## Summary",
        f"- **Total folders:** {len(folders)}",
        f"- **Total files:** {len(files_l)}",
        f"- **Items with unique (broken) permissions:** {len(unique_items)}",
        f"- **Items with inherited:** {len([i for i in flat if i.get('has_unique') == False])}",
        f"- **Items unknown:** {len([i for i in flat if i.get('has_unique') is None])}",
        f"- **Total role assignments:** {len(permissions)}",
        f"- **External user assignments:** {len(ext_perms)}",
    ]
    lines.extend(["\n---\n", "## Items with Broken Inheritance\n"])
    if unique_items:
        lines.append("| Path | Type | Perm Count |")
        lines.append("|------|------|------------|")
        for it in sorted(unique_items, key=lambda x: x["path"]):
            pc = len(it.get("permissions", []))
            lines.append(f"| {it['path'][:70]} | {it['type']} | {pc} |")
    else:
        lines.append("_No unique permissions found._")
    
    lines.extend(["\n---\n", "## Risk Flags\n"])
    risks = []
    for it in unique_items:
        if it["type"] == "folder" and it.get("child_count", 0) > 5:
            risks.append(f"- 🔴 **{it['path']}**: unique perms + {it['child_count']} children")
    if ext_perms:
        risks.append(f"- 🟡 {len(ext_perms)} external user assignments")
    if risks:
        lines.extend(risks)
    else:
        lines.append("_No critical risks detected._")
    
    lines.extend(["\n---\n", "## Folder Tree\n"])
    md_tree(lines, tree, 0)
    lines.append("\n---\n*End of report — generated by Richard the Code Puppy 🐶*\n")
    with open(f"{OUTPUT_DIR}/htthq_v2_analysis_{TS}.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def md_tree(lines, node, depth):
    indent = "  " * depth
    name = node.get("name", "")
    t = node.get("type", "")
    uniq = node.get("has_unique")
    marker = "🔒" if uniq == True else "✅" if uniq == False else "❓"
    if t == "folder":
        lines.append(f"{indent}- 📁 **{name}** {marker}")
        for ch in node.get("children", []):
            md_tree(lines, ch, depth + 1)
    else:
        lines.append(f"{indent}- 📄 {name} {marker}")

def save_checkpoint():
    with open(f"{OUTPUT_DIR}/.v2_chk_{TS}.json", "w") as f:
        json.dump({"flat": flat, "perms": permissions, "ts": datetime.now().isoformat()}, f)

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    log("=" * 50 + " HTTHQ AUDIT v2 " + "=" * 50)
    try:
        resolve()
        enumerate_all()
        save_checkpoint()
        audit_inheritance()
        save_checkpoint()
        generate_reports()
    except KeyboardInterrupt:
        log("INTERRUPTED — checkpoint saved")
        save_checkpoint()
    except Exception as e:
        log(f"FATAL: {e}")
        import traceback
        traceback.print_exc()
        save_checkpoint()
        sys.exit(1)
    log("AUDIT COMPLETE")

if __name__ == "__main__":
    main()
