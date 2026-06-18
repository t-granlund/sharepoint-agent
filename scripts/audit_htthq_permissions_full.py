#!/usr/bin/env python3
"""
HTTHQ Full Permissions Audit — Deep Recursive + Inheritance Analysis
Uses fresh az token, with incremental save and throttling respect.

Outputs:
  audit_output/htthq_full_tree_<timestamp>.json     (hierarchical)
  audit_output/htthq_full_flat_<timestamp>.csv       (flat items)
  audit_output/htthq_permissions_<timestamp>.csv     (role assignments)
  audit_output/htthq_inheritance_analysis_<timestamp>.md  (human analysis)
  audit_output/htthq_scan_log_<timestamp>.txt        (progress log)

Strategy:
  1. Deep recursive BFS enumeration via Graph API (fast)
  2. REST fallback for HasUniqueRoleAssignments per item (medium)
  3. Deep role assignment pulls ONLY for unique-permission items (slow)
  4. Write incrementally so we never lose progress.
"""
import os
import sys
import csv
import json
import time
import subprocess
import urllib.parse
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Optional, Any

import requests

# ─── Config ─────────────────────────────────────────────────────────────────
SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
SP_HOST = "https://example-organization.sharepoint.com"
SITE_RELATIVE = "/sites/HTTHQ"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
OUTPUT_DIR = "audit_output"
BATCH_SIZE = 200          # Graph pagination
SLEEP_ON_429 = True
RATE_LIMIT_MAX = 500      # req/min soft cap (under throttling threshold)
INCREMENTAL_SAVE_EVERY = 50  # items between disk writes

os.makedirs(OUTPUT_DIR, exist_ok=True)
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
TREE_JSON = f"{OUTPUT_DIR}/htthq_full_tree_{TIMESTAMP}.json"
FLAT_CSV = f"{OUTPUT_DIR}/htthq_full_flat_{TIMESTAMP}.csv"
PERMS_CSV = f"{OUTPUT_DIR}/htthq_permissions_{TIMESTAMP}.csv"
ANALYSIS_MD = f"{OUTPUT_DIR}/htthq_inheritance_analysis_{TIMESTAMP}.md"
LOG_FILE = f"{OUTPUT_DIR}/htthq_scan_log_{TIMESTAMP}.txt"

# ─── Logging ────────────────────────────────────────────────────────────────
def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()

# ─── Token Management ───────────────────────────────────────────────────────
class TokenManager:
    def __init__(self):
        self.token = None
        self.expires = 0
    
    def refresh(self):
        """Pull fresh token from az CLI."""
        result = subprocess.run(
            ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com", "-o", "tsv"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            raise RuntimeError(f"az failed: {result.stderr}")
        self.token = result.stdout.strip()
        # Better: also get SP token (uses same base)
        self.graph_headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        
        # SP REST token (same resource for SPO, but let's grab explicitly)
        sp_result = subprocess.run(
            ["az", "account", "get-access-token", "--resource", "00000003-0000-0ff1-ce00-000000000000", "-o", "tsv"],
            capture_output=True, text=True, timeout=30
        )
        self.sp_token = sp_result.stdout.strip() if sp_result.returncode == 0 else self.token
        self.sp_headers = {"Authorization": f"Bearer {self.sp_token}", "Accept": "application/json;odata=verbose"}
        log("Token refreshed successfully")
    
    def get(self):
        if not self.token or self.expires < time.time():
            self.refresh()
            self.expires = time.time() + 3000  # ~50 min safety buffer
        return self.token
    
    def graph_request(self, url: str, params=None, retries=3) -> Optional[Dict]:
        for attempt in range(retries):
            try:
                r = requests.get(url, headers=self.graph_headers, params=params, timeout=30)
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", 5))
                    log(f"⏱️ Graph rate limited, sleeping {wait}s")
                    time.sleep(wait)
                    continue
                if r.status_code in (401, 403):
                    self.refresh()
                    continue
                r.raise_for_status()
                return r.json()
            except requests.exceptions.RequestException as e:
                if attempt == retries - 1:
                    log(f"❌ Graph request failed after {retries} tries: {e}")
                    return None
                time.sleep(2 ** attempt)
        return None
    
    def sp_rest_request(self, rel_path: str, retries=3) -> Optional[Dict]:
        """Make a SharePoint REST call."""
        url = f"{SP_HOST}{rel_path}"
        for attempt in range(retries):
            try:
                r = requests.get(url, headers=self.sp_headers, timeout=30)
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", 10))
                    log(f"⏱️ SPO rate limited, sleeping {wait}s")
                    time.sleep(wait)
                    continue
                if r.status_code in (401, 403):
                    self.refresh()
                    continue
                r.raise_for_status()
                try:
                    return r.json()
                except json.JSONDecodeError:
                    # SP sometimes returns XML instead of JSON
                    return {"_raw_xml": r.text[:500]}
            except requests.exceptions.RequestException as e:
                if attempt == retries - 1:
                    log(f"❌ SPO REST failed after {retries} tries: {e}")
                    return None
                time.sleep(2 ** attempt)
        return None

# ─── Core Data Structures ───────────────────────────────────────────────────
class SharePointAuditor:
    def __init__(self):
        self.token_mgr = TokenManager()
        self.token_mgr.refresh()
        
        self.site_id: Optional[str] = None
        self.drive_id: Optional[str] = None
        self.site_web_id: str = ""
        
        self.flat_items: List[Dict] = []       # all files and folders
        self.permission_records: List[Dict] = []  # role assignments
        self.tree_root: Dict = {}
        
        self.items_processed = 0
        self.request_count = 0
        self.start_time = time.time()
    
    def _rate_limit_check(self):
        self.request_count += 1
        elapsed = time.time() - self.start_time
        rate = self.request_count / (elapsed / 60 + 0.1)  # current req/min
        if rate > RATE_LIMIT_MAX:
            sleep = 1
            log(f"⏱️ Rate limiting ourselves: {rate:.0f}/min, pausing {sleep}s")
            time.sleep(sleep)
    
    # ─── Phase 1: Resolve Site & Drive ──────────────────────────────────────
    def resolve_site(self):
        log(f"🔍 Resolving site: {SITE_URL}")
        data = self.token_mgr.graph_request(f"{GRAPH_BASE}/sites/{SITE_URL}")
        if not data:
            sys.exit(1)
        self.site_id = data["id"]
        self.site_web_id = data.get("id", "").split(",")[-1].split(":")[-1]  # extract web ID roughly
        log(f"✅ Site ID: {self.site_id}")
        
        drives = self.token_mgr.graph_request(f"{GRAPH_BASE}/sites/{self.site_id}/drives")
        if not drives:
            sys.exit(1)
        for d in drives.get("value", []):
            if d["name"] in ("Documents", "Shared Documents"):
                self.drive_id = d["id"]
                log(f"✅ Drive: {d['name']} ({self.drive_id[:40]}...)")
                break
        if not self.drive_id:
            log("❌ No Documents/Shared Documents drive found")
            sys.exit(1)
    
    # ─── Phase 2: Deep Recursive Enumeration ────────────────────────────────
    def enumerate_all(self):
        """Breadth-first recursive enumeration of ALL items."""
        log("🌲 Starting deep recursive enumeration...")
        
        # Start at root
        root = self.token_mgr.graph_request(f"{GRAPH_BASE}/drives/{self.drive_id}/root")
        if not root:
            log("❌ Could not get root")
            return
        
        root_item = self._graph_to_item(root, parent_path="")
        self.flat_items.append(root_item)
        
        queue = [(root["id"], "")]  # (item_id, parent_path)
        
        while queue:
            item_id, parent_path = queue.pop(0)
            self._rate_limit_check()
            
            children = self._get_children(item_id)
            if not children:
                continue
            
            for child in children.get("value", []):
                item = self._graph_to_item(child, parent_path)
                self.flat_items.append(item)
                self.items_processed += 1
                
                if item["item_type"] == "folder":
                    queue.append((item["id"], item["path"]))
                
                if self.items_processed % INCREMENTAL_SAVE_EVERY == 0:
                    self._save_progress()
        
        self._save_progress()
        log(f"✅ Enumeration complete: {len(self.flat_items)} items total")
    
    def _get_children(self, item_id: str) -> Optional[Dict]:
        all_items = []
        url = f"{GRAPH_BASE}/drives/{self.drive_id}/items/{item_id}/children?$top={BATCH_SIZE}"
        while url:
            self._rate_limit_check()
            data = self.token_mgr.graph_request(url)
            if not data:
                break
            all_items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return {"value": all_items}
    
    def _graph_to_item(self, data: Dict, parent_path: str) -> Dict:
        pr = data.get("parentReference", {})
        path = pr.get("path", "") + "/" + data.get("name", "")
        is_folder = "folder" in data
        return {
            "id": data.get("id", ""),
            "name": data.get("name", ""),
            "path": path,
            "server_relative_url": f"{SITE_RELATIVE}/Shared Documents{path.replace('/drives/' + self.drive_id + '/root:', '')}".replace("//", "/"),
            "item_type": "folder" if is_folder else "file",
            "parent_path": parent_path,
            "size": data.get("size", 0),
            "created": data.get("createdDateTime", ""),
            "modified": data.get("lastModifiedDateTime", ""),
            "created_by": data.get("createdBy", {}).get("user", {}).get("displayName", ""),
            "modified_by": data.get("lastModifiedBy", {}).get("user", {}).get("displayName", ""),
            "web_url": data.get("webUrl", ""),
            "child_count": data.get("folder", {}).get("childCount", 0) if is_folder else 0,
            "has_unique_permissions": None,
            "permissions": [],
            "external_users": [],
            "sharing_status": "unknown"
        }
    
    # ─── Phase 3: Permission Inheritance Audit ──────────────────────────────
    def audit_permissions(self):
        """
        For each item, check HasUniqueRoleAssignments via REST.
        Only do deep role pulls for items with unique permissions.
        """
        log("🔐 Starting permission inheritance audit...")
        folders = [i for i in self.flat_items if i["item_type"] == "folder"]
        files = [i for i in self.flat_items if i["item_type"] == "file"]
        total = len(folders) + len(files)
        
        log(f"  Items to check: {len(folders)} folders + {len(files)} files = {total}")
        
        # Get the list ID for REST calls  
        lists = self.token_mgr.graph_request(f"{GRAPH_BASE}/sites/{self.site_id}/lists")
        doc_lib_id = None
        if lists:
            for lst in lists.get("value", []):
                if lst.get("displayName") in ("Documents", "Shared Documents"):
                    doc_lib_id = lst.get("id", "")
                    log(f"  List ID: {doc_lib_id[:30]}...")
                    break
        
        for idx, item in enumerate(self.flat_items, 1):
            if item.get("has_unique_permissions") is not None:
                continue  # already processed (resume support)
            
            self._rate_limit_check()
            srv_rel = item["server_relative_url"]
            
            # Build proper REST path
            encoded = urllib.parse.quote(srv_rel.replace("/sites/HTTHQ", ""))
            if item["item_type"] == "folder":
                rest_path = f"{SITE_RELATIVE}/_api/web/GetFolderByServerRelativeUrl('{encoded}')/ListItemAllFields"
            else:
                rest_path = f"{SITE_RELATIVE}/_api/web/GetFileByServerRelativeUrl('{encoded}')/ListItemAllFields"
            
            # First: check HasUniqueRoleAssignments
            data = self.token_mgr.sp_rest_request(rest_path + "/HasUniqueRoleAssignments")
            if data is not None and "d" in data:
                has_unique = data["d"].get("HasUniqueRoleAssignments", False)
                item["has_unique_permissions"] = bool(has_unique)
                
                if has_unique:
                    self._pull_role_assignments(item, rest_path)
            else:
                log(f"⚠️ Could not determine inheritance for: {item['name'][:50]}")
                item["has_unique_permissions"] = False  # assume inherited on failure
            
            if idx % 20 == 0:
                log(f"  Progress: {idx}/{total} ({idx/total*100:.0f}%) - unique found so far: {sum(1 for i in self.flat_items if i.get('has_unique_permissions'))}")
                self._save_progress()
        
        self._save_progress()
        log("✅ Permission audit complete")
    
    def _pull_role_assignments(self, item: Dict, rest_base: str):
        """Pull detailed role assignments for items with unique perms."""
        url = rest_base + "/RoleAssignments?$expand=Member,RoleDefinitionBindings"
        data = self.token_mgr.sp_rest_request(url)
        if not data or "d" not in data:
            return
        
        for ra in data["d"].get("results", data["d"].get("value", [])):
            member = ra.get("Member", {})
            for rdb in ra.get("RoleDefinitionBindings", {}).get("results", []):
                record = {
                    "item_id": item["id"],
                    "item_path": item["path"],
                    "item_type": item["item_type"],
                    "principal_id": member.get("Id", ""),
                    "principal_name": member.get("Title", member.get("Name", "")),
                    "principal_type": member.get("PrincipalType", ""),
                    "principal_login": member.get("LoginName", ""),
                    "role_name": rdb.get("Name", rdb.get("RoleDefinition", {}).get("Name", "")),
                    "inherited": False,
                    "is_external": self._is_external(member.get("LoginName", "")),
                }
                item["permissions"].append(record)
                self.permission_records.append(record)
    
    def _is_external(self, login_name: str) -> bool:
        ln = (login_name or "").lower()
        return "#ext#" in ln or any(
            ln.endswith(f"@{d}") for d in ["live.com", "outlook.com", "gmail.com", "yahoo.com"]
        ) or ("@" in ln and not ln.endswith("example-organization.com"))
    
    # ─── Phase 4: Analysis & Reporting ──────────────────────────────────────
    def generate_reports(self):
        log("📊 Generating reports...")
        
        # 1. Flat CSV
        with open(FLAT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "id", "name", "path", "item_type", "parent_path", "size",
                "created", "modified", "created_by", "modified_by",
                "child_count", "has_unique_permissions", "sharing_status", "web_url"
            ])
            writer.writeheader()
            for item in self.flat_items:
                row = {k: item.get(k, "") for k in writer.fieldnames}
                row["has_unique_permissions"] = str(item.get("has_unique_permissions", ""))
                writer.writerow(row)
        
        # 2. Permissions CSV
        with open(PERMS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "item_id", "item_path", "item_type", "principal_id", "principal_name",
                "principal_type", "principal_login", "role_name", "inherited", "is_external"
            ])
            writer.writeheader()
            for r in self.permission_records:
                writer.writerow(r)
        
        # 3. Hierarchical JSON
        tree = self._build_tree()
        with open(TREE_JSON, "w", encoding="utf-8") as f:
            json.dump(tree, f, indent=2)
        
        # 4. Human-readable analysis MD
        self._generate_analysis_md(tree)
        
        log(f"📄 Reports written to {OUTPUT_DIR}/")
    
    def _build_tree(self) -> Dict:
        """Build hierarchical tree from flat_items."""
        root = {"id": "root", "name": "Shared Documents", "type": "folder", "children": []}
        lookup = {"": root}
        for item in self.flat_items:
            if not item["id"]:
                continue
            parent = item["parent_path"]
            node = {
                "id": item["id"],
                "name": item["name"],
                "type": item["item_type"],
                "size": item.get("size", 0),
                "has_unique_permissions": item.get("has_unique_permissions", None),
                "permissions_count": len(item.get("permissions", [])),
                "children": [] if item["item_type"] == "folder" else None
            }
            lookup[item["path"]] = node
            if parent in lookup:
                lookup[parent]["children"].append(node)
        return root
    
    def _generate_analysis_md(self, tree: Dict):
        folders = [i for i in self.flat_items if i["item_type"] == "folder"]
        files = [i for i in self.flat_items if i["item_type"] == "file"]
        unique_items = [i for i in self.flat_items if i.get("has_unique_permissions") == True]
        inherited_items = [i for i in self.flat_items if i.get("has_unique_permissions") == False]
        unknown_items = [i for i in self.flat_items if i.get("has_unique_permissions") is None]
        external_perms = [r for r in self.permission_records if r.get("is_external")]
        
        lines = [
            "# HTTHQ Shared Documents — Permission Inheritance Analysis",
            f"\n**Generated:** {datetime.now().isoformat()}",
            f"**Site:** {SITE_URL}",
            f"**Drive:** Documents (Shared Documents)",
            "\n---\n",
            "## 📈 Summary",
            f"- **Total folders:** {len(folders)}",
            f"- **Total files:** {len(files)}",
            f"- **Items with unique permissions:** {len(unique_items)}",
            f"- **Items with inherited permissions:** {len(inherited_items)}",
            f"- **Items where inheritance could not be determined:** {len(unknown_items)}",
            f"- **Total role assignment records:** {len(self.permission_records)}",
            f"- **External user assignments:** {len(external_perms)}",
            "\n---\n",
            "## 🎭 Items with Broken Inheritance (Unique Permissions)",
        ]
        
        if unique_items:
            lines.append("\n| Path | Type | Permission Count |")
            lines.append("|------|------|------------------|")
            for item in sorted(unique_items, key=lambda x: x["path"]):
                pc = len(item.get("permissions", []))
                lines.append(f"| {item['path'][:80]} | {item['item_type']} | {pc} |")
        else:
            lines.append("\n_No items with unique permissions found._")
        
        lines.extend([
            "\n---\n",
            "## 🔗 Sharing Links Detected",
            "(Requires separate check — Graph permissions API)",
            "\n---\n",
            "## ⚠️ Risk Flags",
        ])
        
        risks = []
        # Find unique-permission items with large child counts
        for item in unique_items:
            if item["item_type"] == "folder" and item.get("child_count", 0) > 10:
                risks.append(f"- 🔴 **{item['path']}** has unique permissions AND {item['child_count']} children — {item['child_count']} items may inherit these unique perms")
        
        if external_perms:
            risks.append(f"- 🟡 {len(external_perms)} role assignments involve external users")
        
        if unknown_items:
            risks.append(f"- 🟡 {len(unknown_items)} items could not have their inheritance status determined")
        
        if risks:
            lines.extend(risks)
        else:
            lines.append("\n_No significant risks detected._")
        
        lines.extend([
            "\n---\n",
            "## 📁 Folder Tree (with permission status)",
        ])
        self._append_tree_md(lines, tree, 0)
        
        lines.append("\n---\n*End of analysis*\n")
        with open(ANALYSIS_MD, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    
    def _append_tree_md(self, lines: List[str], node: Dict, depth: int):
        indent = "  " * depth
        name = node.get("name", "Unnamed")
        item_type = node.get("type", "folder")
        unique = node.get("has_unique_permissions")
        if item_type == "folder":
            perm_marker = "[🔒 unique]" if unique else "[inherited]" if unique == False else "[?]"
            lines.append(f"{indent}- 📁 **{name}** {perm_marker}")
            for child in node.get("children", []):
                self._append_tree_md(lines, child, depth + 1)
        else:
            perm_marker = "[🔒 unique]" if unique else "[inherited]" if unique == False else "[?]"
            size_kb = node.get("size", 0) / 1024
            lines.append(f"{indent}- 📄 {name} ({size_kb:.1f} KB) {perm_marker}")
    
    def _save_progress(self):
        """Incremental save to disk — survives crashes."""
        dump = {
            "timestamp": datetime.now().isoformat(),
            "items_processed": self.items_processed,
            "flat_items": self.flat_items,
            "permission_records": self.permission_records
        }
        with open(f"{OUTPUT_DIR}/.last_session_{TIMESTAMP}.json", "w") as f:
            json.dump(dump, f)
    
    def run(self):
        log("=" * 60)
        log(" HTTHQ FULL PERMISSIONS AUDIT — Starting")
        log("=" * 60)
        
        self.resolve_site()
        self.enumerate_all()
        self.audit_permissions()
        self.generate_reports()
        
        log("=" * 60)
        log(" AUDIT COMPLETE")
        log(f" Reports saved to: {OUTPUT_DIR}/")
        log("=" * 60)


# ─── Runner ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        auditor = SharePointAuditor()
        auditor.run()
    except KeyboardInterrupt:
        log("\n⚠️ Interrupted by user. Progress saved to .last_session_*.json")
    except Exception as e:
        log(f"\n💥 Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
