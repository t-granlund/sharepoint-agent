#!/usr/bin/env python3
"""
HTTHQ Full Audit v3 — Incremental saves, longer-running, moderate throttle.
Expected total time: ~5-15 minutes depending on library depth.
"""
import os, sys, csv, json, time, subprocess, urllib.parse, base64
from datetime import datetime
from typing import Optional, List, Dict, Any

import requests

SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
SP_HOST = "https://example-organization.sharepoint.com"
SITE_REL = "/sites/HTTHQ"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
OUTPUT_DIR = "audit_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)
TS = datetime.now().strftime("%Y%m%d_%H%M%S")

LOG_F = f"{OUTPUT_DIR}/htthq_v3_log_{TS}.txt"
CHK_F = f"{OUTPUT_DIR}/.v3_chk_{TS}.json"

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_F, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()

# ─── Auth ────────────────────────────────────────────────────────────────────
class AuthMgr:
    def __init__(self):
        self._g = None
        self._s = None
        self._exp = 0
    def _tk(self, res: str) -> str:
        r = subprocess.run(["az","account","get-access-token","--resource",res,"--output","json"],
                           capture_output=True,text=True,timeout=30)
        if r.returncode != 0:
            raise RuntimeError(f"az: {r.stderr[:300]}")
        return json.loads(r.stdout)["accessToken"]
    def refresh(self):
        self._g = self._tk("https://graph.microsoft.com")
        try:
            self._s = self._tk("00000003-0000-0ff1-ce00-000000000000")
        except Exception:
            self._s = self._g
        try:
            p = json.loads(base64.urlsafe_b64decode(self._g.split(".")[1] + "=="))
            self._exp = p.get("exp", 0)
        except Exception:
            self._exp = time.time() + 3000
    def ensure(self):
        if not self._g or time.time() > self._exp - 120:
            self.refresh()
    def gh(self): self.ensure(); return {"Authorization": f"Bearer {self._g}", "Content-Type": "application/json"}
    def sh(self): self.ensure(); return {"Authorization": f"Bearer {self._s}", "Accept": "application/json;odata=verbose"}

AUTH = AuthMgr()
_req = 0

def sensible_wait(r=None):
    global _req
    _req += 1
    if r is not None and r.status_code == 429:
        w = int(r.headers.get("Retry-After", 5))
        log(f"  Rate limit, wait {w}s")
        time.sleep(w)
        return True
    if _req % 100 == 0:
        log(f"  Requests: {_req}")
    # Self-throttle ~2/sec average
    time.sleep(0.3)
    return False

def gget(url, params=None, retries=3):
    for a in range(retries):
        try:
            r = requests.get(url, headers=AUTH.gh(), params=params, timeout=30)
            if sensible_wait(r):
                continue
            if r.status_code == 401:
                AUTH.refresh(); continue
            if r.status_code == 403:
                log(f"  Graph 403: {url[:80]}..."); return None
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if a == retries - 1:
                log(f"  Graph err: {e}"); return None
            time.sleep(2 ** a)
    return None

def sget(rel, retries=3):
    for a in range(retries):
        try:
            r = requests.get(f"{SP_HOST}{rel}", headers=AUTH.sh(), timeout=30)
            if sensible_wait(r):
                continue
            if r.status_code in (401, 403):
                AUTH.refresh(); continue
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
                log(f"  SPO err: {e}"); return None
            time.sleep(2 ** a)
    return None

# ─── Resume helpers ──────────────────────────────────────────────────────────
def load_state():
    if os.path.exists(CHK_F):
        log(f"Resuming from checkpoint: {CHK_F}")
        with open(CHK_F, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d.get("flat", []), d.get("perms", []), d.get("site_id"), d.get("drive_id"), d.get("queue", [])
    return [], [], None, None, []

def save_state(flat, perms, site_id, drive_id, queue):
    with open(CHK_F, "w", encoding="utf-8") as f:
        json.dump({"flat": flat, "perms": perms, "site_id": site_id, "drive_id": drive_id,
                   "queue": queue, "ts": datetime.now().isoformat()}, f)

# ─── Core ────────────────────────────────────────────────────────────────────
def resolve():
    log("Resolving site...")
    d = gget(f"{GRAPH_BASE}/sites/{SITE_URL}")
    if not d or "id" not in d:
        log("Site fail"); sys.exit(1)
    sid = d["id"]
    drvs = gget(f"{GRAPH_BASE}/sites/{sid}/drives")
    did = None
    for dr in drvs.get("value", []):
        if dr["name"] in ("Documents", "Shared Documents"):
            did = dr["id"]
            break
    if not did:
        log("No drive"); sys.exit(1)
    log(f"Site OK, Drive OK")
    return sid, did

def do_enum(flat, drive_id):
    log("Enumerating...")
    root = gget(f"{GRAPH_BASE}/drives/{drive_id}/root")
    if not root:
        log("Root fail"); return []
    queue = [(root["id"], "Shared Documents")]
    seen = {r["id"] for r in flat}  # resume support
    while queue:
        item_id, parent = queue.pop(0)
        if item_id in seen:
            continue
        seen.add(item_id)
        children = []
        url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item_id}/children?$top=200"
        while url:
            d = gget(url)
            if not d:
                break
            children.extend(d.get("value", []))
            url = d.get("@odata.nextLink")
        for child in children:
            cid = child["id"]
            cname = child.get("name", "")
            cpath = f"{parent}/{cname}" if parent else cname
            isf = "folder" in child
            flat.append({
                "id": cid, "name": cname, "path": cpath,
                "type": "folder" if isf else "file",
                "parent_path": parent,
                "size": child.get("size", 0),
                "created": child.get("createdDateTime", ""),
                "modified": child.get("lastModifiedDateTime", ""),
                "created_by": child.get("createdBy", {}).get("user", {}).get("displayName", ""),
                "modified_by": child.get("lastModifiedBy", {}).get("user", {}).get("displayName", ""),
                "web_url": child.get("webUrl", ""),
                "child_count": child.get("folder", {}).get("childCount", 0) if isf else 0,
                "has_unique": None, "permissions": [],
            })
            if isf:
                queue.append((cid, cpath))
        if len(flat) % 50 == 0:
            log(f"  Enumerated {len(flat)} items, queue: {len(queue)}")
    log(f"Enumeration done: {len(flat)} items")
    return flat

def audit_perms(flat):
    log("Auditing permissions...")
    remaining = [i for i in flat if i["has_unique"] is None]
    log(f"  Items to audit: {len(remaining)}")
    for idx, item in enumerate(remaining, 1):
        rel_path = f"{SITE_REL}/Shared Documents/{item['path'].replace('Shared Documents/','')}"
        enc = urllib.parse.quote(rel_path)
        if item["type"] == "folder":
            api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{enc}')/ListItemAllFields/HasUniqueRoleAssignments"
        else:
            api = f"{SITE_REL}/_api/web/GetFileByServerRelativeUrl('{enc}')/ListItemAllFields/HasUniqueRoleAssignments"
        d = sget(api)
        if d and "d" in d:
            uni = bool(d["d"].get("HasUniqueRoleAssignments", False))
            item["has_unique"] = uni
            if uni:
                pull(item)
        elif d and d.get("_st") in ("404", "500"):
            item["has_unique"] = False
            item["_note"] = f"REST {d['_st']}"
        else:
            item["has_unique"] = False
        if idx % 100 == 0:
            uc = sum(1 for i in flat if i.get("has_unique") == True)
            log(f"  Progress: {idx}/{len(remaining)}, unique: {uc}")
    log(f"Perm audit done, unique items: {sum(1 for i in flat if i.get('has_unique')==True)}")

def pull(item):
    rel = f"{SITE_REL}/Shared Documents/{item['path'].replace('Shared Documents/','')}"
    enc = urllib.parse.quote(rel)
    if item["type"] == "folder":
        api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{enc}')/ListItemAllFields/RoleAssignments?$expand=Member,RoleDefinitionBindings"
    else:
        api = f"{SITE_REL}/_api/web/GetFileByServerRelativeUrl('{enc}')/ListItemAllFields/RoleAssignments?$expand=Member,RoleDefinitionBindings"
    d = sget(api)
    if not d or "d" not in d:
        return
    results = d["d"].get("results", d["d"].get("value", []))
    for ra in results:
        m = ra.get("Member", {})
        for rdb in ra.get("RoleDefinitionBindings", {}).get("results", []):
            lg = m.get("LoginName", "")
            perms = item.setdefault("permissions", [])
            r = {"item_id": item["id"], "item_path": item["path"], "item_type": item["type"],
                 "principal_id": m.get("Id", ""), "principal_name": m.get("Title", m.get("Name", "")),
                 "principal_type": m.get("PrincipalType", ""), "login_name": lg,
                 "role_name": rdb.get("Name", rdb.get("RoleDefinition", {}).get("Name", "")),
                 "inherited": False, "is_external": ext(lg)}
            perms.append(r)

def ext(login):
    l = (login or "").lower()
    if "#ext#" in l:
        return True
    if "@" in l:
        domain = l.split("@")[-1]
        if domain not in ("example-organization.com", "example-organization.onmicrosoft.com"):
            return True
    return False

# ─── Reports ─────────────────────────────────────────────────────────────────
def report(flat, perms):
    log("Generating reports...")
    
    with open(f"{OUTPUT_DIR}/htthq_v3_flat_{TS}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id","name","path","type","parent_path","size","created","modified","created_by","modified_by","child_count","has_unique","permissions_count","web_url"])
        w.writeheader()
        for item in flat:
            w.writerow({"id": item["id"], "name": item["name"], "path": item["path"],
                        "type": item["type"], "parent_path": item["parent_path"], "size": item["size"],
                        "created": item["created"], "modified": item["modified"],
                        "created_by": item["created_by"], "modified_by": item["modified_by"],
                        "child_count": item["child_count"], "has_unique": str(item.get("has_unique","")),
                        "permissions_count": len(item.get("permissions",[])), "web_url": item["web_url"]})
    
    ps = []
    for item in flat:
        ps.extend(item.get("permissions", []))
    with open(f"{OUTPUT_DIR}/htthq_v3_perms_{TS}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["item_id","item_path","item_type","principal_id","principal_name","principal_type","login_name","role_name","inherited","is_external"])
        w.writeheader()
        for r in ps:
            w.writerow(r)
    
    tree = build_tree(flat)
    with open(f"{OUTPUT_DIR}/htthq_v3_tree_{TS}.json", "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2)
    
    generate_md(flat, ps, tree)
    log("Reports done.")

def build_tree(flat):
    root = {"name": "Shared Documents", "type": "folder", "has_unique": False, "children": []}
    nodes = {"": root}
    for item in flat:
        n = {"name": item["name"], "type": item["type"], "size": item.get("size",0),
             "has_unique": item.get("has_unique"), "perm_count": len(item.get("permissions",[])),
             "children": [] if item["type"] == "folder" else None}
        nodes[item["path"]] = n
        parent = item.get("parent_path", "")
        if parent in nodes:
            nodes[parent]["children"].append(n)
    return root

def generate_md(flat, perms, tree):
    folders = [i for i in flat if i["type"] == "folder"]
    files_l = [i for i in flat if i["type"] == "file"]
    unique_items = [i for i in flat if i.get("has_unique") == True]
    ext_perms = [r for r in perms if r.get("is_external")]
    lines = [
        "# HTTHQ Shared Documents — Permission Inheritance Analysis",
        f"\n**Generated:** {datetime.now().isoformat()}  ", "**Site:** HTT Headquarters (HTTHQ)",
        "\n---\n", "## Summary",
        f"- **Total folders:** {len(folders)}", f"- **Total files:** {len(files_l)}",
        f"- **Items with unique (broken) permissions:** {len(unique_items)}",
        f"- **Items inherited:** {len([i for i in flat if i.get('has_unique') == False])}",
        f"- **Role assignments:** {len(perms)}", f"- **External assignments:** {len(ext_perms)}",
        "\n---\n", "## Items with Broken Inheritance\n"
    ]
    if unique_items:
        lines.append("| Path | Type | Perm Count |")
        lines.append("|------|------|------------|")
        for it in sorted(unique_items, key=lambda x: x["path"]):
            lines.append(f"| {it['path'][:70]} | {it['type']} | {len(it.get('permissions',[]))} |")
    else:
        lines.append("_None found._")
    lines.extend(["\n---\n", "## Risk Flags\n"])
    risks = []
    for it in unique_items:
        if it["type"] == "folder" and it.get("child_count", 0) > 5:
            risks.append(f"- 🔴 **{it['path']}**: unique + {it['child_count']} children")
    if ext_perms:
        risks.append(f"- 🟡 {len(ext_perms)} external user roles")
    if risks:
        lines.extend(risks)
    else:
        lines.append("_No critical risks._")
    lines.extend(["\n---\n", "## Folder Tree\n"])
    md_tree(lines, tree, 0)
    lines.append("\n---\n*Report generated by Richard the Code Puppy 🐶*\n")
    with open(f"{OUTPUT_DIR}/htthq_v3_analysis_{TS}.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def md_tree(lines, node, depth):
    indent = "  " * depth
    marker = "🔒" if node.get("has_unique") == True else "✅" if node.get("has_unique") == False else "❓"
    if node.get("type") == "folder":
        lines.append(f"{indent}- 📁 **{node.get('name','')}** {marker}")
        for c in node.get("children", []):
            md_tree(lines, c, depth + 1)
    else:
        lines.append(f"{indent}- 📄 {node.get('name','')} {marker}")

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    log("=" * 50 + " HTTHQ AUDIT v3 " + "=" * 50)
    flat, perms, site_id, drive_id, queue = load_state()
    
    try:
        if not site_id or not drive_id:
            site_id, drive_id = resolve()
        
        if not flat:
            flat = do_enum(flat, drive_id)
            save_state(flat, perms, site_id, drive_id, [])
        
        audit_perms(flat)
        save_state(flat, perms, site_id, drive_id, [])
        
        # Flatten perms
        perms = []
        for item in flat:
            perms.extend(item.get("permissions", []))
        report(flat, perms)
        
    except KeyboardInterrupt:
        log("INTERRUPTED — checkpoint saved. Resume by re-running.")
        save_state(flat, perms if 'perms' in dir() else [], site_id, drive_id, [])
    except Exception as e:
        log(f"FATAL: {e}")
        import traceback; traceback.print_exc()
        save_state(flat, perms if 'perms' in dir() else [], site_id, drive_id, [])
        sys.exit(1)
    log("AUDIT COMPLETE")

if __name__ == "__main__":
    main()
