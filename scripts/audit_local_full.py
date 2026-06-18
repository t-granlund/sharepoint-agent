#!/usr/bin/env python3
"""
HTTHQ Full Audit — Local Overnight Edition
Runs on your MacBook, survives Ctrl+C, resumes from checkpoint.

Usage:
    python audit_local_full.py              # fresh start
    python audit_local_full.py              # auto-resumes if checkpoint exists
    Ctrl+C                                 # saves checkpoint, graceful exit

Expected: ~12 min (delta enum) + ~2.5 hrs (folder perms) = ~2h 45m total
"""
import os, sys, csv, json, time, urllib.request, urllib.parse, subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests

SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
SITE_REL = "/sites/HTTHQ"
SP_HOST = "https://example-organization.sharepoint.com"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
OUTPUT_DIR = Path("./audit_output")
OUTPUT_DIR.mkdir(exist_ok=True)
TS = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = OUTPUT_DIR / f"htthq_local_log_{TS}.txt"
CKPT = OUTPUT_DIR / "htthq_local_checkpoint.json"

# ═══════════════════════════════════════════════════════════════════════════
# Auth: Local az CLI only
# ═══════════════════════════════════════════════════════════════════════════
class LocalAuth:
    def __init__(self):
        self._tokens = {}
        self._exp = {}

    def _get(self, resource: str) -> str:
        now = time.time()
        if resource not in self._tokens or now > self._exp.get(resource, 0) - 180:
            r = subprocess.run(
                ["az", "account", "get-access-token", "--resource", resource, "--output", "json"],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode != 0:
                raise RuntimeError(f"az token failed: {r.stderr[:300]}")
            tok = json.loads(r.stdout)["accessToken"]
            self._tokens[resource] = tok
            self._exp[resource] = now + 3500
            log(f"Refreshed token for {resource.split('/')[-1]}")
        return self._tokens[resource]

    def graph_hdr(self):
        return {"Authorization": f"Bearer {self._get('https://graph.microsoft.com')}"}
    def spo_hdr(self):
        try:
            return {"Authorization": f"Bearer {self._get('00000003-0000-0ff1-ce00-000000000000')}",
                    "Accept": "application/json;odata=verbose"}
        except Exception:
            # Fallback to Graph token for SPO REST (sometimes works)
            return {"Authorization": f"Bearer {self._get('https://graph.microsoft.com')}",
                    "Accept": "application/json;odata=verbose"}

AUTH = LocalAuth()

# ═══════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════
def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())

# ═══════════════════════════════════════════════════════════════════════════
# Phase A: Delta Enumeration (same as CI version)
# ═══════════════════════════════════════════════════════════════════════════
def phase_a_delta() -> List[Dict]:
    if CKPT.exists():
        with open(CKPT, "r") as f:
            data = json.load(f)
        if "flat" in data and data.get("phase_a_complete"):
            log(f"Resumed from checkpoint: {len(data['flat'])} items already enumerated")
            return data["flat"]

    log("=" * 50 + " Phase A: Delta Enumeration " + "=" * 50)
    t0 = time.time()

    site = requests.get(f"{GRAPH_BASE}/sites/{SITE_URL}", headers=AUTH.graph_hdr(), timeout=30).json()
    site_id = site["id"]
    drives = requests.get(f"{GRAPH_BASE}/sites/{site_id}/drives", headers=AUTH.graph_hdr(), timeout=30).json()
    drive_id = next(d["id"] for d in drives.get("value", []) if d["name"] in ("Documents", "Shared Documents"))
    log(f"Site: {site_id} | Drive: {drive_id}")

    flat = []
    url = f"{GRAPH_BASE}/drives/{drive_id}/root/delta?select=id,name,folder,file,size,createdDateTime,lastModifiedDateTime,createdBy,lastModifiedBy,parentReference,webUrl&$top=999"
    page = 0

    while url:
        page += 1
        r = requests.get(url, headers=AUTH.graph_hdr(), timeout=60)
        if r.status_code == 401:
            url = r.url
            continue
        r.raise_for_status()
        data = r.json()

        for item in data.get("value", []):
            if item.get("deleted"):
                continue
            parent_path = item.get("parentReference", {}).get("path", "")
            if ":/" in parent_path:
                rel_parent = parent_path.split(":/", 1)[1]
            else:
                rel_parent = "Shared Documents"

            name = item.get("name", "")
            is_folder = "folder" in item
            flat.append({
                "id": item["id"], "name": name,
                "path": f"{rel_parent}/{name}" if rel_parent else name,
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
                "drive_id": drive_id,
            })

        url = data.get("@odata.nextLink")
        if data.get("@odata.deltaLink"):
            log(f"Delta complete after {page} pages")
            break
        if page % 20 == 0:
            log(f"  Page {page}: {len(flat):,} items...")

    elapsed = time.time() - t0
    log(f"Phase A complete: {len(flat):,} items in {page} pages ({elapsed/60:.1f} min)")

    # Save checkpoint
    with open(CKPT, "w") as f:
        json.dump({"flat": flat, "phase_a_complete": True, "ts": datetime.now().isoformat()}, f)
    return flat

# ═══════════════════════════════════════════════════════════════════════════
# Phase B: Folder Permissions with Checkpoint/Resume
# ═══════════════════════════════════════════════════════════════════════════
_req_count = 0

def _gget(url: str, retries: int = 3) -> requests.Response:
    """Graph API GET with retries, 429 backoff, and longer timeout."""
    for attempt in range(retries):
        try:
            r = requests.get(url, headers=AUTH.graph_hdr(), timeout=60)
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 5))
                time.sleep(wait)
                continue
            return r
        except (requests.ReadTimeout, requests.ConnectionError) as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # 1s, 2s, 4s backoff
                continue
            raise
    return requests.Response()  # Should not reach here


def sget(rel: str) -> Optional[dict]:
    global _req_count
    _req_count += 1
    url = f"{SP_HOST}{rel}"
    for attempt in range(3):
        r = requests.get(url, headers=AUTH.spo_hdr(), timeout=30)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", 5))
            log(f"SPO 429, retry in {wait}s")
            time.sleep(wait)
            continue
        if r.status_code == 401:
            time.sleep(1)
            continue
        if r.status_code == 200:
            return r.json()
        # Non-200 but not retryable
        return {"_st": r.status_code, "_raw": r.text[:100]}
    return {"_st": "timeout"}


def phase_b_folders(flat: List[Dict]) -> List[Dict]:
    log("=" * 50 + " Phase B: Folder Permissions via Graph API " + "=" * 50)

    # Resume check
    checked_ids = set()
    if CKPT.exists():
        with open(CKPT, "r") as f:
            data = json.load(f)
        if data.get("phase_a_complete") and "checked_ids" in data:
            checked_ids = set(data["checked_ids"])
            log(f"Resuming: {len(checked_ids):,} folders already checked")

    # Build folder list + get drive_id from checkpoint or reconstruct
    drive_id = None
    for item in flat:
        if item["type"] == "file":
            item["has_unique"] = False
        elif "drive_id" in item:
            drive_id = item["drive_id"]

    if not drive_id:
        # Re-fetch drive_id
        site = requests.get(f"{GRAPH_BASE}/sites/{SITE_URL}", headers=AUTH.graph_hdr(), timeout=30).json()
        drives = requests.get(f"{GRAPH_BASE}/sites/{site['id']}/drives", headers=AUTH.graph_hdr(), timeout=30).json()
        drive_id = next(d["id"] for d in drives.get("value", []) if d["name"] in ("Documents", "Shared Documents"))

    # Mark deep folders as assumed inherited (no perms check needed)
    for item in flat:
        if item["type"] == "folder" and item["path"].count("/") > 2:
            item["has_unique"] = False
            item["_note"] = "Skipped (depth > 2, assumed inherited)"

    # ONLY check top-level (depth 1) and second-layer (depth 2) folders
    # Depth = number of slashes in the path (Shared Documents/A/B = depth 2)
    # We include depth 1 and depth 2; deeper folders just inherit
    folders = [
        i for i in flat
        if i["type"] == "folder" and i["id"] not in checked_ids
        and i["path"].count("/") <= 2
    ]
    deeper_count = sum(1 for i in flat if i["type"] == "folder" and i["path"].count("/") > 2)
    log(f"Folders to check: {len(folders):,} (top 2 layers; skipping {deeper_count:,} deeper folders)")
    log("  (Depth 1 = children of root | Depth 2 = grandchildren of root)")
    t0 = time.time()
    calls = 0

    try:
        for idx, item in enumerate(folders, 1):
            # Graph permissions: /drives/{drive-id}/items/{item-id}/permissions
            perm_url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item['id']}/permissions"
            calls += 1
            r = _gget(perm_url)

            if r.status_code == 200:
                perms_data = r.json().get("value", [])
                # Graph permissions DON'T directly expose HasUniqueRoleAssignments,
                # but we can infer: if there are permissions with NO inheritedFrom
                # or permissions that differ from typical inherited ones
                item["has_unique"] = _infer_unique(perms_data)
                for p in perms_data:
                    _parse_graph_perm(item, p)
            elif r.status_code == 404:
                item["has_unique"] = False
            else:
                item["has_unique"] = False
                item["_perm_error"] = r.status_code

            checked_ids.add(item["id"])

            if idx % 1000 == 0:
                _save_ckpt(flat, checked_ids, drive_id=drive_id)
                elapsed = time.time() - t0
                rate = idx / elapsed if elapsed > 0 else 0
                eta = (len(folders) - idx) / rate / 60 if rate > 0 else 0
                log(f"  [{idx:,}/{len(folders):,}] {rate:.1f}/sec | ETA: {eta:.1f}m | Calls: {calls}")

    except KeyboardInterrupt:
        log("INTERRUPTED — saving checkpoint...")
        _save_ckpt(flat, checked_ids, drive_id=drive_id)
        log("Checkpoint saved. Re-run to resume.")
        sys.exit(0)

    _save_ckpt(flat, checked_ids, done=True, drive_id=drive_id)
    elapsed = time.time() - t0
    total_unique = sum(1 for f in flat if f.get("has_unique") == True)
    log(f"Phase B complete: {total_unique} unique-permission folders out of {len([f for f in flat if f['type']=='folder']):,} ({elapsed/60:.1f} min, {calls} Graph calls)")
    return flat


def _infer_unique(perms: List[dict]) -> bool:
    """Infer if permissions are unique (not purely inherited).
    Heuristic: if any permission lacks inheritedFrom, or has non-standard roles."""
    for p in perms:
        # If inheritedFrom is present and non-null, it's inherited
        # If missing/None, it's a direct (unique) permission
        if not p.get("inheritedFrom"):
            return True
        # If roles contain something other than read/write, flag it
        roles = p.get("roles", [])
        if any(r not in ("read", "write", "owner") for r in roles):
            return True
    return False


def _parse_graph_perm(item: Dict, p: dict):
    """Parse a Graph permission object into our format."""
    granted = p.get("grantedTo", {})
    user = granted.get("user", {})
    group = granted.get("group", {})

    # Also check grantedToIdentities for group memberships
    identities = p.get("grantedToIdentities", [])
    targets = []
    if user:
        targets.append((user.get("displayName", ""), user.get("email", ""), "user"))
    if group:
        targets.append((group.get("displayName", ""), group.get("email", ""), "group"))
    for ident in identities:
        u = ident.get("user", {})
        g = ident.get("group", {})
        if u:
            targets.append((u.get("displayName", ""), u.get("email", ""), "user"))
        if g:
            targets.append((g.get("displayName", ""), g.get("email", ""), "group"))

    for name, email, ptype in targets:
        login = email or name
        item["permissions"].append({
            "item_id": item["id"], "item_path": item["path"], "item_type": "folder",
            "principal_id": p.get("id", ""), "principal_name": name, "principal_type": ptype,
            "login_name": login, "role_name": ",".join(p.get("roles", [])),
            "inherited": bool(p.get("inheritedFrom")), "is_external": _is_ext(login),
        })


def _is_ext(login: str) -> bool:
    l = (login or "").lower()
    return "#ext#" in l or ("@" in l and l.split("@")[-1] not in ("example-organization.com", "example-organization.onmicrosoft.com"))


def _save_ckpt(flat, checked_ids, done=False, drive_id=None):
    # Inject drive_id into first item for resume
    if drive_id and flat:
        flat[0]["drive_id"] = drive_id
    with open(CKPT, "w") as f:
        json.dump({
            "flat": flat,
            "phase_a_complete": True,
            "checked_ids": list(checked_ids),
            "done": done,
            "ts": datetime.now().isoformat()
        }, f)

# ═══════════════════════════════════════════════════════════════════════════
# Phase C: Reports
# ═══════════════════════════════════════════════════════════════════════════
def phase_c_reports(flat: List[Dict]):
    log("=" * 50 + " Phase C: Reports " + "=" * 50)
    folders = [i for i in flat if i["type"] == "folder"]
    files = [i for i in flat if i["type"] == "file"]
    unique_items = [i for i in flat if i.get("has_unique") == True]
    perms = []
    for item in flat:
        perms.extend(item.get("permissions", []))

    # Flat CSV
    flat_csv = OUTPUT_DIR / f"htthq_local_flat_{TS}.csv"
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
    perms_csv = OUTPUT_DIR / f"htthq_local_perms_{TS}.csv"
    with open(perms_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["item_id","item_path","item_type","principal_id","principal_name","principal_type","login_name","role_name","inherited","is_external"])
        for r in perms:
            w.writerow([r["item_id"], r["item_path"], r["item_type"],
                       r["principal_id"], r["principal_name"], r["principal_type"],
                       r["login_name"], r["role_name"], r["inherited"], r["is_external"]])
    log(f"Perms CSV: {perms_csv.name}")

    # Analysis MD
    md = OUTPUT_DIR / f"htthq_local_analysis_{TS}.md"
    _write_md(md, flat, folders, files, unique_items, perms)
    log(f"Analysis MD: {md.name}")

    return {"flat_csv": str(flat_csv.name), "perms_csv": str(perms_csv.name), "analysis_md": str(md.name)}


def _write_md(path, flat, folders, files, unique_items, perms):
    lines = [
        "# HTTHQ Shared Documents — Full Local Audit",
        f"\n**Date:** {datetime.now().isoformat()}",
        f"**Method:** Graph /delta + SPO REST (local overnight run)",
        f"\n**Total Items:** {len(flat):,} | **Folders:** {len(folders):,} | **Files:** {len(files):,}",
        f"**Unique-permission folders:** {len(unique_items):,} 🔒",
        f"**Role assignments:** {len(perms):,}",
    ]

    if unique_items:
        lines.append("\n## 🔒 Unique-Permission Folders\n")
        for it in sorted(unique_items, key=lambda x: x["path"]):
            lines.append(f"- **{it['path']}** — {it['child_count']} children")

    high_risk = [u for u in unique_items if u.get("child_count", 0) > 10]
    if high_risk:
        lines.append("\n## ⚠️ High Risk (>10 children)\n")
        for it in high_risk:
            lines.append(f"- **{it['path']}** — {it['child_count']} children inherit unique perms")

    ext_perms = [r for r in perms if r.get("is_external")]
    if ext_perms:
        lines.append(f"\n## 🟡 External Users ({len(ext_perms)} role assignments)\n")

    lines.append("\n---\n*Generated by Richard the Code Puppy 🐶 | Local overnight edition*")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════
def main():
    log("=" * 60 + " HTTHQ FULL LOCAL AUDIT " + "=" * 60)
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
        "elapsed_minutes": round(elapsed / 60, 1),
        "reports": report_paths,
        "timestamp": datetime.now().isoformat(),
    }
    with open(OUTPUT_DIR / "htthq_local_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    log(f"\n{'=' * 50}")
    log(f"DONE in {elapsed/60:.1f} minutes")
    log(f"Items: {summary['items_total']:,} | Folders: {summary['folders']:,} | Unique: {summary['unique_folders']}")
    log(f"Reports: {report_paths}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nINTERRUPTED — checkpoint saved. Re-run to resume.")
        sys.exit(0)
