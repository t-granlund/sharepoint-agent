#!/usr/bin/env python3
"""
Phase B: Permission Inheritance Audit via SharePoint REST API
Requires Phase A output (audit_output/phaseA_enumeration.json)
Uses SPO REST for HasUniqueRoleAssignments on every item.
"""
import os, sys, json, time, subprocess, urllib.parse, base64
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

import requests

OUTPUT_DIR = "audit_output"
PHASEA = Path(OUTPUT_DIR) / "phaseA_enumeration.json"
PHASEB = Path(OUTPUT_DIR) / "phaseB_inheritance.json"
PHASEB_LOG = Path(OUTPUT_DIR) / "phaseB_log.txt"

SP_HOST = "https://example-organization.sharepoint.com"
SITE_REL = "/sites/HTTHQ"

class TokenMgr:
    def __init__(self):
        self._token = None
        self._exp = 0
    def refresh(self):
        r = subprocess.run(
            ["az","account","get-access-token","--resource","00000003-0000-0ff1-ce00-000000000000","--output","json"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            raise RuntimeError(f"az fail: {r.stderr[:300]}")
        self._token = json.loads(r.stdout)["accessToken"]
        try:
            p = json.loads(base64.urlsafe_b64decode(self._token.split(".")[1] + "=="))
            self._exp = p.get("exp", 0)
        except Exception:
            self._exp = time.time() + 3000
    def ensure(self):
        if not self._token or time.time() > self._exp - 120:
            self.refresh()
    def hdrs(self):
        self.ensure()
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json;odata=verbose"}

AUTH = TokenMgr()
_req = 0

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(PHASEB_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def spo_get(rel: str, retries=3):
    global _req
    for a in range(retries):
        _req += 1
        if _req % 50 == 0:
            log(f"  Requests: {_req}")
        time.sleep(0.5)  # throttle ~2 req/sec to be polite
        url = f"{SP_HOST}{rel}"
        try:
            r = requests.get(url, headers=AUTH.hdrs(), timeout=30)
            if r.status_code == 429:
                w = int(r.headers.get("Retry-After", 5))
                log(f"  Rate limit, wait {w}s")
                time.sleep(w)
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
                return {"_st": "xml"}
        except Exception as e:
            if a == retries - 1:
                log(f"  SPO err: {e}")
                return None
            time.sleep(2 ** a)
    return None

def check_inheritance(item: Dict) -> Dict:
    """Check HasUniqueRoleAssignments for a single item."""
    srv_rel = item.get("server_relative", f"{SITE_REL}/Shared Documents/{item['path']}")
    # Strip leading /sites/HTTHQ from path if present in item path
    rel_path = srv_rel.replace(SITE_REL, "")
    enc = urllib.parse.quote(rel_path)
    
    if item["type"] == "folder":
        api = f"{SITE_REL}/_api/web/GetFolderByServerRelativeUrl('{enc}')/ListItemAllFields/HasUniqueRoleAssignments"
    else:
        api = f"{SITE_REL}/_api/web/GetFileByServerRelativeUrl('{enc}')/ListItemAllFields/HasUniqueRoleAssignments"
    
    data = spo_get(api)
    if data and "d" in data:
        return {
            "has_unique": bool(data["d"].get("HasUniqueRoleAssignments", False)),
            "source_api": api[:100],
            "error": None
        }
    elif data and data.get("_st"):
        return {
            "has_unique": False,
            "source_api": api[:100],
            "error": f"REST {data['_st']}"
        }
    else:
        return {
            "has_unique": None,
            "source_api": api[:100],
            "error": "API failure"
        }

def main():
    if not PHASEA.exists():
        log("❌ Phase A output not found. Run Phase A first.")
        sys.exit(1)
    
    with open(PHASEA, "r") as f:
        items = json.load(f)
    
    log(f"Phase B starting: {len(items)} items to check")
    
    # Resume support
    done_ids = set()
    previous = []
    if PHASEB.exists():
        with open(PHASEB, "r") as f:
            previous = json.load(f)
        for it in previous:
            if it.get("has_unique") is not None:
                done_ids.add(it["id"])
        log(f"Resuming: {len(done_ids)} items already checked")
    
    results = []
    remaining = [i for i in items if i["id"] not in done_ids]
    
    for idx, item in enumerate(remaining, 1):
        result = check_inheritance(item)
        merged = {
            **item,
            "has_unique": result["has_unique"],
            "check_error": result.get("error")
        }
        results.append(merged)
        
        if idx % 100 == 0:
            unique_cnt = sum(1 for r in results if r.get("has_unique") == True)
            log(f"Progress: {idx}/{len(remaining)} checked, {unique_cnt} unique found")
            # incremental save
            tmp = PHASEB.with_suffix(".json.tmp")
            with open(tmp, "w") as f:
                json.dump(results + previous, f)
            tmp.replace(PHASEB)
    
    # Final save
    tmp = PHASEB.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(results + previous, f)
    tmp.replace(PHASEB)
    
    total_unique = sum(1 for r in results + previous if r.get("has_unique") == True)
    log(f"Phase B Complete! Total items: {len(items)}, Unique-permission: {total_unique}")
    
    # Quick analysis
    unique_items = [r for r in results + previous if r.get("has_unique") == True]
    if unique_items:
        log("Unique-permission items:")
        for it in unique_items[:20]:
            log(f"  🔒 {it['path'][:60]}")
        if len(unique_items) > 20:
            log(f"  ... and {len(unique_items) - 20} more")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted — progress saved to phaseB_inheritance.json")
    except Exception as e:
        log(f"FATAL: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
