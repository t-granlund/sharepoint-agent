#!/usr/bin/env python3
"""
HTTHQ Shallow Audit — Batched Graph API
Checks depth 1-2 folders using batch API (20 requests per batch).
~500 batches for 11k folders = ~10-15 minutes.
"""
import os, sys, csv, json, time, subprocess, uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import requests

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
CKPT = Path("./audit_output/htthq_local_checkpoint.json")
OUT_DIR = Path("./audit_output")
OUT_DIR.mkdir(exist_ok=True)
TS = datetime.now().strftime("%Y%m%d_%H%M%S")
log_path = OUT_DIR / f"shallow_batch_{TS}.log"

tok_cache = {"tok": None, "exp": 0}

def get_tok() -> str:
    if time.time() < tok_cache["exp"]:
        return tok_cache["tok"]
    out = subprocess.run(
        ["az","account","get-access-token","--resource","https://graph.microsoft.com","--output","json"],
        capture_output=True, text=True, timeout=30
    ).stdout
    tok_cache["tok"] = json.loads(out)["accessToken"]
    tok_cache["exp"] = time.time() + 240
    return tok_cache["tok"]

def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(log_path, "a") as f:
        f.write(line + "\n")

def batch_call(requests_list: List[dict]) -> Optional[dict]:
    """Send a batch of up to 20 requests via Microsoft Graph batch endpoint."""
    url = f"{GRAPH_BASE}/$batch"
    payload = {"requests": requests_list}
    try:
        r = requests.post(url, json=payload,
                         headers={"Authorization": f"Bearer {get_tok()}", "Content-Type": "application/json"},
                         timeout=60)
        if r.status_code == 429:
            time.sleep(int(r.headers.get("Retry-After", 5)))
            # Retry once
            r = requests.post(url, json=payload,
                             headers={"Authorization": f"Bearer {get_tok()}", "Content-Type": "application/json"},
                             timeout=60)
        if r.status_code == 200:
            return r.json()
        log(f"  Batch failed: {r.status_code}")
        return None
    except Exception as e:
        log(f"  Batch error: {type(e).__name__}: {e}")
        return None

def is_ext(login: str) -> bool:
    l = (login or "").lower()
    return "#ext#" in l or ("@" in l and l.split("@")[-1] not in ("example-organization.com", "example-organization.onmicrosoft.com"))

def infer_unique(perms: List[dict]) -> bool:
    for p in perms:
        if not p.get("inheritedFrom"):
            return True
    return False

def parse_perms(item: Dict, raw_perms: List[dict]):
    for p in raw_perms:
        gt = p.get("grantedTo", {})
        user, group = gt.get("user"), gt.get("group")
        targets = []
        if user:
            targets.append((user.get("displayName",""), user.get("email",""), "user"))
        if group:
            targets.append((group.get("displayName",""), group.get("email",""), "group"))
        for ident in p.get("grantedToIdentities", []):
            u = ident.get("user", {}); g = ident.get("group", {})
            if u: targets.append((u.get("displayName",""), u.get("email",""), "user"))
            if g: targets.append((g.get("displayName",""), g.get("email",""), "group"))
        for name, email, ptype in targets:
            item["permissions"].append({
                "item_id": item["id"], "item_path": item["path"], "item_type": "folder",
                "principal_id": p.get("id",""), "principal_name": name, "principal_type": ptype,
                "login_name": email or name, "role_name": ",".join(p.get("roles",[])),
                "inherited": bool(p.get("inheritedFrom")), "is_external": is_ext(email or name),
            })

def audit():
    with open(CKPT, "r") as f:
        data = json.load(f)
    flat = data["flat"]
    log(f"Loaded: {len(flat):,} items")

    # Only depth 1 and 2 folders
    to_check = [i for i in flat if i["type"] == "folder" and i["path"].count("/") in (1, 2)]
    for i in flat:
        if i["type"] == "file": i["has_unique"] = False
        elif i["path"].count("/") > 2: i["has_unique"] = False; i["_note"] = "Skipped (deep)"

    log(f"Folders to check: {len(to_check):,} (depth 1-2)")
    drive_id = next(i["drive_id"] for i in flat if "drive_id" in i)

    # Process in batches of 20
    batch_size = 20
    total = len(to_check)
    t0 = time.time()

    for start in range(0, total, batch_size):
        batch_items = to_check[start:start+batch_size]
        requests_list = []
        for item in batch_items:
            req_id = item["id"]
            requests_list.append({
                "id": req_id,
                "method": "GET",
                "url": f"/drives/{drive_id}/items/{item['id']}/permissions"
            })

        result = batch_call(requests_list)

        if result and "responses" in result:
            for resp in result["responses"]:
                item_id = resp.get("id")
                item = next((i for i in batch_items if i["id"] == item_id), None)
                if not item:
                    continue
                status = resp.get("status", 0)
                body = resp.get("body", {})
                if status == 200:
                    perms = body.get("value", [])
                    item["has_unique"] = infer_unique(perms)
                    if item["has_unique"]:
                        parse_perms(item, perms)
                else:
                    item["has_unique"] = False
                    item["_error"] = status
        else:
            # Batch failed — mark all as unchecked to fallback
            for item in batch_items:
                item["has_unique"] = False
                item["_batch_fail"] = True

        if (start // batch_size + 1) % 25 == 0 or start + batch_size >= total:
            elapsed = time.time() - t0
            done = min(start + batch_size, total)
            rate = done / elapsed if elapsed > 0 else 0
            eta = (total - done) / rate / 60 if rate > 0 else 0
            log(f"  [{done:,}/{total:,}] {rate:.1f}/sec | ETA: {eta:.1f}m")

    elapsed = time.time() - t0
    total_unique = sum(1 for i in flat if i.get("has_unique") == True)
    log(f"Done: {total_unique} unique-perm folders in {elapsed/60:.1f} min")
    _reports(flat)

def _reports(flat):
    log("=" * 30 + " Reports " + "=" * 30)
    unique_items = [i for i in flat if i.get("has_unique") == True]
    perms = []
    for item in flat: perms.extend(item.get("permissions", []))

    flat_csv = OUT_DIR / f"htthq_shallow_flat_{TS}.csv"
    with open(flat_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id","name","path","type","depth","child_count","has_unique","web_url"])
        for item in flat:
            w.writerow([item["id"], item["name"], item["path"], item["type"],
                       item["path"].count("/"), item["child_count"], item.get("has_unique",""), item["web_url"]])
    log(f"flat CSV: {flat_csv.name}")

    perms_csv = OUT_DIR / f"htthq_shallow_perms_{TS}.csv"
    with open(perms_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["item_path","principal_name","principal_type","login_name","role_name","inherited","is_external"])
        for r in perms:
            w.writerow([r["item_path"], r["principal_name"], r["principal_type"],
                       r["login_name"], r["role_name"], r["inherited"], r["is_external"]])
    log(f"perms CSV: {perms_csv.name}")

    md = OUT_DIR / f"htthq_shallow_analysis_{TS}.md"
    with open(md, "w", encoding="utf-8") as f:
        f.write("# HTTHQ Shared Documents — Shallow Audit (Depth 1-2)\n\n")
        f.write(f"**Total items:** {len(flat):,}\n")
        f.write(f"**Unique-permission folders (shallow):** {len(unique_items):,} 🔒\n")
        if unique_items:
            f.write("\n## 🔒 Unique-Permission Folders\n\n")
            for it in sorted(unique_items, key=lambda x: x["path"]):
                f.write(f"- **{it['path']}** — {it['child_count']} children\n")
        ext = [r for r in perms if r.get("is_external")]
        if ext:
            f.write(f"\n## 🟡 External ({len(ext)} entries)\n")
        f.write("\n---\n*Richard the Code Puppy 🐶*\n")
    log(f"analysis MD: {md.name}")

if __name__ == "__main__":
    try:
        audit()
    except KeyboardInterrupt:
        log("Interrupted.")
