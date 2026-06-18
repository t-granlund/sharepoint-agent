#!/usr/bin/env python3
"""
HTTHQ Shallow Audit — Top 2 layers only
Loads existing checkpoint, checks only depth <= 2 folders via Graph permissions.
"""
import os, sys, csv, json, time, subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import requests

SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
CKPT = Path("./audit_output/htthq_local_checkpoint.json")
OUT_DIR = Path("./audit_output")
OUT_DIR.mkdir(exist_ok=True)
TS = datetime.now().strftime("%Y%m%d_%H%M%S")
log_path = OUT_DIR / f"shallow_{TS}.log"
TEMP_CKPT = OUT_DIR / "shallow_resume.json"

_tk_cache = {"tok": None, "exp": 0}

def get_tok() -> str:
    """Fetch and cache AZ token (refreshes every 4 minutes)."""
    if time.time() < _tk_cache["exp"]:
        return _tk_cache["tok"]
    out = subprocess.run(
        ["az","account","get-access-token","--resource","https://graph.microsoft.com","--output","json"],
        capture_output=True, text=True, timeout=30
    ).stdout
    tok = json.loads(out)["accessToken"]
    _tk_cache["tok"] = tok
    _tk_cache["exp"] = time.time() + 240
    return tok

def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    with open(log_path, "a") as f:
        f.write(line + "\n")

def gcall(url: str, timeout: int = 25, retries: int = 3) -> Optional[requests.Response]:
    """Graph GET with cached token + retry."""
    for attempt in range(retries):
        try:
            r = requests.get(url, headers={"Authorization": f"Bearer {get_tok()}"}, timeout=timeout)
            if r.status_code == 429:
                time.sleep(int(r.headers.get("Retry-After", 5)))
                continue
            return r
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1 << attempt)
                continue
            log(f"  ERROR: {url} — {type(e).__name__}: {e}")
    return None

def load_flat() -> List[Dict]:
    if not CKPT.exists():
        raise FileNotFoundError(f"Checkpoint not found: {CKPT}")
    with open(CKPT, "r") as f:
        data = json.load(f)
    log(f"Loaded checkpoint: {len(data['flat']):,} items (Phase A complete)")
    return data["flat"]

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
            u = ident.get("user", {})
            g = ident.get("group", {})
            if u:
                targets.append((u.get("displayName",""), u.get("email",""), "user"))
            if g:
                targets.append((g.get("displayName",""), g.get("email",""), "group"))
        for name, email, ptype in targets:
            item["permissions"].append({
                "item_id": item["id"], "item_path": item["path"], "item_type": "folder",
                "principal_id": p.get("id",""), "principal_name": name, "principal_type": ptype,
                "login_name": email or name, "role_name": ",".join(p.get("roles",[])),
                "inherited": bool(p.get("inheritedFrom")), "is_external": is_ext(email or name),
            })

def audit():
    flat = load_flat()

    # Scope: depth 1 and 2 folders only
    depth_1_2 = []
    for item in flat:
        if item["type"] != "folder":
            item["has_unique"] = False
            continue
        depth = item["path"].count("/")
        if depth in (1, 2):
            depth_1_2.append(item)
        else:
            item["has_unique"] = False
            item["_note"] = f"Skipped (depth={depth})"

    # Resume
    done_ids = set()
    if TEMP_CKPT.exists():
        with open(TEMP_CKPT) as f:
            done_ids = set(json.load(f).get("done", []))
        log(f"Resuming: {len(done_ids):,} folders already checked")

    to_check = [i for i in depth_1_2 if i["id"] not in done_ids]
    log(f"Folders to check: {len(to_check):,} (depth 1 and 2)")

    drive_id = next((i["drive_id"] for i in flat if "drive_id" in i), None)
    if not drive_id:
        raise RuntimeError("No drive_id in checkpoint")

    t0 = time.time()
    calls = 0
    timeouts = 0

    try:
        for idx, item in enumerate(to_check, 1):
            url = f"{GRAPH_BASE}/drives/{drive_id}/items/{item['id']}/permissions"
            calls += 1
            r = gcall(url)

            if r is None:
                item["has_unique"] = False
                item["_timeout"] = True
                timeouts += 1
            elif r.status_code == 200:
                perms = r.json().get("value", [])
                item["has_unique"] = infer_unique(perms)
                if item["has_unique"]:
                    parse_perms(item, perms)
            else:
                item["has_unique"] = False
                item["_error"] = r.status_code

            done_ids.add(item["id"])

            if idx % 500 == 0:
                with open(TEMP_CKPT, "w") as f:
                    json.dump({"done": list(done_ids), "ts": datetime.now().isoformat()}, f)
                elapsed = time.time() - t0
                rate = idx / elapsed if elapsed > 0 else 0
                eta = (len(to_check) - idx) / rate / 60 if rate > 0 else 0
                log(f"  [{idx:,}/{len(to_check):,}] {rate:.1f}/sec | ETA: {eta:.1f}m | timeouts: {timeouts}")

    except KeyboardInterrupt:
        log("INTERRUPTED — saving resume state...")
        with open(TEMP_CKPT, "w") as f:
            json.dump({"done": list(done_ids)}, f)
        return

    elapsed = time.time() - t0
    total_unique = sum(1 for i in flat if i.get("has_unique") == True)
    log(f"Phase B done: {total_unique} unique-permission folders | {calls} calls | {timeouts} timeouts | {elapsed/60:.1f} min")

    _reports(flat)

def _reports(flat):
    log("=" * 40 + " Generating Reports " + "=" * 40)
    folders = [i for i in flat if i["type"] == "folder"]
    files = [i for i in flat if i["type"] == "file"]
    unique_items = [i for i in flat if i.get("has_unique") == True]
    perms = []
    for item in flat:
        perms.extend(item.get("permissions", []))

    flat_csv = OUT_DIR / f"htthq_shallow_flat_{TS}.csv"
    with open(flat_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id","name","path","type","depth","child_count","has_unique","web_url"])
        for item in flat:
            depth = item["path"].count("/")
            w.writerow([item["id"], item["name"], item["path"], item["type"],
                       depth, item["child_count"], item.get("has_unique",""), item["web_url"]])
    log(f"Flat CSV: {flat_csv.name}")

    perms_csv = OUT_DIR / f"htthq_shallow_perms_{TS}.csv"
    with open(perms_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["item_path","principal_name","principal_type","login_name","role_name","inherited","is_external"])
        for r in perms:
            w.writerow([r["item_path"], r["principal_name"], r["principal_type"],
                       r["login_name"], r["role_name"], r["inherited"], r["is_external"]])
    log(f"Perms CSV: {perms_csv.name}")

    md = OUT_DIR / f"htthq_shallow_analysis_{TS}.md"
    with open(md, "w", encoding="utf-8") as f:
        f.write("# HTTHQ Shared Documents — Shallow Audit (Depth 1–2)\n\n")
        f.write(f"**Date:** {datetime.now().isoformat()}\n")
        f.write(f"**Scope:** Folders at depth 1 and 2 only\n")
        f.write(f"**Total items:** {len(flat):,} | **Folders:** {len(folders):,} | **Files:** {len(files):,}\n")
        f.write(f"**Unique-permission folders (shallow):** {len(unique_items):,} 🔒\n")
        f.write(f"**Total role assignments:** {len(perms):,}\n")

        if unique_items:
            f.write("\n## 🔒 Unique-Permission Folders\n\n")
            for it in sorted(unique_items, key=lambda x: x["path"]):
                f.write(f"- **{it['path']}** — {it['child_count']} children\n")

        ext = [r for r in perms if r.get("is_external")]
        if ext:
            f.write(f"\n## 🟡 External Permissions ({len(ext)} entries)\n\n")
            for r in ext[:50]:
                note = "👤" if r["principal_type"] == "user" else "👥"
                f.write(f"- {note} **{r['principal_name']}** on `/{r['item_path']}` → {r['role_name']}\n")
            if len(ext) > 50:
                f.write(f"\n... and {len(ext)-50} more\n")

        f.write("\n---\n*By Richard the Code Puppy 🐶*\n")
    log(f"Analysis MD: {md.name}")

    summary = {
        "total_items": len(flat), "folders": len(folders), "files": len(files),
        "unique_shallow": len(unique_items), "perms": len(perms),
        "reports": {"flat_csv": str(flat_csv), "perms_csv": str(perms_csv), "analysis_md": str(md)}
    }
    with open(OUT_DIR / f"htthq_shallow_summary_{TS}.json", "w") as f:
        json.dump(summary, f, indent=2)

if __name__ == "__main__":
    try:
        audit()
    except KeyboardInterrupt:
        log("Interrupted by user. Re-run to resume.")
        sys.exit(0)
