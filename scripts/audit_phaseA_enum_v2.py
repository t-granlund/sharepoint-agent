#!/usr/bin/env python3
"""Phase A v2: Fast enumeration with incremental checkpoint saves."""
import json, os, sys, subprocess, requests

# Get fresh token from az CLI
def get_token():
    r = subprocess.run(
        ["az", "account", "get-access-token", "--resource", "https://graph.microsoft.com", "--output", "json"],
        capture_output=True, text=True, timeout=30
    )
    if r.returncode != 0:
        raise RuntimeError(f"az failed: {r.stderr[:300]}")
    return json.loads(r.stdout)["accessToken"]

TOKEN = get_token()
SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
GRAPH = "https://graph.microsoft.com/v1.0"
CHECKPOINT_EVERY = 500

def log(msg: str):
    print(msg, file=sys.stderr)

def graph_get(url):
    r = requests.get(url, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30)
    if r.status_code == 429:
        import time
        time.sleep(int(r.headers.get("Retry-After", 5)))
        r = requests.get(url, headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30)
    return r.json()

# Load checkpoint if exists
checkpoint_file = "audit_output/.phaseA_checkpoint.json"
flat = []
seen = set()
queue = []
drive_id = None

if os.path.exists(checkpoint_file):
    with open(checkpoint_file, "r") as f:
        cp = json.load(f)
    flat = cp.get("flat", [])
    seen = set(cp.get("seen", []))
    queue = [(q["id"], q["parent"]) for q in cp.get("queue", [])]
    drive_id = cp.get("drive_id")
    log(f"Resumed from checkpoint: {len(flat)} items, {len(queue)} queued")

if not flat or not drive_id:
    log("Resolving site...")
    site = graph_get(f"{GRAPH}/sites/{SITE_URL}")
    if "id" not in site:
        log(f"Error: {json.dumps(site, indent=2)}")
        sys.exit(1)
    site_id = site["id"]
    log(f"Site OK: {site_id}")

    drives = graph_get(f"{GRAPH}/sites/{site_id}/drives")
    drive_id = None
    for d in drives.get("value", []):
        if d["name"] in ("Documents", "Shared Documents"):
            drive_id = d["id"]
            log(f"Drive: {d['name']} ({drive_id[:30]}...)")
            break
    if not drive_id:
        log("No Documents drive")
        sys.exit(1)

    root = graph_get(f"{GRAPH}/drives/{drive_id}/root")
    queue = [(root["id"], "Shared Documents")]

def save_checkpoint():
    cp = {
        "flat": flat,
        "seen": list(seen),
        "queue": [{"id": q[0], "parent": q[1]} for q in queue],
        "drive_id": drive_id,
        "timestamp": flat[-1]["path"] if flat else ""
    }
    with open(checkpoint_file, "w") as f:
        json.dump(cp, f)

while queue:
    item_id, parent = queue.pop(0)
    if item_id in seen:
        continue
    seen.add(item_id)
    
    url = f"{GRAPH}/drives/{drive_id}/items/{item_id}/children?$top=200"
    while url:
        d = graph_get(url)
        if not d or "value" not in d:
            break
        for child in d.get("value", []):
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
                "child_count": child.get("folder", {}).get("childCount", 0) if isf else 0,
                "web_url": child.get("webUrl", ""),
            })
            if isf:
                queue.append((cid, cpath))
        url = d.get("@odata.nextLink")
    
    if len(flat) % CHECKPOINT_EVERY == 0:
        save_checkpoint()
        log(f"  Enumerated {len(flat)} items... | Queue: {len(queue)}")

# Final save
if os.path.exists(checkpoint_file):
    os.remove(checkpoint_file)

with open("audit_output/phaseA_enumeration.json", "w") as f:
    json.dump(flat, f)

# Also write a human-readable summary
log(f"Total: {len(flat)} items")
folders = [x for x in flat if x["type"] == "folder"]
files = [x for x in flat if x["type"] == "file"]
log(f"  Folders: {len(folders)}")
log(f"  Files: {len(files)}")

# Depth analysis
depths = {}
for item in flat:
    depth = item["path"].count("/")
    depths[depth] = depths.get(depth, 0) + 1
    
log("Depth distribution:")
for depth in sorted(depths.keys())[:5]:
    log(f"  Depth {depth}: {depths[depth]} items")

# Show deepest folders
deepest_folders = sorted(folders, key=lambda x: x["path"].count("/"), reverse=True)[:5]
log("Deepest folders:")
for f in deepest_folders:
    log(f"  {f['path'][:80]} ({f['path'].count('/')} levels)")

log(f"Saved to audit_output/phaseA_enumeration.json")
