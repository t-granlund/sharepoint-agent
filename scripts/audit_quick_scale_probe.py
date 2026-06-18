#!/usr/bin/env python3
"""
Quick scale probe: How many items in each top-level folder?
Uses Graph API with $top=200 and nextLink to count per folder.
Completes in ~30 seconds. No full recursion needed.
"""
import subprocess, json, requests, sys

TOKEN = json.loads(subprocess.run(
    ["az","account","get-access-token","--resource","https://graph.microsoft.com","--output","json"],
    capture_output=True, text=True, timeout=30
).stdout)["accessToken"]

GRAPH = "https://graph.microsoft.com/v1.0"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def graph_get(url):
    r = requests.get(url, headers=HEADERS, timeout=30)
    if r.status_code == 429:
        import time
        time.sleep(int(r.headers.get("Retry-After", 2)))
        r = requests.get(url, headers=HEADERS, timeout=30)
    if r.status_code != 200:
        return {"error": r.status_code, "text": r.text[:200]}
    return r.json()


print("🔍 Probing HTTHQ Shared Documents scale...")
print("=" * 60)

site = graph_get(f"{GRAPH}/sites/example-organization.sharepoint.com:/sites/HTTHQ")
site_id = site.get("id", "")
drives = graph_get(f"{GRAPH}/sites/{site_id}/drives")
drive_id = [d for d in drives.get("value", []) if d["name"] in ("Documents", "Shared Documents")][0]["id"]

root = graph_get(f"{GRAPH}/drives/{drive_id}/root")
drive_type = root.get("name", "Documents")

# Get root children (top-level items)
children_url = f"{GRAPH}/drives/{drive_id}/root/children?$top=200"
all_root = []
while children_url:
    data = graph_get(children_url)
    all_root.extend(data.get("value", []))
    children_url = data.get("@odata.nextLink")

top_folders = [i for i in all_root if "folder" in i]
top_files = [i for i in all_root if "file" in i]

print(f"📂 Drive: {drive_type}")
print(f"├─ Top-level folders: {len(top_folders)}")
print(f"└─ Top-level files:   {len(top_files)}")
print()

# Per-folder diagnostics
results = []
for folder in top_folders:
    fid = folder["id"]
    fname = folder["name"]
    reported_count = folder.get("folder", {}).get("childCount", 0)
    
    print(f"📁 {fname} (reported: {reported_count} children)")
    
    # Count immediate children by type
    url = f"{GRAPH}/drives/{drive_id}/items/{fid}/children?$top=200"
    all_children = []
    while url:
        data = graph_get(url)
        if "value" not in data:
            break
        all_children.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    
    subfolders = [c for c in all_children if "folder" in c]
    files = [c for c in all_children if "file" in c]
    
    # Probe one level deeper: count subfolder children
    total_deep_count = 0
    deepest_level = 1  # starts at level 1 (under root)
    
    for sf in subfolders:
        sf_id = sf["id"]
        sf_name = sf["name"]
        sf_fcount = sf.get("folder", {}).get("childCount", 0)
        
        # If subfolder has children, do a quick probe
        if sf_fcount > 0:
            deep_url = f"{GRAPH}/drives/{drive_id}/items/{sf_id}/children?$top=200"
            deep_items = []
            while deep_url:
                ddata = graph_get(deep_url)
                if "value" not in ddata:
                    break
                deep_items.extend(ddata.get("value", []))
                deep_url = ddata.get("@odata.nextLink")
            total_deep_count += len(deep_items)
            if len(deep_items) > 0:
                deepest_level = max(deepest_level, 2)
                # Check if any are sub-sub-folders
                sub_subs = [d for d in deep_items if "folder" in d]
                if sub_subs:
                    deepest_level = max(deepest_level, 3)
    
    total_estimated = len(all_children) + total_deep_count
    
    print(f"   └─ Immediate: {len(files)} files, {len(subfolders)} subfolders")
    print(f"   └─ Deep count: ~{total_estimated} total items (est. depth {deepest_level}+)")
    
    results.append({
        "name": fname,
        "reported": reported_count,
        "immediate_files": len(files),
        "immediate_subfolders": len(subfolders),
        "deep_estimate": total_estimated,
        "depth": deepest_level,
    })
    print()

# Summary table
print("=" * 60)
print("📊 SUMMARY TABLE")
print("=" * 60)
print(f"{'Folder':<35} {'Immed.Files':>12} {'Subfolders':>10} {'Deep Est.':>12} {'Depth':>6}")
print("-" * 75)
total_files = 0
total_est = 0
for r in results:
    print(f"{r['name']:<35} {r['immediate_files']:>12} {r['immediate_subfolders']:>10} {r['deep_estimate']:>12} {r['depth']:>6}")
    total_files += r['immediate_files']
    total_est += r['deep_estimate']
print("-" * 75)
print(f"{'TOTAL':<35} {total_files:>12} {'':>10} {total_est:>12}")
print(f"\n📈 Estimated total library size: ~{total_est:,} items (up to 3+ levels deep)")
