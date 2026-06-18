#!/usr/bin/env python3
"""Phase A: durable Graph enumeration for HTTHQ Shared Documents."""
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

TOKEN = os.environ["GRAPH_TOKEN"]
SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
GRAPH = "https://graph.microsoft.com/v1.0"
OUTPUT_DIR = Path("audit_output")
FINAL_PATH = OUTPUT_DIR / "phaseA_enumeration.json"
CHECKPOINT_PATH = OUTPUT_DIR / "phaseA_enumeration.checkpoint.json"

OUTPUT_DIR.mkdir(exist_ok=True)


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def atomic_json_write(path: Path, payload: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    tmp.replace(path)


def graph_get(url: str, retries: int = 7) -> Dict[str, Any]:
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {TOKEN}"},
                timeout=45,
            )

            if response.status_code in (429, 500, 502, 503, 504):
                retry_after = response.headers.get("Retry-After")
                wait = int(retry_after) if retry_after and retry_after.isdigit() else min(60, 2**attempt)
                log(f"Graph {response.status_code}; retry {attempt}/{retries} after {wait}s")
                time.sleep(wait)
                continue

            response.raise_for_status()
            return response.json()
        except Exception as exc:
            if attempt == retries:
                raise RuntimeError(f"Graph request failed after {retries} attempts: {url}: {exc}") from exc
            wait = min(60, 2**attempt)
            log(f"Graph exception; retry {attempt}/{retries} after {wait}s: {exc}")
            time.sleep(wait)

    raise RuntimeError(f"Graph request failed unexpectedly: {url}")


def load_checkpoint() -> Tuple[List[Dict[str, Any]], List[Tuple[str, str]], set]:
    if not CHECKPOINT_PATH.exists():
        return [], [], set()

    with open(CHECKPOINT_PATH, "r", encoding="utf-8") as f:
        checkpoint = json.load(f)

    flat = checkpoint.get("flat", [])
    queue = [tuple(x) for x in checkpoint.get("queue", [])]
    seen = set(checkpoint.get("seen", []))
    log(f"Resuming Phase A checkpoint: {len(flat)} items, {len(queue)} queued folders, {len(seen)} seen folders")
    return flat, queue, seen


def save_checkpoint(flat: List[Dict[str, Any]], queue: List[Tuple[str, str]], seen: set) -> None:
    atomic_json_write(
        CHECKPOINT_PATH,
        {
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "flat": flat,
            "queue": queue,
            "seen": sorted(seen),
        },
    )


def resolve_drive() -> Tuple[str, str]:
    log("Resolving site...")
    site = graph_get(f"{GRAPH}/sites/{SITE_URL}")
    if "id" not in site:
        raise RuntimeError(f"Site resolution failed: {json.dumps(site, indent=2)}")

    site_id = site["id"]
    log(f"Site OK: {site_id}")

    drives = graph_get(f"{GRAPH}/sites/{site_id}/drives")
    for drive in drives.get("value", []):
        if drive.get("name") in ("Documents", "Shared Documents"):
            drive_id = drive["id"]
            log(f"Drive: {drive.get('name')} ({drive_id[:30]}...)")
            return site_id, drive_id

    raise RuntimeError("No Documents / Shared Documents drive found")


def child_record(child: Dict[str, Any], parent: str) -> Dict[str, Any]:
    name = child.get("name", "")
    path = f"{parent}/{name}" if parent else name
    is_folder = "folder" in child
    return {
        "id": child["id"],
        "name": name,
        "path": path,
        "type": "folder" if is_folder else "file",
        "parent_path": parent,
        "size": child.get("size", 0),
        "created": child.get("createdDateTime", ""),
        "modified": child.get("lastModifiedDateTime", ""),
        "created_by": child.get("createdBy", {}).get("user", {}).get("displayName", ""),
        "modified_by": child.get("lastModifiedBy", {}).get("user", {}).get("displayName", ""),
        "child_count": child.get("folder", {}).get("childCount", 0) if is_folder else 0,
        "web_url": child.get("webUrl", ""),
    }


def main() -> None:
    _, drive_id = resolve_drive()

    flat, queue, seen = load_checkpoint()
    if not queue and not flat:
        root = graph_get(f"{GRAPH}/drives/{drive_id}/root")
        queue = [(root["id"], "Shared Documents")]

    last_checkpoint_count = len(flat)

    while queue:
        item_id, parent = queue.pop(0)
        if item_id in seen:
            continue
        seen.add(item_id)

        url = f"{GRAPH}/drives/{drive_id}/items/{item_id}/children?$top=200"
        while url:
            page = graph_get(url)
            for child in page.get("value", []):
                record = child_record(child, parent)
                flat.append(record)
                if record["type"] == "folder":
                    queue.append((record["id"], record["path"]))
            url = page.get("@odata.nextLink")

        if len(flat) - last_checkpoint_count >= 1000:
            save_checkpoint(flat, queue, seen)
            last_checkpoint_count = len(flat)
            log(f"  Checkpoint: {len(flat)} items, {len(queue)} folders queued")

    log(f"Total: {len(flat)} items")
    atomic_json_write(FINAL_PATH, flat)
    if CHECKPOINT_PATH.exists():
        CHECKPOINT_PATH.unlink()
    print(f"Saved to {FINAL_PATH}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted — checkpoint retained if available")
        raise
    except Exception as exc:
        log(f"FATAL: {exc}")
        raise
