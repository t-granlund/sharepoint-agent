#!/usr/bin/env python3
"""
Simple Folder Permission Audit using Microsoft Graph API only.

This script enumerates folders in a SharePoint document library and checks
their permission inheritance status using ONLY Microsoft Graph API.

Usage:
    python audit_folders_simple.py

Output:
    CSV file with folder permissions audit results.
"""

from azure.identity import DeviceCodeCredential
import requests
import csv
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

# =============================================================================
# CONFIGURATION
# =============================================================================

TENANT_ID = "0c0e35dc-188a-4eb3-b8ba-61752154b407"
CLIENT_ID = "e4846a2a-c399-4d3a-bcb5-c66ac214ec23"
SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
OUTPUT_DIR = "./audit_output"

# Graph API base URL
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class FolderAuditRecord:
    """Represents a folder's audit information."""
    folder_path: str
    folder_name: str
    has_unique_permissions: bool
    permission_count: int
    web_url: str


# =============================================================================
# AUTHENTICATION
# =============================================================================

def authenticate() -> str:
    """
    Authenticate using Azure device code flow.
    
    Returns:
        Access token for Microsoft Graph API
    """
    print("🔐 Initializing authentication...")
    
    # Create a log file to capture device code
    device_code_file = os.path.join(OUTPUT_DIR, "device_code.txt")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Custom callback to capture device code
    # The callback receives: (verification_uri, user_code, expires_on)
    def custom_callback(verification_uri, user_code, expires_on):
        prompt = f"""
🔐 DEVICE CODE AUTHENTICATION REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📱 To sign in, use a web browser to open the page:
   {verification_uri}

🔢 Enter the following code: {user_code}

⏰ Code expires at: {expires_on}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        # Write to file immediately
        with open(device_code_file, "w") as f:
            f.write(prompt)
        # Also print to stdout
        print(prompt)
        print(f"\n📄 Device code also saved to: {device_code_file}")
    
    credential = DeviceCodeCredential(
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        prompt_callback=custom_callback
    )
    
    # Request Graph scope - this will prompt user with device code
    token = credential.get_token("https://graph.microsoft.com/.default")
    print("✅ Authentication successful!\n")
    return token.token


def get_headers(token: str) -> Dict[str, str]:
    """Get standard headers for Graph API requests."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


# =============================================================================
# GRAPH API OPERATIONS
# =============================================================================

def make_graph_request(url: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """
    Make a GET request to Graph API with error handling.
    
    Args:
        url: Full Graph API URL
        headers: Request headers with authorization
        
    Returns:
        JSON response as dict, or None on error
    """
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ API Error: {e}")
        return None


def get_site(token: str) -> Optional[str]:
    """
    Get SharePoint site ID from URL.
    
    Args:
        token: Access token
        
    Returns:
        Site ID string, or None on error
    """
    print(f"📍 Looking up site: {SITE_URL}")
    url = f"{GRAPH_API_BASE}/sites/{SITE_URL}"
    
    data = make_graph_request(url, get_headers(token))
    if data and "id" in data:
        site_id = data["id"]
        print(f"✅ Found site ID: {site_id}")
        return site_id
    
    print("❌ Failed to retrieve site information")
    return None


def get_default_drive(token: str, site_id: str) -> Optional[str]:
    """
    Get the document library (drive) ID for a site.
    Looks for drive named 'Documents'.
    
    Args:
        token: Access token
        site_id: Site ID
        
    Returns:
        Drive ID string, or None on error
    """
    print("📂 Retrieving document library...")
    url = f"{GRAPH_API_BASE}/sites/{site_id}/drives"
    
    data = make_graph_request(url, get_headers(token))
    if data and "value" in data and len(data["value"]) > 0:
        # Look for drive named 'Documents'
        available_drives = [d.get("name", "Unknown") for d in data["value"]]
        print(f"   Available drives: {available_drives}")
        
        for drive in data["value"]:
            drive_name = drive.get("name", "Unknown")
            if drive_name == "Documents":
                drive_id = drive["id"]
                print(f"✅ Found drive: '{drive_name}' (ID: {drive_id})")
                return drive_id
        
        print("❌ Drive 'Documents' not found")
        print(f"   Available drives: {available_drives}")
        return None
    
    print("❌ No drives found for this site")
    return None


def get_folder_permissions(token: str, drive_id: str, item_id: str) -> tuple[bool, int]:
    """
    Check if a folder has unique permissions and count them.
    
    Args:
        token: Access token
        drive_id: Drive ID
        item_id: Folder/item ID
        
    Returns:
        Tuple of (has_unique_permissions, permission_count)
    """
    url = f"{GRAPH_API_BASE}/drives/{drive_id}/items/{item_id}/permissions"
    
    data = make_graph_request(url, get_headers(token))
    if not data or "value" not in data:
        # If we can't get permissions, assume inherited and 0 count
        return False, 0
    
    permissions = data["value"]
    permission_count = len(permissions)
    
    # Check if any permission has inheritedFrom field
    # If ALL permissions have inheritedFrom, permissions are inherited
    # If ANY permission lacks inheritedFrom, it has unique permissions
    has_inherited = any(
        "inheritedFrom" in perm and perm["inheritedFrom"]
        for perm in permissions
    )
    
    has_unique = not has_inherited or any(
        "inheritedFrom" not in perm or not perm.get("inheritedFrom")
        for perm in permissions
    )
    
    return has_unique, permission_count


def get_item_children(token: str, drive_id: str, item_id: str) -> List[Dict[str, Any]]:
    """
    Get child items (files and folders) of a drive item.
    
    Args:
        token: Access token
        drive_id: Drive ID
        item_id: Item ID (use 'root' for root)
        
    Returns:
        List of child items
    """
    url = f"{GRAPH_API_BASE}/drives/{drive_id}/items/{item_id}/children"
    
    data = make_graph_request(url, get_headers(token))
    if data and "value" in data:
        return data["value"]
    return []


def enumerate_folders_recursive(
    token: str,
    drive_id: str,
    item_id: str,
    current_path: str,
    records: List[FolderAuditRecord]
) -> None:
    """
    Recursively enumerate folders and collect permission data.
    
    Args:
        token: Access token
        drive_id: Drive ID
        item_id: Current folder item ID
        current_path: Current folder path for display
        records: List to append audit records to
    """
    children = get_item_children(token, drive_id, item_id)
    
    for child in children:
        # Skip files - we only care about folders
        if child.get("folder") is None:
            continue
        
        folder_name = child.get("name", "Unknown")
        folder_id = child["id"]
        web_url = child.get("webUrl", "")
        
        # Build the full path
        full_path = f"{current_path}/{folder_name}" if current_path else folder_name
        
        print(f"  📁 Processing: {full_path}")
        
        # Check permissions for this folder
        has_unique, perm_count = get_folder_permissions(token, drive_id, folder_id)
        
        # Create audit record
        record = FolderAuditRecord(
            folder_path=full_path,
            folder_name=folder_name,
            has_unique_permissions=has_unique,
            permission_count=perm_count,
            web_url=web_url
        )
        records.append(record)
        
        # Recursively process subfolders
        enumerate_folders_recursive(
            token, drive_id, folder_id, full_path, records
        )


def enumerate_all_folders(token: str, drive_id: str) -> List[FolderAuditRecord]:
    """
    Enumerate all folders in a drive and collect permission information.
    
    Args:
        token: Access token
        drive_id: Drive ID
        
    Returns:
        List of folder audit records
    """
    records: List[FolderAuditRecord] = []
    
    print("\n🔍 Starting folder enumeration...")
    print("=" * 60)
    
    # Start with root children (root itself typically has inherited permissions)
    # First, let's add the root folder info
    root_url = f"{GRAPH_API_BASE}/drives/{drive_id}/root"
    root_data = make_graph_request(root_url, get_headers(token))
    
    if root_data:
        root_id = root_data["id"]
        root_name = root_data.get("name", "Root")
        root_web_url = root_data.get("webUrl", "")
        
        print(f"📁 Processing: {root_name} (Root)")
        
        has_unique, perm_count = get_folder_permissions(token, drive_id, root_id)
        
        records.append(FolderAuditRecord(
            folder_path="/",
            folder_name=root_name,
            has_unique_permissions=has_unique,
            permission_count=perm_count,
            web_url=root_web_url
        ))
        
        # Now enumerate all children recursively
        enumerate_folders_recursive(token, drive_id, "root", "", records)
    
    print("=" * 60)
    print(f"✅ Found {len(records)} folders\n")
    
    return records


# =============================================================================
# CSV EXPORT
# =============================================================================

def export_to_csv(records: List[FolderAuditRecord], output_path: str) -> None:
    """
    Export audit records to CSV file.
    
    Args:
        records: List of folder audit records
        output_path: Path to output CSV file
    """
    fieldnames = [
        "folder_path",
        "folder_name", 
        "has_unique_permissions",
        "permission_count",
        "web_url"
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for record in records:
            writer.writerow({
                "folder_path": record.folder_path,
                "folder_name": record.folder_name,
                "has_unique_permissions": record.has_unique_permissions,
                "permission_count": record.permission_count,
                "web_url": record.web_url
            })
    
    print(f"💾 Exported {len(records)} records to: {output_path}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Main entry point for the folder audit script."""
    print("=" * 60)
    print("📊 SharePoint Folder Permission Audit (Graph API Only)")
    print("=" * 60)
    print()
    
    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Step 1: Authenticate
    token = authenticate()
    
    # Step 2: Get site
    site_id = get_site(token)
    if not site_id:
        print("❌ Cannot proceed without site ID. Exiting.")
        return 1
    
    # Step 3: Get drive (document library)
    drive_id = get_default_drive(token, site_id)
    if not drive_id:
        print("❌ Cannot proceed without drive ID. Exiting.")
        return 1
    
    # Step 4: Enumerate all folders
    records = enumerate_all_folders(token, drive_id)
    
    if not records:
        print("⚠️  No folders found or error occurred during enumeration.")
        return 1
    
    # Step 5: Export to CSV
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"folder_audit_{timestamp}.csv")
    export_to_csv(records, output_file)
    
    # Summary
    unique_count = sum(1 for r in records if r.has_unique_permissions)
    inherited_count = len(records) - unique_count
    
    print()
    print("=" * 60)
    print("📈 AUDIT SUMMARY")
    print("=" * 60)
    print(f"Total folders audited:    {len(records)}")
    print(f"Folders with unique permissions:     {unique_count}")
    print(f"Folders with inherited permissions:  {inherited_count}")
    print()
    print(f"Output file: {output_file}")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    exit(main())
