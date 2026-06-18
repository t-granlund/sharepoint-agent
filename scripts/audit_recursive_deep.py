#!/usr/bin/env python3
"""
Deep Recursive SharePoint Audit Script - HTTHQ Site

This script performs a comprehensive recursive audit of ALL folders and files
in the HTTHQ SharePoint site, capturing detailed metadata and permissions.

Features:
- Recursively traverses ALL folders and subfolders
- Captures folder metadata: path, name, file count, total size, subfolder count
- Captures folder permissions: unique vs inherited, external sharing status
- Captures file metadata: name, path, size, MIME type, dates, version count
- Builds complete hierarchical tree structure
- Outputs to JSON (hierarchical) and CSV (flat) formats

Authentication:
- Uses Azure CLI token (az account get-access-token)
- Falls back to environment variables if needed

Usage:
    python audit_recursive_deep.py
    python audit_recursive_deep.py --site-url "example-organization.sharepoint.com:/sites/HTTHQ"
    python audit_recursive_deep.py --output-dir "./deep_audit_output"

Output Files:
    - htthq_deep_audit_hierarchical_<timestamp>.json (tree structure)
    - htthq_deep_audit_flat_<timestamp>.csv (flat list of all items)
    - htthq_deep_audit_folders_<timestamp>.csv (folder summary)
    - htthq_deep_audit_files_<timestamp>.csv (file details)
"""

import os
import sys
import json
import csv
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict

import requests
from azure.identity import AzureCliCredential, DefaultAzureCredential


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
DEFAULT_OUTPUT_DIR = "./audit_output"
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class FileRecord:
    """Represents a file's audit information."""
    id: str
    name: str
    path: str
    parent_path: str
    size: int
    mime_type: str
    created_date: str
    modified_date: str
    last_modified_by: str
    created_by: str
    web_url: str
    version_count: int = 0
    has_unique_permissions: bool = False
    permission_count: int = 0
    sharing_status: str = "private"  # private, organization, external, anonymous


@dataclass
class FolderRecord:
    """Represents a folder's audit information."""
    id: str
    name: str
    path: str
    parent_path: str
    file_count: int = 0
    total_size_bytes: int = 0
    subfolder_count: int = 0
    created_date: str = ""
    modified_date: str = ""
    last_modified_by: str = ""
    created_by: str = ""
    web_url: str = ""
    has_unique_permissions: bool = False
    permission_count: int = 0
    sharing_status: str = "private"
    child_folder_ids: List[str] = field(default_factory=list)
    child_file_ids: List[str] = field(default_factory=list)


@dataclass
class TreeNode:
    """Represents a node in the hierarchical tree structure."""
    id: str
    name: str
    type: str  # 'folder' or 'file'
    path: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    children: List['TreeNode'] = field(default_factory=list)


@dataclass
class AuditSummary:
    """Summary of the entire audit."""
    audit_timestamp: str
    site_url: str
    total_folders: int = 0
    total_files: int = 0
    total_size_bytes: int = 0
    folders_with_unique_permissions: int = 0
    files_with_unique_permissions: int = 0
    external_sharing_count: int = 0
    anonymous_sharing_count: int = 0
    max_depth_reached: int = 0


# =============================================================================
# AUTHENTICATION
# =============================================================================

def authenticate_azure_cli() -> Optional[str]:
    """
    Authenticate using Azure CLI credential.
    
    Returns:
        Access token string, or None if authentication fails
    """
    print("🔐 Authenticating with Azure CLI...")
    
    try:
        # Try AzureCliCredential first
        credential = AzureCliCredential()
        token = credential.get_token("https://graph.microsoft.com/.default")
        print("✅ Azure CLI authentication successful!")
        print(f"   Token expires: {token.expires_on}")
        return token.token
    except Exception as e:
        print(f"⚠️  Azure CLI auth failed: {e}")
        
        # Fall back to DefaultAzureCredential
        try:
            print("🔄 Trying DefaultAzureCredential...")
            credential = DefaultAzureCredential(
                exclude_interactive_browser_credential=True,
                exclude_device_code_credential=True,
                exclude_shared_token_cache_credential=False,
            )
            token = credential.get_token("https://graph.microsoft.com/.default")
            print("✅ DefaultAzureCredential authentication successful!")
            return token.token
        except Exception as e2:
            print(f"❌ DefaultAzureCredential also failed: {e2}")
            return None


def get_headers(token: str) -> Dict[str, str]:
    """Get standard headers for Graph API requests."""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


# =============================================================================
# GRAPH API OPERATIONS
# =============================================================================

def make_graph_request(url: str, headers: Dict[str, str], params: Optional[Dict] = None) -> Optional[Dict[str, Any]]:
    """
    Make a GET request to Graph API with error handling.
    
    Args:
        url: Full Graph API URL
        headers: Request headers with authorization
        params: Optional query parameters
        
    Returns:
        JSON response as dict, or None on error
    """
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 429:
            # Rate limited - wait and retry once
            retry_after = int(response.headers.get("Retry-After", 5))
            print(f"⏳ Rate limited. Waiting {retry_after}s...")
            import time
            time.sleep(retry_after)
            response = requests.get(url, headers=headers, params=params, timeout=30)
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ API Error: {e}")
        return None


def get_site_id(token: str, site_url: str) -> Optional[str]:
    """
    Get SharePoint site ID from URL.
    
    Args:
        token: Access token
        site_url: SharePoint site URL
        
    Returns:
        Site ID string, or None on error
    """
    print(f"📍 Looking up site: {site_url}")
    
    url = f"{GRAPH_API_BASE}/sites/{site_url}"
    
    data = make_graph_request(url, get_headers(token))
    if data and "id" in data:
        site_id = data["id"]
        print(f"✅ Found site ID: {site_id}")
        return site_id
    
    print("❌ Failed to retrieve site information")
    return None


def get_document_drives(token: str, site_id: str) -> List[Dict[str, Any]]:
    """
    Get all document libraries (drives) for a site.
    
    Args:
        token: Access token
        site_id: Site ID
        
    Returns:
        List of drive dictionaries
    """
    print("📂 Retrieving document libraries...")
    
    url = f"{GRAPH_API_BASE}/sites/{site_id}/drives"
    
    data = make_graph_request(url, get_headers(token))
    if data and "value" in data:
        drives = data["value"]
        print(f"   Found {len(drives)} drive(s): {[d.get('name', 'Unknown') for d in drives]}")
        return drives
    
    print("❌ No drives found for this site")
    return []


def get_item_children_paginated(token: str, drive_id: str, item_id: str) -> List[Dict[str, Any]]:
    """
    Get all child items with pagination support.
    
    Args:
        token: Access token
        drive_id: Drive ID
        item_id: Item ID (use 'root' for root)
        
    Returns:
        List of all child items
    """
    items = []
    url = f"{GRAPH_API_BASE}/drives/{drive_id}/items/{item_id}/children"
    
    while url:
        data = make_graph_request(url, get_headers(token))
        if not data:
            break
        
        items.extend(data.get("value", []))
        
        # Check for next page
        url = data.get("@odata.nextLink")
    
    return items


def get_item_permissions(token: str, drive_id: str, item_id: str) -> Tuple[bool, int, str, List[Dict]]:
    """
    Get permissions for an item and analyze sharing status.
    
    Args:
        token: Access token
        drive_id: Drive ID
        item_id: Item ID
        
    Returns:
        Tuple of (has_unique_permissions, permission_count, sharing_status, permissions_list)
    """
    url = f"{GRAPH_API_BASE}/drives/{drive_id}/items/{item_id}/permissions"
    
    data = make_graph_request(url, get_headers(token))
    if not data or "value" not in data:
        return False, 0, "private", []
    
    permissions = data["value"]
    permission_count = len(permissions)
    
    # Check if permissions are inherited
    has_inherited = any(
        "inheritedFrom" in perm and perm["inheritedFrom"]
        for perm in permissions
    )
    
    has_unique = not has_inherited or any(
        "inheritedFrom" not in perm or not perm.get("inheritedFrom")
        for perm in permissions
    )
    
    # Analyze sharing status
    sharing_status = "private"
    for perm in permissions:
        # Check for anonymous links
        if perm.get("link", {}).get("scope") == "anonymous":
            sharing_status = "anonymous"
            break
        # Check for organization-wide links
        elif perm.get("link", {}).get("scope") == "organization":
            sharing_status = "organization"
        # Check for external users
        elif perm.get("grantedToIdentities") or perm.get("grantedTo", {}).get("user", {}).get("email", "").endswith(('.', '!')) == False:
            user_email = perm.get("grantedTo", {}).get("user", {}).get("email", "")
            if user_email and not user_email.endswith("@example-organization.com"):
                if sharing_status == "private":
                    sharing_status = "external"
    
    return has_unique, permission_count, sharing_status, permissions


def get_item_versions(token: str, drive_id: str, item_id: str) -> int:
    """
    Get version count for a file.
    
    Args:
        token: Access token
        drive_id: Drive ID
        item_id: Item ID
        
    Returns:
        Number of versions
    """
    url = f"{GRAPH_API_BASE}/drives/{drive_id}/items/{item_id}/versions"
    
    data = make_graph_request(url, get_headers(token))
    if data and "value" in data:
        return len(data["value"])
    return 0


def get_folder_metadata(token: str, drive_id: str, folder_id: str) -> Dict[str, Any]:
    """
    Get detailed metadata for a folder.
    
    Args:
        token: Access token
        drive_id: Drive ID
        folder_id: Folder ID
        
    Returns:
        Folder metadata dictionary
    """
    url = f"{GRAPH_API_BASE}/drives/{drive_id}/items/{folder_id}"
    
    return make_graph_request(url, get_headers(token)) or {}


def get_file_metadata(token: str, drive_id: str, file_id: str) -> Dict[str, Any]:
    """
    Get detailed metadata for a file.
    
    Args:
        token: Access token
        drive_id: Drive ID
        file_id: File ID
        
    Returns:
        File metadata dictionary
    """
    url = f"{GRAPH_API_BASE}/drives/{drive_id}/items/{file_id}"
    
    return make_graph_request(url, get_headers(token)) or {}


# =============================================================================
# RECURSIVE AUDIT FUNCTIONS
# =============================================================================

def process_item_recursive(
    token: str,
    drive_id: str,
    item: Dict[str, Any],
    parent_path: str,
    depth: int,
    folder_records: Dict[str, FolderRecord],
    file_records: Dict[str, FileRecord],
    tree_nodes: Dict[str, TreeNode],
    max_depth: List[int]
) -> None:
    """
    Recursively process an item (folder or file) and all its children.
    
    Args:
        token: Access token
        drive_id: Drive ID
        item: Item dictionary from Graph API
        parent_path: Path of parent folder
        depth: Current depth in tree
        folder_records: Dictionary to store folder records
        file_records: Dictionary to store file records
        tree_nodes: Dictionary to store tree nodes
        max_depth: List containing max depth reached (mutable)
    """
    # Track max depth
    max_depth[0] = max(max_depth[0], depth)
    
    item_id = item.get("id", "")
    item_name = item.get("name", "Unknown")
    current_path = f"{parent_path}/{item_name}" if parent_path else item_name
    
    # Get permissions info
    has_unique, perm_count, sharing_status, _ = get_item_permissions(token, drive_id, item_id)
    
    # Get creator/modifier info
    created_by = item.get("createdBy", {}).get("user", {}).get("displayName", "")
    modified_by = item.get("lastModifiedBy", {}).get("user", {}).get("displayName", "")
    created_date = item.get("createdDateTime", "")
    modified_date = item.get("lastModifiedDateTime", "")
    web_url = item.get("webUrl", "")
    
    # Check if folder or file
    if item.get("folder"):
        # It's a folder
        print(f"{'  ' * depth}📁 {item_name}")
        
        folder_record = FolderRecord(
            id=item_id,
            name=item_name,
            path=current_path,
            parent_path=parent_path,
            created_date=created_date,
            modified_date=modified_date,
            last_modified_by=modified_by,
            created_by=created_by,
            web_url=web_url,
            has_unique_permissions=has_unique,
            permission_count=perm_count,
            sharing_status=sharing_status
        )
        
        # Create tree node
        tree_node = TreeNode(
            id=item_id,
            name=item_name,
            type="folder",
            path=current_path,
            metadata={
                "created_date": created_date,
                "modified_date": modified_date,
                "has_unique_permissions": has_unique,
                "permission_count": perm_count,
                "sharing_status": sharing_status
            }
        )
        
        # Get children
        children = get_item_children_paginated(token, drive_id, item_id)
        
        child_folders = []
        child_files = []
        total_size = 0
        
        for child in children:
            child_id = child.get("id", "")
            
            if child.get("folder"):
                child_folders.append(child_id)
                # Recursively process subfolder
                process_item_recursive(
                    token, drive_id, child, current_path, depth + 1,
                    folder_records, file_records, tree_nodes, max_depth
                )
            else:
                # It's a file
                child_files.append(child_id)
                file_size = child.get("size", 0)
                total_size += file_size
                
                # Process file
                file_has_unique, file_perm_count, file_sharing, _ = get_item_permissions(token, drive_id, child_id)
                file_versions = get_item_versions(token, drive_id, child_id)
                
                file_record = FileRecord(
                    id=child_id,
                    name=child.get("name", "Unknown"),
                    path=f"{current_path}/{child.get('name', 'Unknown')}",
                    parent_path=current_path,
                    size=file_size,
                    mime_type=child.get("file", {}).get("mimeType", "application/octet-stream"),
                    created_date=child.get("createdDateTime", ""),
                    modified_date=child.get("lastModifiedDateTime", ""),
                    last_modified_by=child.get("lastModifiedBy", {}).get("user", {}).get("displayName", ""),
                    created_by=child.get("createdBy", {}).get("user", {}).get("displayName", ""),
                    web_url=child.get("webUrl", ""),
                    version_count=file_versions,
                    has_unique_permissions=file_has_unique,
                    permission_count=file_perm_count,
                    sharing_status=file_sharing
                )
                
                file_records[child_id] = file_record
                
                # Add file to tree
                file_node = TreeNode(
                    id=child_id,
                    name=child.get("name", "Unknown"),
                    type="file",
                    path=f"{current_path}/{child.get('name', 'Unknown')}",
                    metadata={
                        "size": file_size,
                        "mime_type": child.get("file", {}).get("mimeType", "application/octet-stream"),
                        "created_date": child.get("createdDateTime", ""),
                        "modified_date": child.get("lastModifiedDateTime", ""),
                        "version_count": file_versions,
                        "has_unique_permissions": file_has_unique,
                        "sharing_status": file_sharing
                    }
                )
                tree_node.children.append(file_node)
        
        # Update folder record with counts
        folder_record.subfolder_count = len(child_folders)
        folder_record.file_count = len(child_files)
        folder_record.total_size_bytes = total_size
        folder_record.child_folder_ids = child_folders
        folder_record.child_file_ids = child_files
        
        folder_records[item_id] = folder_record
        tree_nodes[item_id] = tree_node
        
    else:
        # It's a file at root level - process it
        print(f"{'  ' * depth}📄 {item_name}")
        
        file_size = item.get("size", 0)
        file_versions = get_item_versions(token, drive_id, item_id)
        
        file_record = FileRecord(
            id=item_id,
            name=item_name,
            path=current_path,
            parent_path=parent_path,
            size=file_size,
            mime_type=item.get("file", {}).get("mimeType", "application/octet-stream"),
            created_date=created_date,
            modified_date=modified_date,
            last_modified_by=modified_by,
            created_by=created_by,
            web_url=web_url,
            version_count=file_versions,
            has_unique_permissions=has_unique,
            permission_count=perm_count,
            sharing_status=sharing_status
        )
        
        file_records[item_id] = file_record


def run_deep_audit(token: str, drive_id: str, drive_name: str) -> Tuple[Dict[str, FolderRecord], Dict[str, FileRecord], AuditSummary]:
    """
    Run a deep recursive audit of a drive.
    
    Args:
        token: Access token
        drive_id: Drive ID
        drive_name: Drive name for reporting
        
    Returns:
        Tuple of (folder_records, file_records, summary)
    """
    print(f"\n🔍 Starting deep audit of drive: {drive_name}")
    print("=" * 80)
    
    folder_records: Dict[str, FolderRecord] = {}
    file_records: Dict[str, FileRecord] = {}
    tree_nodes: Dict[str, TreeNode] = {}
    max_depth = [0]
    
    # Start with root
    root_url = f"{GRAPH_API_BASE}/drives/{drive_id}/root"
    root_data = make_graph_request(root_url, get_headers(token))
    
    if root_data:
        # Process root and all children recursively
        process_item_recursive(
            token, drive_id, root_data, "", 0,
            folder_records, file_records, tree_nodes, max_depth
        )
    
    # Calculate summary
    total_size = sum(f.size for f in file_records.values())
    folders_unique = sum(1 for f in folder_records.values() if f.has_unique_permissions)
    files_unique = sum(1 for f in file_records.values() if f.has_unique_permissions)
    external_sharing = sum(1 for f in folder_records.values() if f.sharing_status in ["external", "anonymous"])
    external_sharing += sum(1 for f in file_records.values() if f.sharing_status in ["external", "anonymous"])
    anonymous_sharing = sum(1 for f in folder_records.values() if f.sharing_status == "anonymous")
    anonymous_sharing += sum(1 for f in file_records.values() if f.sharing_status == "anonymous")
    
    summary = AuditSummary(
        audit_timestamp=datetime.now().isoformat(),
        site_url=DEFAULT_SITE_URL,
        total_folders=len(folder_records),
        total_files=len(file_records),
        total_size_bytes=total_size,
        folders_with_unique_permissions=folders_unique,
        files_with_unique_permissions=files_unique,
        external_sharing_count=external_sharing,
        anonymous_sharing_count=anonymous_sharing,
        max_depth_reached=max_depth[0]
    )
    
    print("=" * 80)
    print(f"✅ Audit complete!")
    print(f"   Folders: {summary.total_folders}")
    print(f"   Files: {summary.total_files}")
    print(f"   Total Size: {format_bytes(summary.total_size_bytes)}")
    print(f"   Max Depth: {summary.max_depth_reached}")
    
    return folder_records, file_records, summary


def format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


# =============================================================================
# EXPORT FUNCTIONS
# =============================================================================

def export_to_hierarchical_json(
    folder_records: Dict[str, FolderRecord],
    file_records: Dict[str, FileRecord],
    summary: AuditSummary,
    output_path: str
) -> None:
    """
    Export audit data to hierarchical JSON.
    
    Args:
        folder_records: Dictionary of folder records
        file_records: Dictionary of file records
        summary: Audit summary
        output_path: Path to output file
    """
    # Build hierarchical tree
    tree = {
        "audit_summary": {
            "timestamp": summary.audit_timestamp,
            "site_url": summary.site_url,
            "total_folders": summary.total_folders,
            "total_files": summary.total_files,
            "total_size_bytes": summary.total_size_bytes,
            "total_size_formatted": format_bytes(summary.total_size_bytes),
            "folders_with_unique_permissions": summary.folders_with_unique_permissions,
            "files_with_unique_permissions": summary.files_with_unique_permissions,
            "external_sharing_count": summary.external_sharing_count,
            "anonymous_sharing_count": summary.anonymous_sharing_count,
            "max_depth_reached": summary.max_depth_reached
        },
        "tree": []
    }
    
    # Build folder hierarchy
    folder_by_path = {f.path: f for f in folder_records.values()}
    
    def build_tree(folder: FolderRecord) -> Dict:
        """Recursively build tree structure."""
        node = {
            "id": folder.id,
            "name": folder.name,
            "type": "folder",
            "path": folder.path,
            "metadata": {
                "file_count": folder.file_count,
                "subfolder_count": folder.subfolder_count,
                "total_size_bytes": folder.total_size_bytes,
                "total_size_formatted": format_bytes(folder.total_size_bytes),
                "created_date": folder.created_date,
                "modified_date": folder.modified_date,
                "created_by": folder.created_by,
                "last_modified_by": folder.last_modified_by,
                "has_unique_permissions": folder.has_unique_permissions,
                "permission_count": folder.permission_count,
                "sharing_status": folder.sharing_status,
                "web_url": folder.web_url
            },
            "children": []
        }
        
        # Add child folders
        for child_id in folder.child_folder_ids:
            if child_id in folder_records:
                child_folder = folder_records[child_id]
                node["children"].append(build_tree(child_folder))
        
        # Add files
        for file_id in folder.child_file_ids:
            if file_id in file_records:
                file_record = file_records[file_id]
                node["children"].append({
                    "id": file_record.id,
                    "name": file_record.name,
                    "type": "file",
                    "path": file_record.path,
                    "metadata": {
                        "size_bytes": file_record.size,
                        "size_formatted": format_bytes(file_record.size),
                        "mime_type": file_record.mime_type,
                        "created_date": file_record.created_date,
                        "modified_date": file_record.modified_date,
                        "created_by": file_record.created_by,
                        "last_modified_by": file_record.last_modified_by,
                        "version_count": file_record.version_count,
                        "has_unique_permissions": file_record.has_unique_permissions,
                        "permission_count": file_record.permission_count,
                        "sharing_status": file_record.sharing_status,
                        "web_url": file_record.web_url
                    }
                })
        
        return node
    
    # Find root folders (those with empty parent_path)
    root_folders = [f for f in folder_records.values() if not f.parent_path]
    for root_folder in root_folders:
        tree["tree"].append(build_tree(root_folder))
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2, default=str)
    
    print(f"💾 Exported hierarchical JSON to: {output_path}")


def export_flat_csv(
    folder_records: Dict[str, FolderRecord],
    file_records: Dict[str, FileRecord],
    output_path: str
) -> None:
    """
    Export all items to a flat CSV.
    
    Args:
        folder_records: Dictionary of folder records
        file_records: Dictionary of file records
        output_path: Path to output file
    """
    fieldnames = [
        "item_type", "id", "name", "path", "parent_path", "size_bytes",
        "size_formatted", "mime_type", "created_date", "modified_date",
        "created_by", "last_modified_by", "version_count",
        "has_unique_permissions", "permission_count", "sharing_status", "web_url"
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # Write folders
        for folder in folder_records.values():
            writer.writerow({
                "item_type": "folder",
                "id": folder.id,
                "name": folder.name,
                "path": folder.path,
                "parent_path": folder.parent_path,
                "size_bytes": folder.total_size_bytes,
                "size_formatted": format_bytes(folder.total_size_bytes),
                "mime_type": "",
                "created_date": folder.created_date,
                "modified_date": folder.modified_date,
                "created_by": folder.created_by,
                "last_modified_by": folder.last_modified_by,
                "version_count": "",
                "has_unique_permissions": folder.has_unique_permissions,
                "permission_count": folder.permission_count,
                "sharing_status": folder.sharing_status,
                "web_url": folder.web_url
            })
        
        # Write files
        for file in file_records.values():
            writer.writerow({
                "item_type": "file",
                "id": file.id,
                "name": file.name,
                "path": file.path,
                "parent_path": file.parent_path,
                "size_bytes": file.size,
                "size_formatted": format_bytes(file.size),
                "mime_type": file.mime_type,
                "created_date": file.created_date,
                "modified_date": file.modified_date,
                "created_by": file.created_by,
                "last_modified_by": file.last_modified_by,
                "version_count": file.version_count,
                "has_unique_permissions": file.has_unique_permissions,
                "permission_count": file.permission_count,
                "sharing_status": file.sharing_status,
                "web_url": file.web_url
            })
    
    print(f"💾 Exported flat CSV to: {output_path}")


def export_folders_csv(
    folder_records: Dict[str, FolderRecord],
    output_path: str
) -> None:
    """
    Export folder summary to CSV.
    
    Args:
        folder_records: Dictionary of folder records
        output_path: Path to output file
    """
    fieldnames = [
        "id", "name", "path", "parent_path", "file_count", "subfolder_count",
        "total_size_bytes", "total_size_formatted", "created_date", "modified_date",
        "created_by", "last_modified_by", "has_unique_permissions",
        "permission_count", "sharing_status", "web_url"
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for folder in sorted(folder_records.values(), key=lambda x: x.path):
            writer.writerow({
                "id": folder.id,
                "name": folder.name,
                "path": folder.path,
                "parent_path": folder.parent_path,
                "file_count": folder.file_count,
                "subfolder_count": folder.subfolder_count,
                "total_size_bytes": folder.total_size_bytes,
                "total_size_formatted": format_bytes(folder.total_size_bytes),
                "created_date": folder.created_date,
                "modified_date": folder.modified_date,
                "created_by": folder.created_by,
                "last_modified_by": folder.last_modified_by,
                "has_unique_permissions": folder.has_unique_permissions,
                "permission_count": folder.permission_count,
                "sharing_status": folder.sharing_status,
                "web_url": folder.web_url
            })
    
    print(f"💾 Exported folders CSV to: {output_path}")


def export_files_csv(
    file_records: Dict[str, FileRecord],
    output_path: str
) -> None:
    """
    Export file details to CSV.
    
    Args:
        file_records: Dictionary of file records
        output_path: Path to output file
    """
    fieldnames = [
        "id", "name", "path", "parent_path", "size_bytes", "size_formatted",
        "mime_type", "created_date", "modified_date", "created_by",
        "last_modified_by", "version_count", "has_unique_permissions",
        "permission_count", "sharing_status", "web_url"
    ]
    
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for file in sorted(file_records.values(), key=lambda x: x.path):
            writer.writerow({
                "id": file.id,
                "name": file.name,
                "path": file.path,
                "parent_path": file.parent_path,
                "size_bytes": file.size,
                "size_formatted": format_bytes(file.size),
                "mime_type": file.mime_type,
                "created_date": file.created_date,
                "modified_date": file.modified_date,
                "created_by": file.created_by,
                "last_modified_by": file.last_modified_by,
                "version_count": file.version_count,
                "has_unique_permissions": file.has_unique_permissions,
                "permission_count": file.permission_count,
                "sharing_status": file.sharing_status,
                "web_url": file.web_url
            })
    
    print(f"💾 Exported files CSV to: {output_path}")


def export_summary_json(summary: AuditSummary, output_path: str) -> None:
    """Export summary to JSON."""
    summary_dict = {
        "audit_timestamp": summary.audit_timestamp,
        "site_url": summary.site_url,
        "total_folders": summary.total_folders,
        "total_files": summary.total_files,
        "total_size_bytes": summary.total_size_bytes,
        "total_size_formatted": format_bytes(summary.total_size_bytes),
        "folders_with_unique_permissions": summary.folders_with_unique_permissions,
        "files_with_unique_permissions": summary.files_with_unique_permissions,
        "external_sharing_count": summary.external_sharing_count,
        "anonymous_sharing_count": summary.anonymous_sharing_count,
        "max_depth_reached": summary.max_depth_reached
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary_dict, f, indent=2)
    
    print(f"💾 Exported summary JSON to: {output_path}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Main entry point for the deep audit script."""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Deep Recursive SharePoint Audit - HTTHQ Site",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with defaults:
  python audit_recursive_deep.py
  
  # Specify custom site:
  python audit_recursive_deep.py --site-url "yourtenant.sharepoint.com:/sites/YourSite"
  
  # Specify custom output directory:
  python audit_recursive_deep.py --output-dir "./my_audit"
        """
    )
    
    parser.add_argument(
        "--site-url",
        default=os.environ.get("SITE_URL", DEFAULT_SITE_URL),
        help=f"SharePoint site URL (default: {DEFAULT_SITE_URL})"
    )
    
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("OUTPUT_DIR", DEFAULT_OUTPUT_DIR),
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )
    
    args = parser.parse_args()
    
    # Header
    print("=" * 80)
    print("🔍 DEEP RECURSIVE SHAREPOINT AUDIT")
    print("=" * 80)
    print(f"🌐 Site: {args.site_url}")
    print(f"📁 Output: {args.output_dir}")
    print("=" * 80)
    print()
    
    start_time = datetime.now()
    
    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Step 1: Authenticate
    token = authenticate_azure_cli()
    if not token:
        print("\n❌ Authentication failed!")
        print("\nTroubleshooting:")
        print("  1. Ensure you're logged in: az login")
        print("  2. Check your Azure CLI installation: az --version")
        print("  3. Verify you have Graph API permissions")
        return 1
    
    # Step 2: Get site
    site_id = get_site_id(token, args.site_url)
    if not site_id:
        print("❌ Cannot proceed without site ID. Exiting.")
        return 1
    
    # Step 3: Get drives
    drives = get_document_drives(token, site_id)
    if not drives:
        print("❌ Cannot proceed without drives. Exiting.")
        return 1
    
    # Process each drive
    all_folders: Dict[str, FolderRecord] = {}
    all_files: Dict[str, FileRecord] = {}
    
    for drive in drives:
        drive_id = drive.get("id")
        drive_name = drive.get("name", "Unknown")
        
        # Run deep audit on this drive
        folders, files, summary = run_deep_audit(token, drive_id, drive_name)
        
        all_folders.update(folders)
        all_files.update(files)
    
    # Calculate overall summary
    total_size = sum(f.size for f in all_files.values())
    overall_summary = AuditSummary(
        audit_timestamp=datetime.now().isoformat(),
        site_url=args.site_url,
        total_folders=len(all_folders),
        total_files=len(all_files),
        total_size_bytes=total_size,
        folders_with_unique_permissions=sum(1 for f in all_folders.values() if f.has_unique_permissions),
        files_with_unique_permissions=sum(1 for f in all_files.values() if f.has_unique_permissions),
        external_sharing_count=sum(1 for f in all_folders.values() if f.sharing_status in ["external", "anonymous"]) + 
                               sum(1 for f in all_files.values() if f.sharing_status in ["external", "anonymous"]),
        anonymous_sharing_count=sum(1 for f in all_folders.values() if f.sharing_status == "anonymous") + 
                               sum(1 for f in all_files.values() if f.sharing_status == "anonymous"),
        max_depth_reached=max(summary.max_depth_reached, 0)
    )
    
    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Step 4: Export results
    print("\n" + "=" * 80)
    print("📊 EXPORTING RESULTS")
    print("=" * 80)
    
    # Hierarchical JSON
    hierarchical_path = os.path.join(args.output_dir, f"htthq_deep_audit_hierarchical_{timestamp}.json")
    export_to_hierarchical_json(all_folders, all_files, overall_summary, hierarchical_path)
    
    # Flat CSV
    flat_csv_path = os.path.join(args.output_dir, f"htthq_deep_audit_flat_{timestamp}.csv")
    export_flat_csv(all_folders, all_files, flat_csv_path)
    
    # Folders CSV
    folders_csv_path = os.path.join(args.output_dir, f"htthq_deep_audit_folders_{timestamp}.csv")
    export_folders_csv(all_folders, folders_csv_path)
    
    # Files CSV
    files_csv_path = os.path.join(args.output_dir, f"htthq_deep_audit_files_{timestamp}.csv")
    export_files_csv(all_files, files_csv_path)
    
    # Summary JSON
    summary_path = os.path.join(args.output_dir, f"htthq_deep_audit_summary_{timestamp}.json")
    export_summary_json(overall_summary, summary_path)
    
    # Print final summary
    execution_time = (datetime.now() - start_time).total_seconds()
    
    print("\n" + "=" * 80)
    print("✅ DEEP AUDIT COMPLETE")
    print("=" * 80)
    print()
    print("📊 SUMMARY:")
    print(f"   Total Folders:              {overall_summary.total_folders}")
    print(f"   Total Files:                {overall_summary.total_files}")
    print(f"   Total Size:                 {format_bytes(overall_summary.total_size_bytes)}")
    print(f"   Max Folder Depth:           {overall_summary.max_depth_reached}")
    print()
    print("🔐 PERMISSIONS:")
    print(f"   Folders w/ Unique Perms:    {overall_summary.folders_with_unique_permissions}")
    print(f"   Files w/ Unique Perms:      {overall_summary.files_with_unique_permissions}")
    print(f"   External Sharing:           {overall_summary.external_sharing_count}")
    print(f"   Anonymous Sharing:          {overall_summary.anonymous_sharing_count}")
    print()
    print("📁 OUTPUT FILES:")
    print(f"   📄 {hierarchical_path}")
    print(f"   📄 {flat_csv_path}")
    print(f"   📄 {folders_csv_path}")
    print(f"   📄 {files_csv_path}")
    print(f"   📄 {summary_path}")
    print()
    print(f"⏱️  Execution Time: {execution_time:.2f} seconds")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    exit(main())
