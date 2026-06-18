#!/usr/bin/env python3
"""
Folder-only permission audit script for SharePoint.

This script performs a focused audit of SharePoint folder permissions:
- Enumerates ONLY folders (not files) from the document library
- Checks each folder for unique permission inheritance via REST API
- Generates JSON and CSV reports

Usage:
    python audit_folder_permissions.py

Configuration:
    Requires config/config.yaml with Azure AD credentials:
    - tenant_id
    - client_id
    - client_secret (optional - falls back to interactive auth)

Output:
    - ./audit_output/folder_permissions_audit.json
    - ./audit_output/folder_permissions_audit.csv

Exit Codes:
    0 - Success
    1 - Error
    130 - Interrupted by user (Ctrl+C)
"""

import sys
import os
import csv
import json
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import quote
from loguru import logger

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.sharepoint_auth import SharePointAuthContext, create_auth_from_config
from core.audit.graph_client import GraphClient
from core.manager import ConfigurationManager


# Configuration
SITE_URL = "https://example-organization.sharepoint.com/sites/HTTHQ"
SITE_HOSTNAME = "example-organization.sharepoint.com"
SITE_PATH = "/sites/HTTHQ"
DRIVE_NAME = "Documents"
OUTPUT_DIR = "./audit_output"


@dataclass
class FolderPermissionRecord:
    """Represents a folder's permission status."""
    folder_path: str
    web_url: str
    has_unique_permissions: bool
    permission_count: Optional[int] = None
    error: Optional[str] = None


class FolderOnlyDiscoveryEngine:
    """
    Discovery engine that enumerates ONLY folders (not files).
    """

    def __init__(self, graph_client: GraphClient):
        self.graph = graph_client
        logger.info("FolderOnlyDiscoveryEngine initialized")

    def is_system_item(self, name: str) -> bool:
        """Check if an item is a system item that should be excluded."""
        if not name:
            return True
        if name == "Forms":
            return True
        if name.lower().endswith(".aspx"):
            return True
        system_prefixes = ["~", ".", "_"]
        if any(name.startswith(prefix) for prefix in system_prefixes):
            return True
        system_folders = ["appdata", "item templates", "site assets", "site pages", "forms"]
        if name.lower() in system_folders:
            return True
        return False

    def enumerate_folders_only(self, drive_id: str) -> List[Dict[str, Any]]:
        """
        Recursively enumerate ONLY folders in a drive.

        Args:
            drive_id: The drive ID

        Returns:
            List of folder dictionaries with path, webUrl, and id
        """
        logger.info(f"Starting folder-only enumeration for drive {drive_id}")
        start_time = datetime.now()

        folders: List[Dict[str, Any]] = []
        folder_count = 0
        error_count = 0

        # Stack for DFS: (item_id, parent_path)
        stack = [("root", "")]

        while stack:
            item_id, parent_path = stack.pop()

            try:
                child_count = 0
                for child_data in self.graph.get_drive_items(drive_id, item_id):
                    child_count += 1

                    # Log progress periodically
                    if folder_count > 0 and folder_count % 50 == 0:
                        logger.info(f"Discovery progress: {folder_count} folders found...")

                    name = child_data.get("name", "")

                    # Skip system items
                    if self.is_system_item(name):
                        logger.debug(f"Skipping system item: {name}")
                        continue

                    # Skip files - only process folders
                    if "folder" not in child_data:
                        logger.debug(f"Skipping file: {name}")
                        continue

                    # Build full path
                    folder_path = f"{parent_path}/{name}" if parent_path else f"/{name}"

                    folder_info = {
                        "id": child_data.get("id", ""),
                        "name": name,
                        "path": folder_path,
                        "webUrl": child_data.get("webUrl", ""),
                        "parent_id": item_id
                    }

                    folders.append(folder_info)
                    folder_count += 1

                    # Add this folder to stack for processing its children
                    folder_item_id = child_data.get("id")
                    if folder_item_id:
                        stack.append((folder_item_id, folder_path))

                logger.debug(f"Processed {child_count} children of folder {item_id}")

            except Exception as e:
                error_count += 1
                logger.error(f"Error processing folder {item_id}: {e}")
                continue

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        logger.info(f"Folder enumeration complete!")
        logger.info(f"  Total folders: {len(folders)}")
        logger.info(f"  Errors: {error_count}")
        logger.info(f"  Duration: {duration:.2f} seconds")

        return folders


class FolderPermissionAuditor:
    """
    Audits folder permissions using SharePoint REST API.
    """

    def __init__(self, auth: SharePointAuthContext, site_url: str, site_path: str, drive_name: str):
        self.auth = auth
        self.site_url = site_url.rstrip("/")
        self.site_path = site_path
        self.drive_name = drive_name
        logger.info(f"FolderPermissionAuditor initialized for {site_url}")

    def _make_rest_request(self, endpoint: str) -> Dict[str, Any]:
        """Make a REST API request to SharePoint."""
        import requests

        if not endpoint.startswith("/_api/"):
            endpoint = f"/_api/{endpoint.lstrip('/')}"

        url = f"{self.site_url}{endpoint}"
        headers = self.auth.get_headers_sharepoint(self.site_url)
        headers["Accept"] = "application/json;odata=verbose"

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json()
        if "d" in data:
            return data["d"]
        return data

    def check_unique_permissions(self, server_relative_path: str) -> bool:
        """
        Check if a folder has unique permissions.

        Args:
            server_relative_path: Server-relative path (e.g., '/sites/HTTHQ/Shared Documents/Folder')

        Returns:
            True if folder has unique permissions, False if inheriting
        """
        encoded_path = quote(server_relative_path, safe="")
        endpoint = f"/web/GetFolderByServerRelativeUrl('{encoded_path}')/ListItemAllFields/HasUniqueRoleAssignments"

        logger.debug(f"Checking unique permissions for: {server_relative_path}")

        try:
            data = self._make_rest_request(endpoint)
            result = data.get("HasUniqueRoleAssignments", False)
            if isinstance(result, str):
                result = result.lower() == "true"
            return bool(result)
        except Exception as e:
            logger.warning(f"Failed to check permissions for {server_relative_path}: {e}")
            raise

    def get_permission_count(self, server_relative_path: str) -> Optional[int]:
        """
        Get the number of role assignments for a folder.

        Args:
            server_relative_path: Server-relative path

        Returns:
            Number of role assignments, or None if unavailable
        """
        encoded_path = quote(server_relative_path, safe="")
        endpoint = f"/web/GetFolderByServerRelativeUrl('{encoded_path}')/ListItemAllFields/RoleAssignments"

        logger.debug(f"Getting permission count for: {server_relative_path}")

        try:
            data = self._make_rest_request(endpoint)
            results = data.get("results", [])
            return len(results)
        except Exception as e:
            logger.warning(f"Failed to get permission count for {server_relative_path}: {e}")
            return None

    def audit_folder(self, folder_info: Dict[str, Any]) -> FolderPermissionRecord:
        """
        Audit a single folder's permissions.

        Args:
            folder_info: Dictionary with folder metadata

        Returns:
            FolderPermissionRecord with audit results
        """
        folder_path = folder_info["path"]
        web_url = folder_info["webUrl"]

        # Build server-relative path
        server_relative_path = f"{self.site_path}/{self.drive_name}{folder_path}"

        try:
            has_unique = self.check_unique_permissions(server_relative_path)
            permission_count = None

            if has_unique:
                permission_count = self.get_permission_count(server_relative_path)

            return FolderPermissionRecord(
                folder_path=folder_path,
                web_url=web_url,
                has_unique_permissions=has_unique,
                permission_count=permission_count
            )

        except Exception as e:
            logger.error(f"Error auditing folder {folder_path}: {e}")
            return FolderPermissionRecord(
                folder_path=folder_path,
                web_url=web_url,
                has_unique_permissions=False,
                error=str(e)
            )

    def audit_all_folders(self, folders: List[Dict[str, Any]]) -> List[FolderPermissionRecord]:
        """
        Audit permissions for all folders.

        Args:
            folders: List of folder dictionaries

        Returns:
            List of FolderPermissionRecord
        """
        results: List[FolderPermissionRecord] = []
        total = len(folders)

        logger.info(f"Starting permission audit for {total} folders...")

        for idx, folder in enumerate(folders, 1):
            logger.info(f"Auditing folder {idx}/{total}: {folder['path']}")
            record = self.audit_folder(folder)
            results.append(record)

            # Progress logging every 10 folders
            if idx % 10 == 0:
                logger.info(f"Progress: {idx}/{total} folders processed ({idx/total*100:.1f}%)")

        logger.info(f"Permission audit complete. Audited {len(results)} folders.")
        return results


class FolderAuditReporter:
    """
    Generates reports from folder permission audit results.
    """

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"FolderAuditReporter initialized. Output dir: {self.output_dir}")

    def save_json(self, records: List[FolderPermissionRecord], filename: str = "folder_permissions_audit.json") -> str:
        """Save results to JSON file."""
        output_path = self.output_dir / filename

        data = []
        for record in records:
            data.append({
                "folder_path": record.folder_path,
                "web_url": record.web_url,
                "has_unique_permissions": record.has_unique_permissions,
                "permission_count": record.permission_count,
                "error": record.error
            })

        metadata = {
            "audit_timestamp": datetime.now().isoformat(),
            "total_folders": len(records),
            "folders_with_unique_permissions": sum(1 for r in records if r.has_unique_permissions),
            "folders_with_errors": sum(1 for r in records if r.error is not None)
        }

        output = {
            "metadata": metadata,
            "folders": data
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

        logger.info(f"JSON report saved: {output_path}")
        return str(output_path)

    def save_csv(self, records: List[FolderPermissionRecord], filename: str = "folder_permissions_audit.csv") -> str:
        """Save results to CSV file."""
        output_path = self.output_dir / filename

        fieldnames = ["folder_path", "has_unique_permissions", "permission_count", "web_url"]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for record in records:
                writer.writerow({
                    "folder_path": record.folder_path,
                    "has_unique_permissions": record.has_unique_permissions,
                    "permission_count": record.permission_count if record.permission_count is not None else "",
                    "web_url": record.web_url
                })

        logger.info(f"CSV report saved: {output_path}")
        return str(output_path)

    def generate_summary(self, records: List[FolderPermissionRecord]) -> str:
        """Generate a text summary report."""
        total = len(records)
        unique_count = sum(1 for r in records if r.has_unique_permissions)
        inherited_count = total - unique_count
        error_count = sum(1 for r in records if r.error is not None)

        lines = [
            "=" * 80,
            "FOLDER PERMISSIONS AUDIT SUMMARY",
            "=" * 80,
            "",
            f"Audit Timestamp: {datetime.now().isoformat()}",
            f"Site: {SITE_URL}",
            f"Document Library: {DRIVE_NAME}",
            "",
            "STATISTICS:",
            f"  Total folders audited: {total}",
            f"  Folders with unique permissions: {unique_count} ({unique_count/total*100:.1f}%)",
            f"  Folders with inherited permissions: {inherited_count} ({inherited_count/total*100:.1f}%)",
            f"  Folders with errors: {error_count}",
            "",
        ]

        if unique_count > 0:
            lines.extend([
                "FOLDERS WITH UNIQUE PERMISSIONS:",
                "-" * 80,
            ])
            for record in records:
                if record.has_unique_permissions:
                    perm_info = f" ({record.permission_count} permissions)" if record.permission_count else ""
                    lines.append(f"  {record.folder_path}{perm_info}")
            lines.append("")

        if error_count > 0:
            lines.extend([
                "FOLDERS WITH ERRORS:",
                "-" * 80,
            ])
            for record in records:
                if record.error:
                    lines.append(f"  {record.folder_path}: {record.error}")
            lines.append("")

        lines.extend([
            "=" * 80,
            f"Output files saved to: {self.output_dir}",
            "=" * 80,
        ])

        summary_text = "\n".join(lines)

        # Save summary to file
        summary_path = self.output_dir / "folder_permissions_summary.txt"
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary_text)

        logger.info(f"Summary report saved: {summary_path}")
        return summary_text


def print_banner():
    """Print the audit banner."""
    print("=" * 80)
    print("📁 FOLDER-ONLY PERMISSION AUDIT")
    print("=" * 80)
    print(f"📍 Site: {SITE_URL}")
    print(f"📂 Document Library: {DRIVE_NAME}")
    print(f"📁 Output: {OUTPUT_DIR}")
    print("=" * 80)
    print()


def main():
    """Main entry point for the folder permission audit."""
    print_banner()

    try:
        # Step 1: Load configuration
        print("📋 Step 1: Loading configuration...")
        config_manager = ConfigurationManager(config_file="config/config.yaml")
        config_manager.load_config()
        full_config = config_manager.config
        azure_config = full_config.get('azure', {})

        if not azure_config:
            print("❌ Error: Azure configuration not found!")
            print("\nPlease create config/config.yaml with your Azure AD credentials.")
            return 1

        required_keys = ["tenant_id", "client_id"]
        missing = [k for k in required_keys if not azure_config.get(k)]
        if missing:
            print(f"❌ Error: Missing required config keys: {', '.join(missing)}")
            return 1

        client_secret = azure_config.get("client_secret")
        if client_secret:
            print("   ✅ Configuration loaded (using client secret authentication)")
        else:
            print("   ✅ Configuration loaded (will use interactive browser authentication)")
        print()

        # Step 2: Initialize authentication
        print("🔐 Step 2: Authenticating with SharePoint...")
        try:
            auth = create_auth_from_config(full_config)
            print("   ✅ Authentication successful")
        except Exception as e:
            print(f"   ❌ Authentication failed: {e}")
            return 1
        print()

        # Step 3: Resolve site and drive
        print("🔍 Step 3: Resolving site and drive...")
        graph_client = GraphClient(auth)

        try:
            # Get site ID
            site_id = graph_client.get_site_id(SITE_HOSTNAME, SITE_PATH)
            print(f"   ✅ Site resolved: {site_id}")

            # Get drives and find target
            drives = graph_client.get_drives(site_id)
            target_drive = None
            for drive in drives:
                if drive.get("name", "").lower() == DRIVE_NAME.lower():
                    target_drive = drive
                    break

            if not target_drive and drives:
                target_drive = drives[0]
                print(f"   ⚠️  Drive '{DRIVE_NAME}' not found. Using '{target_drive.get('name')}' instead.")

            if not target_drive:
                print("   ❌ No drives found in site")
                return 1

            drive_id = target_drive["id"]
            print(f"   ✅ Drive resolved: {target_drive.get('name')} ({drive_id})")

        except Exception as e:
            print(f"   ❌ Failed to resolve site or drive: {e}")
            return 1
        print()

        # Step 4: Enumerate folders only
        print("📂 Step 4: Enumerating folders...")
        discovery = FolderOnlyDiscoveryEngine(graph_client)
        try:
            folders = discovery.enumerate_folders_only(drive_id)
            print(f"   ✅ Found {len(folders)} folders")
        except Exception as e:
            print(f"   ❌ Folder enumeration failed: {e}")
            return 1
        print()

        if not folders:
            print("⚠️  No folders found in document library. Nothing to audit.")
            return 0

        # Step 5: Audit folder permissions
        print("🔐 Step 5: Auditing folder permissions...")
        print("-" * 80)
        auditor = FolderPermissionAuditor(auth, SITE_URL, SITE_PATH, DRIVE_NAME)
        try:
            results = auditor.audit_all_folders(folders)
            print("   ✅ Permission audit complete")
        except Exception as e:
            print(f"   ❌ Permission audit failed: {e}")
            return 1
        print()

        # Step 6: Generate reports
        print("📊 Step 6: Generating reports...")
        reporter = FolderAuditReporter(OUTPUT_DIR)

        json_path = reporter.save_json(results)
        csv_path = reporter.save_csv(results)
        summary = reporter.generate_summary(results)

        print(f"   ✅ JSON report: {json_path}")
        print(f"   ✅ CSV report: {csv_path}")
        print()

        # Print summary
        print(summary)

        return 0

    except KeyboardInterrupt:
        print()
        print("⚠️  Audit interrupted by user (Ctrl+C)")
        return 130

    except Exception as e:
        print()
        print("❌ Audit failed!")
        print(f"Error: {type(e).__name__}: {e}")
        print()
        logger.exception("Folder permission audit failed")
        return 1

    finally:
        # Cleanup
        if 'graph_client' in locals():
            graph_client.close()


if __name__ == "__main__":
    sys.exit(main())
