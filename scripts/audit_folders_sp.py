#!/usr/bin/env python3
"""
SharePoint Folder Permission Audit - Service Principal & OIDC Edition

This script performs folder permission audits on SharePoint using either:
    - Service Principal authentication (ClientSecretCredential)
    - OIDC federation (DefaultAzureCredential with WorkloadIdentityCredential)
    - Interactive device code flow (fallback)

Perfect for both local development and CI/CD pipelines!

Environment Variables Required (Service Principal):
    AZURE_CLIENT_ID      - Your Azure AD App Registration Client ID
    AZURE_CLIENT_SECRET  - Your Azure AD App Client Secret
    AZURE_TENANT_ID      - Your Azure AD Tenant ID

Environment Variables Required (OIDC - for CI/CD):
    AZURE_CLIENT_ID      - Your Azure AD App Registration Client ID
    AZURE_TENANT_ID      - Your Azure AD Tenant ID
    AZURE_FEDERATED_TOKEN_FILE - Path to OIDC token file (auto-set by GitHub Actions)
    Or AZURE_AUTHORITY_HOST for other OIDC providers

Optional Environment Variables:
    SITE_URL             - SharePoint site URL (default: example-organization.sharepoint.com:/sites/HTTHQ)
    OUTPUT_DIR           - Directory for output files (default: ./audit_output)
    CI                   - Set to "true" for CI/CD mode (non-interactive)
    CI_ENVIRONMENT       - Environment name for reporting (dev, production, etc.)

Usage:
    # With Service Principal:
    export AZURE_CLIENT_SECRET='your-secret'
    python audit_folders_sp.py

    # In GitHub Actions (OIDC):
    python audit_folders_sp.py --ci-mode --format both

    # With saved configuration:
    python audit_folders_sp.py --use-saved-config

Created: Service Principal + OIDC authentication version for automation
"""

import os
import sys
import json
import csv
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict

import requests
from azure.identity import (
    ClientSecretCredential,
    DefaultAzureCredential,
    AzureCliCredential,
)
from azure.core.exceptions import ClientAuthenticationError


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_CLIENT_ID = "e4846a2a-c399-4d3a-bcb5-c66ac214ec23"
DEFAULT_TENANT_ID = "0c0e35dc-188a-4eb3-b8ba-61752154b407"
DEFAULT_SITE_URL = "example-organization.sharepoint.com:/sites/HTTHQ"
DEFAULT_OUTPUT_DIR = "./audit_output"

GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"

# Config file location (matches setup script)
CONFIG_DIR = Path.home() / ".sharepoint-agent"
CONFIG_FILE = CONFIG_DIR / "sp_credentials.json"

# CI/CD Detection
CI_MODE = os.environ.get("CI", "").lower() in ("true", "1", "yes", "on")
CI_ENVIRONMENT = os.environ.get("CI_ENVIRONMENT", os.environ.get("ENVIRONMENT", "local"))


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


@dataclass
class AuthenticationResult:
    """Result of authentication attempt."""
    success: bool
    token: Optional[str]
    credential: Optional[Any]
    auth_method: str
    error_message: str = ""


@dataclass
class CISummary:
    """Summary for CI/CD environments."""
    total_folders: int
    folders_with_unique_permissions: int
    folders_with_inherited_permissions: int
    execution_time_seconds: float
    success: bool
    error_message: str = ""


# =============================================================================
# AUTHENTICATION - MULTI-METHOD
# =============================================================================

def load_credentials_from_config() -> Dict[str, str]:
    """
    Load credentials from the saved configuration file.
    
    Returns:
        Dictionary with client_id, client_secret, tenant_id
    """
    if not CONFIG_FILE.exists():
        return {}
    
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        
        return {
            "client_id": config.get("client_id", ""),
            "client_secret": config.get("client_secret", ""),
            "tenant_id": config.get("tenant_id", "")
        }
    except Exception as e:
        print(f"⚠️  Warning: Failed to load config file: {e}", file=sys.stderr)
        return {}


def get_credentials(use_saved_config: bool = False) -> Dict[str, str]:
    """
    Get credentials from environment variables or config file.
    
    Args:
        use_saved_config: If True, try loading from saved config file first
        
    Returns:
        Dictionary with client_id, client_secret, tenant_id
    """
    credentials = {
        "client_id": "",
        "client_secret": "",
        "tenant_id": ""
    }
    
    # Try config file first if requested
    if use_saved_config:
        config_creds = load_credentials_from_config()
        if config_creds:
            if not CI_MODE:
                print("📂 Loaded credentials from saved configuration")
            credentials.update(config_creds)
            return credentials
        else:
            if not CI_MODE:
                print("⚠️  No saved configuration found, checking environment variables...")
    
    # Check environment variables
    credentials["client_id"] = os.environ.get("AZURE_CLIENT_ID", DEFAULT_CLIENT_ID)
    credentials["client_secret"] = os.environ.get("AZURE_CLIENT_SECRET", "")
    credentials["tenant_id"] = os.environ.get("AZURE_TENANT_ID", DEFAULT_TENANT_ID)
    
    return credentials


def is_oidc_environment() -> bool:
    """
    Detect if we're running in an OIDC-enabled CI/CD environment.
    
    Returns:
        True if OIDC environment variables are detected
    """
    # Check for GitHub Actions OIDC
    if os.environ.get("AZURE_FEDERATED_TOKEN_FILE"):
        return True
    
    # Check for other OIDC providers
    if os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        return True
    
    # Check for Azure workload identity
    if os.environ.get("AZURE_AUTHORITY_HOST"):
        return True
    
    return False


def authenticate_oidc() -> AuthenticationResult:
    """
    Authenticate using OIDC federation (for GitHub Actions).
    
    Uses DefaultAzureCredential which includes WorkloadIdentityCredential
    for OIDC token exchange.
    
    Returns:
        AuthenticationResult with token and status
    """
    if not CI_MODE:
        print("🔐 Authenticating with OIDC federation...")
    
    try:
        # Try AzureCliCredential directly first for local testing
        try:
            credential = AzureCliCredential()
            token = credential.get_token("https://graph.microsoft.com/.default")
        except Exception:
            # Fall back to DefaultAzureCredential for other environments
            credential = DefaultAzureCredential(
                exclude_interactive_browser_credential=True,
                exclude_device_code_credential=True,
                exclude_shared_token_cache_credential=True,
                exclude_visual_studio_code_credential=True,
                exclude_azure_cli_credential=False,
                exclude_managed_identity_credential=True,
            )
            token = credential.get_token("https://graph.microsoft.com/.default")
        
        if not CI_MODE:
            print("✅ OIDC authentication successful!")
            print(f"   Token expires: {token.expires_on}")
        
        return AuthenticationResult(
            success=True,
            token=token.token,
            credential=credential,
            auth_method="OIDC"
        )
        
    except ClientAuthenticationError as e:
        error_msg = str(e)
        if "AADSTS70021" in error_msg:
            error_msg = (
                "OIDC federation failed. No matching federated identity record found. "
                "Please verify your federated credential subject identifier matches "
                "the GitHub Actions workflow context."
            )
        elif "AADSTS70011" in error_msg:
            error_msg = (
                "Invalid scope. Ensure your Azure AD app has Microsoft Graph permissions "
                "and admin consent has been granted."
            )
        
        return AuthenticationResult(
            success=False,
            token=None,
            credential=None,
            auth_method="OIDC",
            error_message=error_msg
        )
        
    except Exception as e:
        return AuthenticationResult(
            success=False,
            token=None,
            credential=None,
            auth_method="OIDC",
            error_message=f"OIDC authentication error: {str(e)}"
        )


def authenticate_service_principal(
    client_id: str,
    client_secret: str,
    tenant_id: str
) -> AuthenticationResult:
    """
    Authenticate using Service Principal (ClientSecretCredential).
    
    Args:
        client_id: Azure AD App Registration Client ID
        client_secret: Azure AD App Client Secret
        tenant_id: Azure AD Tenant ID
        
    Returns:
        AuthenticationResult with token and status
    """
    if not CI_MODE:
        print("🔐 Authenticating with Service Principal...")
    
    # Validate inputs
    if not all([client_id, client_secret, tenant_id]):
        missing = []
        if not client_id:
            missing.append("client_id (AZURE_CLIENT_ID)")
        if not client_secret:
            missing.append("client_secret (AZURE_CLIENT_SECRET)")
        if not tenant_id:
            missing.append("tenant_id (AZURE_TENANT_ID)")
        
        return AuthenticationResult(
            success=False,
            token=None,
            credential=None,
            auth_method="ServicePrincipal",
            error_message=f"Missing required credentials: {', '.join(missing)}"
        )
    
    try:
        # Create credential
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        print("DEBUG: Getting token...", file=sys.stderr, flush=True)
        # Get token for Microsoft Graph
        token = credential.get_token("https://graph.microsoft.com/.default")
        
        if not CI_MODE:
            print("✅ Service Principal authentication successful!")
            print(f"   Token expires: {token.expires_on}")
        
        return AuthenticationResult(
            success=True,
            token=token.token,
            credential=credential,
            auth_method="ServicePrincipal"
        )
        
    except ClientAuthenticationError as e:
        error_msg = str(e)
        if "AADSTS7000215" in error_msg:
            error_msg = "Invalid client secret. Please check AZURE_CLIENT_SECRET."
        elif "AADSTS700016" in error_msg:
            error_msg = "Application not found. Please check AZURE_CLIENT_ID."
        elif "AADSTS90002" in error_msg:
            error_msg = "Tenant not found. Please check AZURE_TENANT_ID."
        
        return AuthenticationResult(
            success=False,
            token=None,
            credential=None,
            auth_method="ServicePrincipal",
            error_message=error_msg
        )
        
    except Exception as e:
        return AuthenticationResult(
            success=False,
            token=None,
            credential=None,
            auth_method="ServicePrincipal",
            error_message=f"Authentication error: {str(e)}"
        )


def authenticate(
    credentials: Dict[str, str],
    prefer_oidc: bool = True
) -> AuthenticationResult:
    """
    Authenticate using the best available method.
    
    Priority:
    1. OIDC (if in CI/CD environment)
    2. Service Principal (if client secret available)
    3. Interactive (fallback, not in CI mode)
    
    Args:
        credentials: Dictionary with client_id, client_secret, tenant_id
        prefer_oidc: If True, try OIDC first in CI environments
        
    Returns:
        AuthenticationResult with token and status
    """
    # Try OIDC first if we're in a CI environment or OIDC is detected
    if prefer_oidc and (CI_MODE or is_oidc_environment()):
        result = authenticate_oidc()
        if result.success:
            return result
        
        # OIDC failed, but we have a client secret as fallback
        if credentials.get("client_secret"):
            if not CI_MODE:
                print("⚠️  OIDC failed, falling back to Service Principal...")
    
    # Try Service Principal
    if credentials.get("client_secret"):
        result = authenticate_service_principal(
            credentials.get("client_id", ""),
            credentials.get("client_secret", ""),
            credentials.get("tenant_id", "")
        )
        if result.success:
            return result
    
    # In CI mode, we can't do interactive auth
    if CI_MODE:
        return AuthenticationResult(
            success=False,
            token=None,
            credential=None,
            auth_method="None",
            error_message=(
                "No authentication method available in CI mode. "
                "Ensure AZURE_CLIENT_ID, AZURE_TENANT_ID are set, "
                "and either OIDC federation is configured or AZURE_CLIENT_SECRET is provided."
            )
        )
    
    # Last resort: interactive device code flow
    print("🔐 Falling back to interactive device code authentication...")
    try:
        credential = DeviceCodeCredential(
            tenant_id=credentials.get("tenant_id", DEFAULT_TENANT_ID),
            client_id=credentials.get("client_id", DEFAULT_CLIENT_ID)
        )
        token = credential.get_token("https://graph.microsoft.com/.default")
        
        print("✅ Interactive authentication successful!")
        
        return AuthenticationResult(
            success=True,
            token=token.token,
            credential=credential,
            auth_method="Interactive"
        )
    except Exception as e:
        return AuthenticationResult(
            success=False,
            token=None,
            credential=None,
            auth_method="Interactive",
            error_message=f"Interactive authentication failed: {str(e)}"
        )


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
        if CI_MODE:
            print(f"::error::API Error: {e}", file=sys.stderr)
        else:
            print(f"❌ API Error: {e}")
        return None


def get_site(token: str, site_url: str) -> Optional[str]:
    """
    Get SharePoint site ID from URL.
    
    Args:
        token: Access token
        site_url: SharePoint site URL
        
    Returns:
        Site ID string, or None on error
    """
    if not CI_MODE:
        print(f"📍 Looking up site: {site_url}")
    
    url = f"{GRAPH_API_BASE}/sites/{site_url}"
    
    data = make_graph_request(url, get_headers(token))
    if data and "id" in data:
        site_id = data["id"]
        if not CI_MODE:
            print(f"✅ Found site ID: {site_id}")
        return site_id
    
    if CI_MODE:
        print(f"::error::Failed to retrieve site information for {site_url}", file=sys.stderr)
    else:
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
    if not CI_MODE:
        print("📂 Retrieving document library...")
    
    url = f"{GRAPH_API_BASE}/sites/{site_id}/drives"
    
    data = make_graph_request(url, get_headers(token))
    if data and "value" in data and len(data["value"]) > 0:
        # Look for drive named 'Documents'
        available_drives = [d.get("name", "Unknown") for d in data["value"]]
        
        if not CI_MODE:
            print(f"   Available drives: {available_drives}")
        
        for drive in data["value"]:
            drive_name = drive.get("name", "Unknown")
            if drive_name == "Documents":
                drive_id = drive["id"]
                if not CI_MODE:
                    print(f"✅ Found drive: '{drive_name}' (ID: {drive_id})")
                return drive_id
        
        if CI_MODE:
            print(f"::error::Drive 'Documents' not found. Available: {available_drives}", file=sys.stderr)
        else:
            print("❌ Drive 'Documents' not found")
            print(f"   Available drives: {available_drives}")
        return None
    
    if CI_MODE:
        print("::error::No drives found for this site", file=sys.stderr)
    else:
        print("❌ No drives found for this site")
    return None


def get_folder_permissions(token: str, drive_id: str, item_id: str) -> Tuple[bool, int]:
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
        
        if not CI_MODE:
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
    
    if not CI_MODE:
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
        
        if not CI_MODE:
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
    
    if not CI_MODE:
        print("=" * 60)
        print(f"✅ Found {len(records)} folders\n")
    
    return records


# =============================================================================
# EXPORT FUNCTIONS
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
            writer.writerow(asdict(record))
    
    if not CI_MODE:
        print(f"💾 Exported {len(records)} records to: {output_path}")


def export_to_json(records: List[FolderAuditRecord], output_path: str, 
                   auth_method: str = "unknown") -> None:
    """
    Export audit records to JSON file.
    
    Args:
        records: List of folder audit records
        output_path: Path to output JSON file
        auth_method: Authentication method used
    """
    data = {
        "audit_timestamp": datetime.now().isoformat(),
        "environment": CI_ENVIRONMENT,
        "authentication_method": auth_method,
        "total_folders": len(records),
        "folders_with_unique_permissions": sum(1 for r in records if r.has_unique_permissions),
        "folders": [asdict(r) for r in records]
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    if not CI_MODE:
        print(f"💾 Exported {len(records)} records to: {output_path}")


def output_ci_summary(records: List[FolderAuditRecord], 
                      auth_method: str,
                      execution_time: float) -> CISummary:
    """
    Output CI/CD friendly summary.
    
    Args:
        records: List of folder audit records
        auth_method: Authentication method used
        execution_time: Execution time in seconds
        
    Returns:
        CISummary object
    """
    unique_count = sum(1 for r in records if r.has_unique_permissions)
    inherited_count = len(records) - unique_count
    
    summary = CISummary(
        total_folders=len(records),
        folders_with_unique_permissions=unique_count,
        folders_with_inherited_permissions=inherited_count,
        execution_time_seconds=execution_time,
        success=True
    )
    
    # Output GitHub Actions workflow commands
    print("\n" + "=" * 60)
    print("SHAREPOINT AUDIT SUMMARY")
    print("=" * 60)
    print(f"Environment:        {CI_ENVIRONMENT}")
    print(f"Authentication:     {auth_method}")
    print(f"Total Folders:      {summary.total_folders}")
    print(f"Unique Permissions: {summary.folders_with_unique_permissions}")
    print(f"Inherited Perms:    {summary.folders_with_inherited_permissions}")
    print(f"Execution Time:     {execution_time:.2f}s")
    print("=" * 60)
    
    # Output GitHub Actions annotations
    print(f"\n::set-output name=total_folders::{summary.total_folders}")
    print(f"::set-output name=unique_permissions::{summary.folders_with_unique_permissions}")
    print(f"::set-output name=inherited_permissions::{summary.folders_with_inherited_permissions}")
    
    return summary


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Main entry point for the folder audit script."""
    global CI_MODE
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="SharePoint Folder Permission Audit - Service Principal & OIDC Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With environment variables (Service Principal):
  export AZURE_CLIENT_SECRET='your-secret'
  python audit_folders_sp.py
  
  # In GitHub Actions (OIDC):
  python audit_folders_sp.py --ci-mode --format both
  
  # Use saved configuration:
  python audit_folders_sp.py --use-saved-config
  
  # Specify custom site:
  python audit_folders_sp.py --site-url "yourtenant.sharepoint.com:/sites/YourSite"
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
    
    parser.add_argument(
        "--use-saved-config",
        action="store_true",
        help="Load credentials from saved configuration file"
    )
    
    parser.add_argument(
        "--format",
        choices=["csv", "json", "both"],
        default="csv",
        help="Output format (default: csv)"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal output (good for automation)"
    )
    
    parser.add_argument(
        "--ci-mode",
        action="store_true",
        default=CI_MODE,
        help="CI/CD mode (non-interactive, uses env vars)"
    )
    
    parser.add_argument(
        "--prefer-oidc",
        action="store_true",
        default=True,
        help="Prefer OIDC authentication when in CI/CD (default: True)"
    )
    
    args = parser.parse_args()
    
    # Override CI_MODE if explicitly set via argument
    if args.ci_mode:
        CI_MODE = True
    
    start_time = datetime.now()
    
    # Header
    if not CI_MODE and not args.quiet:
        print("=" * 60)
        print("📊 SharePoint Folder Permission Audit")
        print("=" * 60)
        print()
        print(f"🌐 Site: {args.site_url}")
        print(f"🔧 Environment: {CI_ENVIRONMENT}")
        print()
    
    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get credentials
    credentials = get_credentials(use_saved_config=args.use_saved_config)
    
    # Authenticate
    auth_result = authenticate(credentials, prefer_oidc=args.prefer_oidc)
    
    if not auth_result.success:
        error_msg = auth_result.error_message
        
        if CI_MODE:
            print(f"::error::{error_msg}", file=sys.stderr)
            print("\n::error::Authentication failed. Check your Azure configuration.", file=sys.stderr)
        else:
            print()
            print(f"❌ Authentication failed: {error_msg}")
            print()
            print("Troubleshooting:")
            print("  1. For Service Principal:")
            print("     - Run 'python setup_service_principal.py' to configure credentials")
            print("     - Set environment variables:")
            print("       export AZURE_CLIENT_SECRET='your-secret'")
            print("  2. For OIDC (GitHub Actions):")
            print("     - Run 'python setup_oidc_federation.py' for setup instructions")
            print("     - Ensure federated credentials are configured in Azure AD")
            print("  3. Use --use-saved-config if you saved credentials during setup")
            print()
        
        return 1
    
    token = auth_result.token
    
    # Get site
    site_id = get_site(token, args.site_url)
    if not site_id:
        if CI_MODE:
            print("::error::Cannot proceed without site ID. Exiting.", file=sys.stderr)
        else:
            print("❌ Cannot proceed without site ID. Exiting.")
        return 1
    
    # Get drive (document library)
    drive_id = get_default_drive(token, site_id)
    if not drive_id:
        if CI_MODE:
            print("::error::Cannot proceed without drive ID. Exiting.", file=sys.stderr)
        else:
            print("❌ Cannot proceed without drive ID. Exiting.")
        return 1
    
    # Enumerate all folders
    records = enumerate_all_folders(token, drive_id)
    
    if not records:
        if CI_MODE:
            print("::warning::No folders found or error occurred during enumeration.", file=sys.stderr)
        else:
            print("⚠️  No folders found or error occurred during enumeration.")
        return 1
    
    # Export results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"folder_audit_{timestamp}"
    
    if args.format in ("csv", "both"):
        csv_file = os.path.join(args.output_dir, f"{base_filename}.csv")
        export_to_csv(records, csv_file)
    
    if args.format in ("json", "both"):
        json_file = os.path.join(args.output_dir, f"{base_filename}.json")
        export_to_json(records, json_file, auth_result.auth_method)
    
    # Calculate execution time
    execution_time = (datetime.now() - start_time).total_seconds()
    
    # CI Mode summary
    if CI_MODE:
        output_ci_summary(records, auth_result.auth_method, execution_time)
    elif not args.quiet:
        # Regular summary
        unique_count = sum(1 for r in records if r.has_unique_permissions)
        inherited_count = len(records) - unique_count
        
        print()
        print("=" * 60)
        print("📈 AUDIT SUMMARY")
        print("=" * 60)
        print(f"Authentication:                     {auth_result.auth_method}")
        print(f"Total folders audited:              {len(records)}")
        print(f"Folders with unique permissions:    {unique_count}")
        print(f"Folders with inherited permissions: {inherited_count}")
        print(f"Execution time:                     {execution_time:.2f}s")
        print()
        print("Output files:")
        if args.format in ("csv", "both"):
            print(f"  CSV: {os.path.join(args.output_dir, base_filename)}.csv")
        if args.format in ("json", "both"):
            print(f"  JSON: {os.path.join(args.output_dir, base_filename)}.json")
        print("=" * 60)
    
    return 0


if __name__ == "__main__":
    exit(main())