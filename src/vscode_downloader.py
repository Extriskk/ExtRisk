"""
VSCode Extension Downloader - Downloads extensions from VS Marketplace or Open VSX

Supports downloading by:
  - Full identifier: publisher.extensionName
  - Marketplace URL: https://marketplace.visualstudio.com/items?itemName=publisher.extensionName
  - Open VSX: use --openvsx and identifier (e.g. jtl.vscode-theme-seti from open-vsx.org)
"""

import re
import requests
from pathlib import Path


class VSCodeExtensionDownloader:
    """Downloads VSCode extensions (.vsix) from the Visual Studio Marketplace or Open VSX Registry"""

    # VS Marketplace Gallery API endpoint
    GALLERY_API = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"

    # Direct VSIX download URL template (VS Marketplace)
    VSIX_DOWNLOAD_URL = (
        "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/"
        "{publisher}/vsextensions/{name}/{version}/vspackage"
    )

    # Open VSX Registry API (metadata for latest version; response includes files.download)
    OPENVSX_API_BASE = "https://open-vsx.org/api"

    # Marketplace item URL pattern
    MARKETPLACE_URL_RE = re.compile(
        r'marketplace\.visualstudio\.com/items\?itemName=([^&\s]+)',
        re.IGNORECASE
    )

    # Open VSX extension URL: open-vsx.org/extension/namespace/name
    OPENVSX_URL_RE = re.compile(
        r'open-vsx\.org/extension/([a-zA-Z0-9\-]+)/([a-zA-Z0-9\-]+)',
        re.IGNORECASE
    )

    # Valid extension identifier pattern: publisher.extensionName
    IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+$')

    def __init__(self, download_dir="downloads"):
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json;api-version=6.1-preview.1',
            'Content-Type': 'application/json',
        }

    def parse_identifier(self, input_str):
        """
        Parse input into (publisher, extension_name) tuple.

        Accepts:
          - publisher.extensionName
          - https://marketplace.visualstudio.com/items?itemName=publisher.extensionName

        Returns:
            tuple: (publisher, extension_name) or None
        """
        input_str = input_str.strip()

        # Check if it's an Open VSX URL (namespace/name in path)
        openvsx_match = self.OPENVSX_URL_RE.search(input_str)
        if openvsx_match:
            return (openvsx_match.group(1), openvsx_match.group(2))

        # Check if it's a marketplace URL
        url_match = self.MARKETPLACE_URL_RE.search(input_str)
        if url_match:
            identifier = url_match.group(1)
        else:
            identifier = input_str

        # Validate identifier format (publisher.extensionName)
        if not self.IDENTIFIER_RE.match(identifier):
            return None

        parts = identifier.split('.', 1)
        if len(parts) != 2:
            return None

        return (parts[0], parts[1])

    def _fetch_metadata_openvsx(self, publisher, extension_name):
        """
        Fetch extension metadata from Open VSX Registry.
        Returns same-shaped dict as fetch_metadata for compatibility.
        """
        url = f"{self.OPENVSX_API_BASE}/{publisher}/{extension_name}"
        try:
            resp = requests.get(url, headers={'Accept': 'application/json'}, timeout=15)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            return {'available': False, 'error': str(e)}

        files = data.get('files') or {}
        download_url = files.get('download')
        if not download_url:
            return {'available': False, 'error': 'No download URL in Open VSX response'}

        version = data.get('version', 'unknown')
        pub = data.get('publishedBy') or {}
        metadata = {
            'available': True,
            'store': 'openvsx',
            'identifier': f"{publisher}.{extension_name}",
            'name': data.get('displayName', extension_name),
            'publisher': pub.get('fullName', publisher),
            'publisher_id': pub.get('loginName', publisher),
            'publisher_domain': '',
            'publisher_verified': data.get('verified', False),
            'short_description': (data.get('description') or '')[:200],
            'version': version,
            'last_updated': data.get('timestamp', 'Unknown'),
            'categories': data.get('categories', []),
            'tags': data.get('tags', []),
            'install_count': int(data.get('downloadCount', 0)),
            'rating_value': round(data.get('averageRating', 0), 2),
            'rating_count': int(data.get('reviewCount', 0)),
            'flags': '',
            'store_url': f"https://open-vsx.org/extension/{publisher}/{extension_name}",
            'risk_signals': {},
            '_openvsx_download_url': download_url,
        }
        if metadata['install_count'] < 500:
            metadata['risk_signals']['low_adoption'] = True
        if not metadata['publisher_verified']:
            metadata['risk_signals']['unverified_publisher'] = True
        if metadata['rating_count'] < 5:
            metadata['risk_signals']['few_ratings'] = True
        return metadata

    def fetch_metadata(self, publisher, extension_name, store='vscode'):
        """
        Fetch extension metadata from VS Marketplace or Open VSX.

        Args:
            publisher: Publisher/namespace name
            extension_name: Extension name
            store: 'vscode' (default) or 'openvsx'

        Returns:
            dict: Extension metadata including version, description, stats, etc.
        """
        if store == 'openvsx':
            return self._fetch_metadata_openvsx(publisher, extension_name)

        # VS Marketplace
        payload = {
            "filters": [
                {
                    "criteria": [
                        {
                            "filterType": 7,  # ExtensionName
                            "value": f"{publisher}.{extension_name}"
                        }
                    ],
                    "pageNumber": 1,
                    "pageSize": 1,
                    "sortBy": 0,
                    "sortOrder": 0
                }
            ],
            "assetTypes": [],
            "flags": 0x192  # IncludeVersions | IncludeStatistics | IncludeFiles
        }

        try:
            resp = requests.post(
                self.GALLERY_API,
                json=payload,
                headers=self.headers,
                timeout=15
            )
            resp.raise_for_status()
            data = resp.json()

            results = data.get('results', [])
            if not results or not results[0].get('extensions'):
                return {'available': False, 'error': 'Extension not found in VS Marketplace'}

            ext = results[0]['extensions'][0]

            # Extract statistics
            stats = {}
            for stat in ext.get('statistics', []):
                stats[stat['statisticName']] = stat.get('value', 0)

            # Extract latest version
            versions = ext.get('versions', [])
            latest_version = versions[0]['version'] if versions else 'unknown'
            last_updated = versions[0].get('lastUpdated', 'Unknown') if versions else 'Unknown'

            # Extract categories and tags
            categories = ext.get('categories', [])
            tags = ext.get('tags', [])

            # Publisher info
            pub_info = ext.get('publisher', {})
            publisher_display = pub_info.get('displayName', publisher)
            publisher_domain = pub_info.get('domain', '')
            publisher_verified = pub_info.get('isDomainVerified', False)

            metadata = {
                'available': True,
                'store': 'vscode',
                'identifier': f"{publisher}.{extension_name}",
                'name': ext.get('displayName', extension_name),
                'publisher': publisher_display,
                'publisher_id': pub_info.get('publisherId', ''),
                'publisher_domain': publisher_domain,
                'publisher_verified': publisher_verified,
                'short_description': ext.get('shortDescription', ''),
                'version': latest_version,
                'last_updated': last_updated,
                'categories': categories,
                'tags': tags,
                'install_count': int(stats.get('install', 0)),
                'rating_value': round(stats.get('averagerating', 0), 2),
                'rating_count': int(stats.get('ratingcount', 0)),
                'flags': ext.get('flags', ''),
                'store_url': f"https://marketplace.visualstudio.com/items?itemName={publisher}.{extension_name}",
                'risk_signals': {}
            }

            # Risk signals based on paper's Layer 1: Metadata & Publisher Analysis
            if metadata['install_count'] < 500:
                metadata['risk_signals']['low_adoption'] = True
            if not publisher_verified:
                metadata['risk_signals']['unverified_publisher'] = True
            if metadata['rating_count'] < 5:
                metadata['risk_signals']['few_ratings'] = True

            return metadata

        except requests.RequestException as e:
            return {'available': False, 'error': str(e)}

    def download_extension(self, publisher, extension_name, version=None, store='vscode'):
        """
        Download a VSIX package from the VS Marketplace or Open VSX.

        Args:
            publisher: Publisher/namespace name
            extension_name: Extension name
            version: Specific version (default: latest); ignored when store='openvsx'
            store: 'vscode' (default) or 'openvsx'

        Returns:
            Path: Path to downloaded .vsix file, or None on failure
        """
        metadata = self.fetch_metadata(publisher, extension_name, store=store)
        if not metadata.get('available'):
            print(f"[!] Could not find extension {publisher}.{extension_name} ({store})")
            return None

        version = version or metadata.get('version', 'latest')

        if store == 'openvsx':
            download_url = metadata.get('_openvsx_download_url')
            if not download_url:
                print(f"[!] No download URL for {publisher}.{extension_name} on Open VSX")
                return None
        else:
            download_url = self.VSIX_DOWNLOAD_URL.format(
                publisher=publisher,
                name=extension_name,
                version=version
            )

        vsix_filename = f"{publisher}.{extension_name}-{version}.vsix"
        vsix_path = self.download_dir / vsix_filename

        try:
            print(f"[+] Downloading {publisher}.{extension_name} v{version} ({store})...")
            print(f"    URL: {download_url}")

            resp = requests.get(
                download_url,
                headers={'User-Agent': self.headers['User-Agent']},
                timeout=60,
                stream=True
            )
            resp.raise_for_status()

            # Write to file
            total_size = 0
            with open(vsix_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        total_size += len(chunk)

            size_mb = total_size / (1024 * 1024)
            print(f"[+] Downloaded: {vsix_path} ({size_mb:.2f} MB)")
            return vsix_path

        except requests.RequestException as e:
            print(f"[!] Download failed: {e}")
            return None

    def download_by_identifier(self, identifier, store='vscode'):
        """
        Download extension by full identifier string (publisher.extensionName)
        or marketplace URL.

        Args:
            identifier: Extension identifier or marketplace URL
            store: 'vscode' (VS Marketplace) or 'openvsx' (Open VSX Registry)

        Returns:
            tuple: (vsix_path, metadata) or (None, None) on failure
        """
        parsed = self.parse_identifier(identifier)
        if not parsed:
            print(f"[!] Invalid extension identifier: {identifier}")
            print(f"    Expected format: publisher.extensionName")
            print(f"    Example: ms-python.python (VS Marketplace) or jtl.vscode-theme-seti (Open VSX)")
            return None, None

        publisher, extension_name = parsed

        # Fetch metadata first (from chosen store)
        metadata = self.fetch_metadata(publisher, extension_name, store=store)
        if not metadata.get('available'):
            print(f"[!] Extension not found: {publisher}.{extension_name} ({store})")
            return None, None

        # Download the VSIX
        vsix_path = self.download_extension(
            publisher, extension_name,
            version=metadata.get('version'),
            store=store
        )

        return vsix_path, metadata
