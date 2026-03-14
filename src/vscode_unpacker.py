"""
VSCode Extension Unpacker - Extracts and parses .vsix packages

VSIX files are standard ZIP archives containing:
  - [Content_Types].xml
  - extension.vsixmanifest (XML metadata)
  - extension/ directory with the actual extension code:
      - package.json (main metadata)
      - extension source files (.js, .ts, etc.)
      - node_modules/ (bundled dependencies)
"""

import json
import os
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


class VSCodeExtensionUnpacker:
    """Extracts and parses VSCode .vsix extension packages"""

    def __init__(self, extract_dir="data/vscode_extensions"):
        self.extract_dir = Path(extract_dir)
        self.extract_dir.mkdir(parents=True, exist_ok=True)

    def unpack(self, vsix_path):
        """
        Extract a .vsix file to the extraction directory.

        Args:
            vsix_path: Path to the .vsix file

        Returns:
            Path: Path to the extracted extension directory, or None on failure
        """
        vsix_path = Path(vsix_path)

        if not vsix_path.exists():
            print(f"[!] VSIX file not found: {vsix_path}")
            return None

        # Create output directory based on VSIX filename
        dir_name = vsix_path.stem  # e.g., "ms-python.python-2024.1.0"
        output_dir = self.extract_dir / dir_name

        try:
            # Clean up existing extraction
            if output_dir.exists():
                import shutil
                shutil.rmtree(output_dir)

            print(f"[+] Extracting VSIX: {vsix_path.name}")

            with zipfile.ZipFile(vsix_path, 'r') as zf:
                info_list = zf.infolist()
                # Check for zip bombs (total uncompressed size)
                total_size = sum(info.file_size for info in info_list)
                max_size = 500 * 1024 * 1024  # 500 MB limit
                if total_size > max_size:
                    print(f"[!] VSIX exceeds size limit ({total_size / 1024 / 1024:.1f} MB > 500 MB)")
                    return None

                file_count = sum(1 for info in info_list if not info.is_dir())
                zf.extractall(output_dir)

            # The actual extension code lives under extension/ subdirectory
            extension_subdir = output_dir / "extension"
            if extension_subdir.exists():
                print(f"[+] Extracted to: {extension_subdir}")
                print(f"    Files: {file_count}")
                return extension_subdir
            else:
                # Some VSIX packages don't use extension/ subdirectory
                print(f"[+] Extracted to: {output_dir} (flat structure)")
                return output_dir

        except zipfile.BadZipFile:
            print(f"[!] Invalid VSIX file (not a valid ZIP archive)")
            return None
        except Exception as e:
            print(f"[!] Extraction failed: {e}")
            return None

    def read_package_json(self, extension_dir):
        """
        Read and parse the package.json from an extracted extension.

        Args:
            extension_dir: Path to the extracted extension directory

        Returns:
            dict: Parsed package.json content, or None on failure
        """
        extension_dir = Path(extension_dir)
        package_json_path = extension_dir / "package.json"

        if not package_json_path.exists():
            print(f"[!] package.json not found in {extension_dir}")
            return None

        try:
            with open(package_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid package.json: {e}")
            return None

    def read_vsixmanifest(self, extraction_root):
        """
        Read and parse the extension.vsixmanifest XML file.

        Args:
            extraction_root: Root extraction directory (parent of extension/)

        Returns:
            dict: Parsed manifest data, or None
        """
        # vsixmanifest is at the root of the ZIP, not inside extension/
        root_dir = Path(extraction_root)

        # If we're given the extension/ subdir, go up one level
        if root_dir.name == "extension":
            root_dir = root_dir.parent

        manifest_path = root_dir / "extension.vsixmanifest"
        if not manifest_path.exists():
            return None

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()

            # Handle XML namespaces
            ns = ''
            if root.tag.startswith('{'):
                ns = root.tag.split('}')[0] + '}'

            metadata = {}

            # Extract Identity
            identity = root.find(f'.//{ns}Identity')
            if identity is not None:
                metadata['id'] = identity.get('Id', '')
                metadata['version'] = identity.get('Version', '')
                metadata['publisher'] = identity.get('Publisher', '')
                metadata['language'] = identity.get('Language', '')

            # Extract DisplayName
            display_name = root.find(f'.//{ns}DisplayName')
            if display_name is not None:
                metadata['display_name'] = display_name.text or ''

            # Extract Description
            description = root.find(f'.//{ns}Description')
            if description is not None:
                metadata['description'] = description.text or ''

            # Extract Tags
            tags = root.find(f'.//{ns}Tags')
            if tags is not None and tags.text:
                metadata['tags'] = [t.strip() for t in tags.text.split(',')]

            # Extract Properties
            properties = {}
            for prop in root.findall(f'.//{ns}Property'):
                prop_id = prop.get('Id', '')
                prop_value = prop.get('Value', '')
                properties[prop_id] = prop_value
            metadata['properties'] = properties

            return metadata

        except ET.ParseError as e:
            print(f"[!] Failed to parse vsixmanifest: {e}")
            return None

    def get_file_inventory(self, extension_dir):
        """
        Get a categorized inventory of all files in the extension.

        Returns:
            dict: Categorized file lists with sizes
        """
        extension_dir = Path(extension_dir)

        inventory = {
            'javascript': [],    # .js files
            'typescript': [],    # .ts files
            'json': [],          # .json files
            'webview': [],       # .html, .htm files
            'styles': [],        # .css files
            'native': [],        # .node, .dll, .so, .dylib
            'wasm': [],          # .wasm files
            'config': [],        # .yml, .yaml, .toml, .ini
            'other': [],
            'total_files': 0,
            'total_size': 0,
            'node_modules_size': 0,
            'has_node_modules': False
        }

        ext_map = {
            '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript',
            '.json': 'json',
            '.html': 'webview', '.htm': 'webview',
            '.css': 'styles',
            '.node': 'native', '.dll': 'native', '.so': 'native', '.dylib': 'native',
            '.wasm': 'wasm',
            '.yml': 'config', '.yaml': 'config', '.toml': 'config', '.ini': 'config',
        }

        # Use os.walk for fast traversal; estimate node_modules size
        # without categorizing individual files (can be thousands of entries)
        str_ext_dir = str(extension_dir)
        for dirpath, dirnames, filenames in os.walk(extension_dir):
            in_node_modules = 'node_modules' in dirpath

            # For node_modules subtree, just accumulate size quickly
            if in_node_modules:
                inventory['has_node_modules'] = True
                for fname in filenames:
                    try:
                        fsize = os.path.getsize(os.path.join(dirpath, fname))
                        inventory['node_modules_size'] += fsize
                        inventory['total_files'] += 1
                    except OSError:
                        pass
                continue

            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue

                relative = os.path.relpath(fpath, str_ext_dir)
                suffix = Path(fname).suffix.lower()

                inventory['total_files'] += 1
                inventory['total_size'] += size

                entry = {
                    'path': relative,
                    'size': size,
                    'extension': suffix
                }
                category = ext_map.get(suffix, 'other')
                inventory[category].append(entry)

        # Add node_modules size to total
        inventory['total_size'] += inventory['node_modules_size']
        return inventory

    def get_dependency_tree(self, extension_dir):
        """
        Extract dependency information from package.json.

        Returns:
            dict: Dependencies with production and dev separation
        """
        pkg = self.read_package_json(extension_dir)
        if not pkg:
            return {'dependencies': {}, 'devDependencies': {}, 'total': 0}

        deps = pkg.get('dependencies', {})
        dev_deps = pkg.get('devDependencies', {})

        return {
            'dependencies': deps,
            'devDependencies': dev_deps,
            'total': len(deps) + len(dev_deps),
            'production_count': len(deps),
            'dev_count': len(dev_deps)
        }

    def get_activation_events(self, extension_dir):
        """
        Extract activation events from package.json.
        These determine WHEN the extension loads - wildcard activation is risky.

        Returns:
            list: Activation events
        """
        pkg = self.read_package_json(extension_dir)
        if not pkg:
            return []

        # In older VS Code extensions, activationEvents is explicit
        activation_events = pkg.get('activationEvents', [])

        # In newer extensions, contributes can imply activation
        # onCommand:* is implied by contributes.commands
        contributes = pkg.get('contributes', {})
        if contributes.get('commands'):
            for cmd in contributes['commands']:
                cmd_id = cmd.get('command', '')
                if cmd_id:
                    implied = f"onCommand:{cmd_id}"
                    if implied not in activation_events:
                        activation_events.append(implied)

        return activation_events

    def get_extension_entry_points(self, extension_dir):
        """
        Identify the main entry point and any secondary entry points.

        Returns:
            dict: Entry point information
        """
        pkg = self.read_package_json(extension_dir)
        if not pkg:
            return {'main': None, 'browser': None, 'all': []}

        main = pkg.get('main', None)
        browser = pkg.get('browser', None)

        all_entries = []
        if main:
            all_entries.append({'type': 'main', 'path': main})
        if browser:
            all_entries.append({'type': 'browser', 'path': browser})

        return {
            'main': main,
            'browser': browser,
            'all': all_entries
        }
