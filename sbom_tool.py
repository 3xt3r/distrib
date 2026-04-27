#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified SBOM tool.

Subcommands:
  reorder  - reorder components in an existing CycloneDX SBOM JSON
  deb      - scan .deb packages and generate CycloneDX SBOM
  rpm      - run syft on RPM folder, enrich components and write updated SBOM
  cve-rpm  - run ALT Linux CVE scanner for CycloneDX SBOM
  binary   - unpack .deb/.rpm packages, scan Go/Rust/.NET/Java artifacts, and optionally diff source vs binary SBOM

Important:
  The deb and rpm commands automatically call reorder_components() before writing
  the final SBOM file.

  Compatibility aliases:
    --rpm is accepted as an alias for the rpm mode and automatically runs
    the bundled ALT Linux CVE scanner after updated_sbom.json is written.

    --binary is accepted as an alias for the binary mode.

    --cve-rpm is accepted as an alias for the cve-rpm subcommand when used
    as the first argument. Inside the rpm command, --cve-rpm can still be
    used to pass raw arguments to the CVE scanner.
"""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# Common / reorder logic
# =============================================================================

ECOSYSTEM_ORDER = [
    "rpm",
    "deb",
    "apk",
    "npm",
    "pypi",
    "maven",
    "golang",
    "composer",
    "gem",
    "nuget",
    "cargo",
    "cocoapods",
    "generic",
    "unknown",
]


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().lower()


def make_output_path(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.stem}_reordered{input_path.suffix}")


def has_gost_provided_by(component: Dict[str, Any]) -> bool:
    properties = component.get("properties", [])
    if not isinstance(properties, list):
        return False

    for prop in properties:
        if isinstance(prop, dict) and prop.get("name") == "GOST:provided_by":
            return True

    return False


def get_property(component: Dict[str, Any], prop_name: str) -> Optional[Any]:
    properties = component.get("properties", [])
    if not isinstance(properties, list):
        return None

    for prop in properties:
        if isinstance(prop, dict) and prop.get("name") == prop_name:
            return prop.get("value")

    return None


def ecosystem_from_purl(purl: Any) -> Optional[str]:
    """
    Extract ecosystem from Package URL, for example:
      pkg:rpm/zip@3.0-alt5?... -> rpm
      pkg:npm/lodash@4.17.21 -> npm
    """
    if not isinstance(purl, str):
        return None

    match = re.match(r"^pkg:([^/]+)/", purl)
    if match:
        return match.group(1).lower()

    return None


def normalize_ecosystem(value: Any) -> str:
    if not value:
        return "unknown"

    value = str(value).strip().lower()

    mapping = {
        "rpm": "rpm",
        "deb": "deb",
        "dpkg": "deb",
        "apk": "apk",
        "npm": "npm",
        "pypi": "pypi",
        "python": "pypi",
        "pip": "pypi",
        "maven": "maven",
        "golang": "golang",
        "go-module": "golang",
        "go": "golang",
        "composer": "composer",
        "gem": "gem",
        "rubygems": "gem",
        "nuget": "nuget",
        "cargo": "cargo",
        "crate": "cargo",
        "cocoapods": "cocoapods",
        "generic": "generic",
    }

    return mapping.get(value, value)


def detect_ecosystem(component: Dict[str, Any]) -> str:
    # 1. First try purl.
    ecosystem = ecosystem_from_purl(component.get("purl"))
    if ecosystem:
        return normalize_ecosystem(ecosystem)

    # 2. Then syft:package:type.
    ecosystem = get_property(component, "syft:package:type")
    if ecosystem:
        return normalize_ecosystem(ecosystem)

    # 3. Then CycloneDX type field.
    ecosystem = component.get("type")
    if ecosystem:
        return normalize_ecosystem(ecosystem)

    return "unknown"


def ecosystem_rank(ecosystem: str) -> int:
    try:
        return ECOSYSTEM_ORDER.index(ecosystem)
    except ValueError:
        return len(ECOSYSTEM_ORDER)


def component_sort_key(component: Dict[str, Any]) -> Tuple[int, str, str, str, str]:
    ecosystem = detect_ecosystem(component)
    name = str(component.get("name", "")).lower()
    version = str(component.get("version", "")).lower()
    bom_ref = str(component.get("bom-ref", "")).lower()

    return (
        ecosystem_rank(ecosystem),
        ecosystem,
        name,
        version,
        bom_ref,
    )


def reorder_components(sbom: Dict[str, Any]) -> Dict[str, Any]:
    components = sbom.get("components")

    if not isinstance(components, list):
        raise ValueError("В JSON нет массива 'components'")

    without_gost: List[Dict[str, Any]] = []
    with_gost: List[Dict[str, Any]] = []
    other_items: List[Any] = []

    for component in components:
        if not isinstance(component, dict):
            other_items.append(component)
            continue

        if has_gost_provided_by(component):
            with_gost.append(component)
        else:
            without_gost.append(component)

    without_gost_sorted = sorted(without_gost, key=component_sort_key)
    with_gost_sorted = sorted(with_gost, key=component_sort_key)

    # Keep non-dict component entries at the end instead of failing unexpectedly.
    sbom["components"] = without_gost_sorted + with_gost_sorted + other_items
    return sbom


def cmd_reorder(args: argparse.Namespace) -> int:
    input_path = Path(args.input_json)

    if not input_path.exists():
        print(f"Файл не найден: {input_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output).resolve() if args.output else make_output_path(input_path)

    try:
        with input_path.open("r", encoding="utf-8") as f:
            sbom = json.load(f)

        sbom = reorder_components(sbom)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(sbom, f, ensure_ascii=False, indent=2)

        print(f"Готово. Результат сохранён в: {output_path}")
        return 0

    except json.JSONDecodeError as e:
        print(f"Ошибка JSON: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1


# =============================================================================
# DEB to CycloneDX
# =============================================================================

AR_MAGIC = b"!<arch>\n"
CONTROL_CANDIDATES = ("control", "./control", ".//control")


@dataclass
class DebPackage:
    file_path: Path
    package: str
    version: str
    architecture: str = ""
    maintainer: str = ""
    description: str = ""
    homepage: str = ""
    source: str = ""
    depends_raw: str = ""
    pre_depends_raw: str = ""
    section: str = ""
    priority: str = ""
    sha256: str = ""
    bom_ref: str = ""
    purl: str = ""
    internal_depends_on: List[str] = field(default_factory=list)
    provided_by: str = ""


@dataclass(frozen=True)
class ListedPackage:
    original_line: str
    package: str
    version: str


def unique_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            out.append(item)
            seen.add(item)
    return out


def read_ar_members(path: Path) -> Dict[str, bytes]:
    data = path.read_bytes()
    if not data.startswith(AR_MAGIC):
        raise ValueError(f"{path} is not a valid .deb archive")

    pos = len(AR_MAGIC)
    members: Dict[str, bytes] = {}

    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        pos += 60

        name = header[0:16].decode("utf-8", errors="ignore").strip().rstrip("/")
        size_raw = header[48:58].decode("utf-8", errors="ignore").strip()
        end = header[58:60]

        if end != b"`\n":
            raise ValueError(f"{path}: invalid ar member header")

        size = int(size_raw)
        payload = data[pos:pos + size]
        pos += size
        if pos % 2 == 1:
            pos += 1

        members[name] = payload

    return members


def decompress_control_tar(name: str, payload: bytes) -> bytes:
    lower = name.lower()

    if lower.endswith(".gz"):
        import gzip
        return gzip.decompress(payload)

    if lower.endswith(".xz"):
        import lzma
        return lzma.decompress(payload)

    if lower.endswith(".bz2"):
        import bz2
        return bz2.decompress(payload)

    if lower.endswith(".zst") or lower.endswith(".zstd"):
        try:
            import zstandard as zstd  # type: ignore
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(payload)
        except Exception:
            pass

        for bin_name in ("zstd", "unzstd"):
            try:
                proc = subprocess.run(
                    [bin_name, "-d", "-c"],
                    input=payload,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if proc.returncode == 0:
                    return proc.stdout
            except FileNotFoundError:
                continue

        raise RuntimeError(
            "control.tar.zst found, but neither 'zstandard' nor 'zstd/unzstd' is available"
        )

    if lower.endswith(".tar"):
        return payload

    raise ValueError(f"Unsupported control archive format: {name}")


def extract_control_text_from_deb(path: Path) -> str:
    members = read_ar_members(path)

    control_member_name = ""
    for name in members:
        if name.startswith("control.tar"):
            control_member_name = name
            break

    if not control_member_name:
        raise ValueError(f"{path}: control.tar.* not found")

    control_tar_raw = decompress_control_tar(
        control_member_name, members[control_member_name]
    )

    with tarfile.open(fileobj=io.BytesIO(control_tar_raw), mode="r:") as tf:
        control_member = None

        for member in tf.getmembers():
            candidate = member.name.strip()
            if candidate in CONTROL_CANDIDATES or candidate.endswith("/control"):
                control_member = member
                break

        if control_member is None:
            for member in tf.getmembers():
                if member.name.endswith("control"):
                    control_member = member
                    break

        if control_member is None:
            raise ValueError(f"{path}: control file not found inside {control_member_name}")

        extracted = tf.extractfile(control_member)
        if extracted is None:
            raise ValueError(f"{path}: failed to extract control file")

        return extracted.read().decode("utf-8", errors="replace")


def parse_debian_control(text: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    current_key = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")

        if not line:
            continue

        if line[0].isspace():
            if current_key:
                fields[current_key] = fields.get(current_key, "") + "\n" + line.strip()
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        fields[key] = value
        current_key = key

    return fields


_DEP_SPLIT_COMMA_RE = re.compile(r"\s*,\s*")
_DEP_SPLIT_ALT_RE = re.compile(r"\s*\|\s*")
_DEP_CLEAN_RE = re.compile(r"\s*\(.*?\)")
_DEP_ARCH_RE = re.compile(r"\[.*?\]")
_DEP_PROFILE_RE = re.compile(r"<.*?>")


def parse_dependency_names(depends_text: str) -> List[str]:
    if not depends_text.strip():
        return []

    result: List[str] = []

    for group in _DEP_SPLIT_COMMA_RE.split(depends_text.strip()):
        if not group:
            continue

        alternatives = _DEP_SPLIT_ALT_RE.split(group)
        for alt in alternatives:
            dep = alt.strip()
            dep = _DEP_CLEAN_RE.sub("", dep)
            dep = _DEP_ARCH_RE.sub("", dep)
            dep = _DEP_PROFILE_RE.sub("", dep)
            dep = dep.strip()

            if ":" in dep:
                dep = dep.split(":", 1)[0].strip()

            if dep:
                result.append(dep)

    return unique_preserve_order(result)


def normalize_version_for_match(version: str) -> str:
    version = version.strip()

    while True:
        new_version = re.sub(r"(?:\+ci\d+|\+b\d+)$", "", version, flags=re.IGNORECASE)
        if new_version == version:
            break
        version = new_version

    return version


def simplify_component_version(version: str) -> str:
    version = version.strip()

    if ":" in version:
        version = version.split(":", 1)[1]

    version = version.split("~", 1)[0]
    version = version.split("-", 1)[0]

    return version or "0"


def make_bom_ref(pkg: DebPackage) -> str:
    return f"pkg:deb/{pkg.package}@{pkg.version}?arch={pkg.architecture or 'unknown'}"


def make_purl(pkg: DebPackage) -> str:
    qualifiers = []
    if pkg.architecture:
        qualifiers.append(f"arch={pkg.architecture}")
    q = f"?{'&'.join(qualifiers)}" if qualifiers else ""
    return f"pkg:deb/{pkg.package}@{pkg.version}{q}"


def read_deb_metadata(path: Path) -> DebPackage:
    control_text = extract_control_text_from_deb(path)
    fields = parse_debian_control(control_text)

    package = fields.get("Package", "").strip()
    version = fields.get("Version", "").strip()

    if not package or not version:
        raise ValueError(f"{path}: Package/Version not found in control")

    pkg = DebPackage(
        file_path=path,
        package=package,
        version=version,
        architecture=fields.get("Architecture", "").strip(),
        maintainer=fields.get("Maintainer", "").strip(),
        description=fields.get("Description", "").strip(),
        homepage=fields.get("Homepage", "").strip(),
        source=fields.get("Source", "").strip(),
        depends_raw=fields.get("Depends", "").strip(),
        pre_depends_raw=fields.get("Pre-Depends", "").strip(),
        section=fields.get("Section", "").strip(),
        priority=fields.get("Priority", "").strip(),
        sha256=sha256_file(path),
        bom_ref="",
        purl="",
    )
    pkg.bom_ref = make_bom_ref(pkg)
    pkg.purl = make_purl(pkg)
    return pkg


def dedupe_packages_by_bom_ref(packages: List[DebPackage]) -> List[DebPackage]:
    by_ref: Dict[str, DebPackage] = {}
    for pkg in packages:
        if pkg.bom_ref not in by_ref:
            by_ref[pkg.bom_ref] = pkg
    return list(by_ref.values())


def parse_package_version_line(line: str) -> ListedPackage:
    cleaned = line.split("#", 1)[0].strip()
    if not cleaned:
        raise ValueError("empty")

    filename = Path(cleaned).name
    match = re.match(r"^(?P<name>[^_]+)_(?P<version>[^_]+)_[^_]+\.deb$", filename)
    if not match:
        raise ValueError(
            f"unsupported format: {line!r}. Expected Debian filename like 'name_version_arch.deb'"
        )

    return ListedPackage(
        original_line=cleaned,
        package=match.group("name").strip().lower(),
        version=match.group("version").strip(),
    )


def load_listed_packages(path: Path) -> List[ListedPackage]:
    listed_packages: List[ListedPackage] = []

    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.split("#", 1)[0].strip()
        if not stripped:
            continue

        try:
            listed_packages.append(parse_package_version_line(stripped))
        except ValueError as e:
            raise ValueError(f"{path}:{lineno}: {e}") from e

    return listed_packages


def extract_version_from_deb_filename(filename: str) -> str:
    match = re.match(r"^[^_]+_([^_]+)_[^_]+\.deb$", filename)
    if not match:
        return ""
    return match.group(1).strip()


def package_matches_list_entry(pkg: DebPackage, entry: ListedPackage) -> bool:
    if pkg.package.lower() != entry.package:
        return False

    pkg_versions = {
        pkg.version,
        normalize_version_for_match(pkg.version),
    }

    file_version = extract_version_from_deb_filename(pkg.file_path.name)
    if file_version:
        pkg_versions.add(file_version)
        pkg_versions.add(normalize_version_for_match(file_version))

    entry_versions = {
        entry.version,
        normalize_version_for_match(entry.version),
    }

    return bool(pkg_versions & entry_versions)


def is_listed_in_txt(pkg: DebPackage, listed_packages: List[ListedPackage]) -> bool:
    for entry in listed_packages:
        if package_matches_list_entry(pkg, entry):
            return True
    return False


def component_properties(pkg: DebPackage) -> List[dict]:
    properties = [
        {"name": "GOST:attack_surface", "value": "no"},
        {"name": "GOST:security_function", "value": "no"},
        {"name": "deb:filename", "value": pkg.file_path.name},
    ]

    if pkg.provided_by:
        properties.append({"name": "GOST:provided_by", "value": pkg.provided_by})

    return properties


def component_from_pkg(pkg: DebPackage) -> dict:
    properties = component_properties(pkg)

    if not pkg.provided_by:
        return {
            "type": "library",
            "name": pkg.package,
            "version": simplify_component_version(pkg.version),
            "externalReferences": [
                {
                    "type": "vcs",
                    "url": "",
                }
            ],
            "properties": properties,
        }

    external_refs = [
        {
            "type": "distribution",
            "url": pkg.file_path.resolve().as_uri(),
        }
    ]

    if pkg.homepage:
        external_refs.append({"type": "website", "url": pkg.homepage})

    component = {
        "type": "library",
        "bom-ref": pkg.bom_ref,
        "name": pkg.package,
        "version": pkg.version,
        "purl": pkg.purl,
        "hashes": [{"alg": "SHA-256", "content": pkg.sha256}],
        "properties": properties,
        "externalReferences": external_refs,
    }

    return component


def dependency_entries(packages: List[DebPackage]) -> List[dict]:
    valid_refs = {pkg.bom_ref for pkg in packages if pkg.provided_by}
    merged: Dict[str, List[str]] = {}

    for pkg in packages:
        if not pkg.provided_by:
            continue

        merged.setdefault(pkg.bom_ref, [])
        filtered_deps = [dep for dep in pkg.internal_depends_on if dep in valid_refs]
        merged[pkg.bom_ref].extend(filtered_deps)

    entries = []
    for ref in sorted(merged.keys()):
        unique_deps = unique_preserve_order(merged[ref])
        unique_deps = [x for x in unique_deps if x != ref]
        entries.append(
            {
                "ref": ref,
                "dependsOn": unique_deps,
            }
        )

    return entries


def build_sbom(packages: List[DebPackage], sbom_name: str, with_dependencies: bool = False) -> dict:
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "deb_to_cyclonedx",
                        "version": "1.0.1",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": sbom_name,
                "version": "1",
            },
        },
        "components": [component_from_pkg(pkg) for pkg in packages],
    }

    if with_dependencies:
        sbom["dependencies"] = dependency_entries(packages)

    return sbom


def build_internal_dependencies(packages: List[DebPackage]) -> None:
    by_name: Dict[str, DebPackage] = {}
    for pkg in packages:
        if pkg.package not in by_name:
            by_name[pkg.package] = pkg

    for pkg in packages:
        dep_names = parse_dependency_names(pkg.depends_raw) + parse_dependency_names(
            pkg.pre_depends_raw
        )
        dep_names = unique_preserve_order(dep_names)

        internal_refs: List[str] = []
        for dep_name in dep_names:
            dep_pkg = by_name.get(dep_name)
            if dep_pkg:
                internal_refs.append(dep_pkg.bom_ref)

        pkg.internal_depends_on = unique_preserve_order(internal_refs)


def scan_deb_folder(folder: Path, with_dependencies: bool = False) -> Tuple[List[DebPackage], List[dict]]:
    packages: List[DebPackage] = []
    errors: List[dict] = []

    deb_files = sorted(folder.rglob("*.deb"))

    for deb_path in deb_files:
        try:
            pkg = read_deb_metadata(deb_path)
            packages.append(pkg)
        except Exception as e:
            errors.append(
                {
                    "file": str(deb_path),
                    "error": str(e),
                }
            )

    packages = dedupe_packages_by_bom_ref(packages)

    if with_dependencies:
        build_internal_dependencies(packages)

    return packages, errors


def apply_provided_by_rules(
    packages: List[DebPackage], listed_packages: List[ListedPackage]
) -> Tuple[int, List[DebPackage]]:
    matched_packages: List[DebPackage] = []

    for pkg in packages:
        if listed_packages and is_listed_in_txt(pkg, listed_packages):
            matched_packages.append(pkg)
        elif listed_packages:
            pkg.provided_by = "Astra Linux"

    return len(matched_packages), matched_packages


def find_unmatched_txt_entries(
    matched_packages: List[DebPackage], listed_packages: List[ListedPackage]
) -> List[ListedPackage]:
    unmatched_entries: List[ListedPackage] = []

    for entry in listed_packages:
        found = False
        for pkg in matched_packages:
            if package_matches_list_entry(pkg, entry):
                found = True
                break
        if not found:
            unmatched_entries.append(entry)

    return unmatched_entries


def cmd_deb(args: argparse.Namespace) -> int:
    folder = Path(args.folder).resolve()
    if not folder.is_dir():
        print(f"Folder not found: {folder}", file=sys.stderr)
        return 1

    listed_packages: List[ListedPackage] = []
    if args.package_list:
        list_path = Path(args.package_list).resolve()
        if not list_path.is_file():
            print(f"TXT file not found: {list_path}", file=sys.stderr)
            return 1
        try:
            listed_packages = load_listed_packages(list_path)
        except Exception as e:
            print(f"Failed to read TXT file: {e}", file=sys.stderr)
            return 1

    packages, errors = scan_deb_folder(folder, with_dependencies=args.with_dependencies)
    matched_count, matched_packages = apply_provided_by_rules(packages, listed_packages)
    unmatched_txt_entries = find_unmatched_txt_entries(matched_packages, listed_packages)

    out_path = Path(args.output).resolve()
    sbom = build_sbom(packages, sbom_name=folder.name, with_dependencies=args.with_dependencies)

    # Auto reorder before writing final SBOM.
    sbom = reorder_components(sbom)

    out_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"SBOM written: {out_path}")
    print(f"Packages included: {len(packages)}")
    print(f"Dependencies included: {'yes' if args.with_dependencies else 'no'}")
    print("Reorder applied: yes")

    merge_whl_into_sbom(sbom, folder, out_path)

    if listed_packages:
        astra_count = sum(1 for p in packages if p.provided_by == "Astra Linux")

        print(f"Packages matched with TXT: {matched_count}")
        print(f"Packages marked with GOST:provided_by=Astra Linux: {astra_count}")

        if matched_packages:
            print("Packages NOT marked as GOST:provided_by=Astra Linux:")
            for pkg in sorted(matched_packages, key=lambda x: (x.package.lower(), x.version)):
                print(f"  {pkg.package} {pkg.version} ({pkg.file_path.name})")

        print(f"TXT entries not found among packages without GOST:provided_by: {len(unmatched_txt_entries)}")
        if unmatched_txt_entries:
            print("TXT packages that did NOT get into final list without GOST:provided_by:")
            for entry in unmatched_txt_entries:
                print(f"  {entry.original_line}")

    if errors:
        err_path = Path(args.errors_output).resolve()
        err_path.parent.mkdir(parents=True, exist_ok=True)
        err_path.write_text(json.dumps(errors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Errors written: {err_path}")
        print(f"Packages with errors: {len(errors)}")

    return 0


# =============================================================================
# RPM Syft enrichment
# =============================================================================

GOST_PROVIDED_BY_NAME = "GOST:provided_by"
GOST_PROVIDED_BY_VALUE = "Alt Linux"

DEFAULT_PROPERTIES = [
    {"name": "GOST:attack_surface", "value": "no"},
    {"name": "GOST:security_function", "value": "no"},
]

REPORT_FILE_DEFAULT = "debug/report.txt"
UPDATED_SBOM_FILE_DEFAULT = "alt.json"


def run_cmd(cmd: List[str], env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def run_syft(scan_target: Path, env: Dict[str, str]) -> Dict[str, Any]:
    result = run_cmd(["syft", str(scan_target), "-o", "cyclonedx-json"], env=env)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "syft failed")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"failed to parse syft output: {e}") from e


def rpm_query_buildhost(path: Path) -> Dict[str, str]:
    result = run_cmd(
        [
            "rpm",
            "-qp",
            "--queryformat",
            r"%{BUILDHOST}\n",
            "--nosignature",
            "--nodigest",
            str(path),
        ]
    )

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode != 0:
        return {
            "ok": "false",
            "error": stderr or f"rpm exited with code {result.returncode}",
            "buildhost": "",
        }

    buildhost = "" if stdout == "(none)" else stdout.strip()
    return {
        "ok": "true",
        "error": "",
        "buildhost": buildhost,
    }


def query_rpm_info(rpm_path: Path) -> Optional[Dict[str, str]]:
    query_format = r"%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"

    try:
        proc = subprocess.run(
            ["rpm", "-qp", "--queryformat", query_format, str(rpm_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("command 'rpm' not found in system")

    if proc.returncode != 0:
        return None

    line = proc.stdout.strip()
    if not line:
        return None

    parts = line.split("\t")
    if len(parts) != 5:
        return None

    name, epoch, version, release, arch = parts

    if epoch == "(none)":
        epoch = ""

    version_release = version
    if release:
        version_release = f"{version}-{release}"

    return {
        "name": name,
        "epoch": epoch,
        "version": version,
        "release": release,
        "version_release": version_release,
        "arch": arch,
        "path": str(rpm_path),
        "filename": rpm_path.name,
    }


def ensure_properties(comp: Dict[str, Any]) -> List[Dict[str, str]]:
    props = comp.get("properties")
    if not isinstance(props, list):
        props = []
        comp["properties"] = props
    return props


def upsert_property(comp: Dict[str, Any], name: str, value: str) -> None:
    value = str(value or "").strip()
    if not value:
        return

    props = ensure_properties(comp)
    for item in props:
        if isinstance(item, dict) and item.get("name") == name:
            item["value"] = value
            return

    props.append({"name": name, "value": value})


def remove_property(comp: Dict[str, Any], name: str) -> int:
    props = comp.get("properties")
    if not isinstance(props, list):
        return 0

    before = len(props)
    comp["properties"] = [
        p for p in props
        if not (isinstance(p, dict) and str(p.get("name") or "").strip() == name)
    ]
    return before - len(comp["properties"])


def remove_properties_from_all_components(data: Dict[str, Any], names: List[str]) -> int:
    removed = 0
    components = data.get("components")
    if not isinstance(components, list):
        return removed

    for comp in components:
        if not isinstance(comp, dict):
            continue
        for name in names:
            removed += remove_property(comp, name)

    return removed


def has_property_value(comp: Dict[str, Any], name: str, expected: str) -> bool:
    props = comp.get("properties")
    if not isinstance(props, list):
        return False

    expected = str(expected or "").strip()
    for item in props:
        if not isinstance(item, dict):
            continue
        if str(item.get("name") or "").strip() != name:
            continue
        if str(item.get("value") or "").strip() == expected:
            return True
    return False


def get_property_values(comp: Dict[str, Any], name: str) -> List[str]:
    result: List[str] = []
    props = comp.get("properties")
    if not isinstance(props, list):
        return result

    for item in props:
        if not isinstance(item, dict):
            continue
        if str(item.get("name") or "").strip() != name:
            continue
        value = str(item.get("value") or "").strip()
        if value:
            result.append(value)

    return result


def get_rpm_sha256_property(comp: Dict[str, Any]) -> str:
    for value in get_property_values(comp, "rpm:sha256"):
        value = value.strip().lower()
        if value:
            return value
    return ""


def get_properties_map(component: Dict[str, Any]) -> Dict[str, Any]:
    result = {}
    for item in component.get("properties", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value")
        if name is not None:
            result[name] = value
    return result


def has_property(component: Dict[str, Any], property_name: str) -> bool:
    for item in component.get("properties", []):
        if isinstance(item, dict) and item.get("name") == property_name:
            return True
    return False


def add_property_if_missing(component: Dict[str, Any], property_name: str, property_value: str) -> bool:
    if has_property(component, property_name):
        return False

    props = ensure_properties(component)
    props.append({
        "name": property_name,
        "value": property_value,
    })
    return True


def find_rpm_files(root: Path) -> List[Path]:
    return sorted(p for p in root.rglob("*.rpm") if p.is_file())


def norm_path_parts(path_str: str) -> List[str]:
    s = str(path_str or "").strip().replace("\\", "/").strip("/")
    if not s:
        return []
    return [part for part in s.split("/") if part]


def common_suffix_len(a: List[str], b: List[str]) -> int:
    n = 0
    for x, y in zip(reversed(a), reversed(b)):
        if x != y:
            break
        n += 1
    return n


def build_component_locations(cdx: Dict[str, Any]) -> List[Tuple[List[str], Dict[str, Any], str]]:
    result: List[Tuple[List[str], Dict[str, Any], str]] = []

    components = cdx.get("components")
    if not isinstance(components, list):
        return result

    for comp in components:
        if not isinstance(comp, dict):
            continue

        if not has_property_value(comp, "syft:package:type", "rpm"):
            continue

        props = comp.get("properties")
        if not isinstance(props, list):
            continue

        for prop in props:
            if not isinstance(prop, dict):
                continue

            name = str(prop.get("name") or "").strip()
            value = str(prop.get("value") or "").strip()

            if name.startswith("syft:location:") and name.endswith(":path") and value:
                parts = norm_path_parts(value)
                if parts:
                    result.append((parts, comp, value))

    return result


def find_component_by_path_suffix(
    rpm_file: Path,
    component_locations: List[Tuple[List[str], Dict[str, Any], str]],
) -> Tuple[Optional[Dict[str, Any]], str, int]:
    file_parts = norm_path_parts(str(rpm_file.resolve()))
    if not file_parts:
        return None, "", 0

    best_comp: Optional[Dict[str, Any]] = None
    best_raw_path = ""
    best_score = 0

    for loc_parts, comp, raw_path in component_locations:
        score = common_suffix_len(file_parts, loc_parts)
        if score < 1:
            continue

        if score > best_score:
            best_score = score
            best_comp = comp
            best_raw_path = raw_path

    return best_comp, best_raw_path, best_score


def build_component_sha_index(cdx: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    index: Dict[str, List[Dict[str, Any]]] = {}

    components = cdx.get("components")
    if not isinstance(components, list):
        return index

    for comp in components:
        if not isinstance(comp, dict):
            continue

        if not has_property_value(comp, "syft:package:type", "rpm"):
            continue

        sha256 = get_rpm_sha256_property(comp)
        if not sha256:
            continue

        index.setdefault(sha256, []).append(comp)

    return index


def enrich_scan_target_components(
    cdx: Dict[str, Any],
    scan_target: Path,
    debug: bool = False,
) -> Dict[str, int]:
    rpm_files = find_rpm_files(scan_target)
    if not rpm_files:
        raise RuntimeError("no .rpm files found in scan_target")

    component_locations = build_component_locations(cdx)

    stats = {
        "scan_rpm_total": 0,
        "scan_matched_by_syft_location_suffix": 0,
        "scan_unmatched": 0,
        "scan_buildhost_empty": 0,
        "scan_rpm_query_errors": 0,
    }

    for rpm_file in rpm_files:
        stats["scan_rpm_total"] += 1

        matched_comp, matched_path, matched_score = find_component_by_path_suffix(rpm_file, component_locations)
        if matched_comp is None:
            stats["scan_unmatched"] += 1
            if debug:
                print(f"scan unmatched: {rpm_file}", file=sys.stderr)
            continue

        rpm_sha256 = sha256_file(rpm_file)
        upsert_property(matched_comp, "rpm:sha256", rpm_sha256)

        buildhost_info = rpm_query_buildhost(rpm_file)
        if buildhost_info.get("ok") != "true":
            stats["scan_rpm_query_errors"] += 1
            if debug:
                print(
                    f"scan buildhost query error: {rpm_file}: {buildhost_info.get('error', '')}",
                    file=sys.stderr,
                )
        else:
            buildhost = buildhost_info.get("buildhost", "")
            if buildhost:
                upsert_property(matched_comp, "rpm:buildhost", buildhost)
            else:
                stats["scan_buildhost_empty"] += 1

        stats["scan_matched_by_syft_location_suffix"] += 1
        if debug:
            print(
                f"scan matched: {rpm_file} -> {matched_path} (suffix_parts={matched_score})",
                file=sys.stderr,
            )

    return stats


def compare_with_other_root(
    cdx: Dict[str, Any],
    compare_root: Path,
    debug: bool = False,
) -> Dict[str, int]:
    rpm_files = find_rpm_files(compare_root)
    if not rpm_files:
        raise RuntimeError("no .rpm files found under compare root")

    components = cdx.get("components")
    if isinstance(components, list):
        for comp in components:
            if not isinstance(comp, dict):
                continue
            if has_property_value(comp, "syft:package:type", "rpm"):
                remove_property(comp, GOST_PROVIDED_BY_NAME)

    sha_index = build_component_sha_index(cdx)

    stats = {
        "compare_rpm_total": 0,
        "compare_matched_by_sha256": 0,
        "compare_unmatched": 0,
        "compare_buildhost_empty": 0,
        "compare_rpm_query_errors": 0,
    }

    for rpm_file in rpm_files:
        stats["compare_rpm_total"] += 1

        rpm_sha256 = sha256_file(rpm_file)
        matched_components = sha_index.get(rpm_sha256, [])

        if not matched_components:
            stats["compare_unmatched"] += 1
            if debug:
                print(f"compare unmatched: {rpm_file} sha256={rpm_sha256}", file=sys.stderr)
            continue

        buildhost_info = rpm_query_buildhost(rpm_file)
        if buildhost_info.get("ok") != "true":
            stats["compare_rpm_query_errors"] += 1
            if debug:
                print(
                    f"compare buildhost query error: {rpm_file}: {buildhost_info.get('error', '')}",
                    file=sys.stderr,
                )
            buildhost = ""
        else:
            buildhost = buildhost_info.get("buildhost", "")
            if not buildhost:
                stats["compare_buildhost_empty"] += 1

        for comp in matched_components:
            upsert_property(comp, GOST_PROVIDED_BY_NAME, GOST_PROVIDED_BY_VALUE)
            if buildhost:
                upsert_property(comp, "rpm:buildhost", buildhost)

        stats["compare_matched_by_sha256"] += 1

        if debug:
            msg = f"compare matched: {rpm_file} sha256={rpm_sha256} components={len(matched_components)}"
            if buildhost:
                msg += f" buildhost={buildhost}"
            print(msg, file=sys.stderr)

    return stats


def add_default_properties_to_all_components(sbom: Dict[str, Any]) -> int:
    added_count = 0

    for comp in sbom.get("components", []):
        if not isinstance(comp, dict):
            continue

        for prop in DEFAULT_PROPERTIES:
            if add_property_if_missing(comp, prop["name"], prop["value"]):
                added_count += 1

    return added_count


def normalize_sbom_version(version: str) -> str:
    if not version:
        return ""
    if ":" in version:
        return version.split(":", 1)[1]
    return version


def extract_filtered_sbom_components(sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = []

    for comp in sbom.get("components", []):
        if not isinstance(comp, dict):
            continue

        name = comp.get("name")
        if not name:
            continue

        props = get_properties_map(comp)
        buildhost = props.get("rpm:buildhost", "")

        if not isinstance(buildhost, str) or not buildhost.endswith(".altlinux.org"):
            continue

        if GOST_PROVIDED_BY_NAME in props:
            continue

        result.append({
            "component": comp,
            "name": name,
            "version_raw": comp.get("version", ""),
            "version_norm": normalize_sbom_version(comp.get("version", "")),
            "bom_ref": comp.get("bom-ref", ""),
            "buildhost": buildhost,
        })

    return result


def index_disk_rpms(rpm_files: List[Path]) -> Dict[str, List[Dict[str, str]]]:
    index: Dict[str, List[Dict[str, str]]] = {}

    for rpm_path in rpm_files:
        info = query_rpm_info(rpm_path)
        if not info:
            continue
        index.setdefault(info["name"], []).append(info)

    return index


def compare_components(
    sbom_components: List[Dict[str, Any]],
    disk_index: Dict[str, List[Dict[str, str]]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    version_mismatches = []
    missing_on_disk = []

    for comp in sbom_components:
        name = comp["name"]
        sbom_ver = comp["version_norm"]
        disk_variants = disk_index.get(name, [])

        if not disk_variants:
            missing_on_disk.append({
                "name": name,
                "sbom_version_norm": sbom_ver,
            })
            continue

        disk_versions = sorted({pkg["version_release"] for pkg in disk_variants})

        if sbom_ver in disk_versions:
            continue

        version_mismatches.append({
            "name": name,
            "sbom_version_norm": sbom_ver,
            "disk_versions": disk_versions,
        })

    return version_mismatches, missing_on_disk


def add_provided_by_for_found_components(
    sbom_components: List[Dict[str, Any]],
    disk_index: Dict[str, List[Dict[str, str]]],
) -> int:
    changed = 0

    for item in sbom_components:
        name = item["name"]
        component = item["component"]

        if name in disk_index and disk_index[name]:
            if add_property_if_missing(component, GOST_PROVIDED_BY_NAME, GOST_PROVIDED_BY_VALUE):
                changed += 1

    return changed


def write_report(
    version_mismatches: List[Dict[str, Any]],
    missing_on_disk: List[Dict[str, Any]],
    output_file: Path,
) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        if not version_mismatches and not missing_on_disk:
            f.write("Проблем не найдено.\n")
            return

        for item in sorted(version_mismatches, key=lambda x: x["name"]):
            name = item["name"]
            sbom_ver = item["sbom_version_norm"]
            disk_versions = ", ".join(item["disk_versions"])
            f.write(f"{name}: SBOM={sbom_ver} | DISK={disk_versions}\n")

        if missing_on_disk:
            if version_mismatches:
                f.write("\n")
            f.write("Нет на диске:\n")
            for item in sorted(missing_on_disk, key=lambda x: x["name"]):
                f.write(f"- {item['name']}\n")


def is_rpm_component(comp: Dict[str, Any]) -> bool:
    return has_property_value(comp, "syft:package:type", "rpm")


def get_syft_location_paths(comp: Dict[str, Any]) -> List[str]:
    result: List[str] = []

    props = comp.get("properties")
    if not isinstance(props, list):
        return result

    for prop in props:
        if not isinstance(prop, dict):
            continue

        name = str(prop.get("name") or "").strip()
        value = str(prop.get("value") or "").strip()

        if name.startswith("syft:location:") and name.endswith(":path") and value:
            result.append(value)

    return result


def path_to_file_uri(path_str: str) -> str:
    if not path_str:
        return ""

    try:
        return Path(path_str).resolve().as_uri()
    except Exception:
        return ""


def ensure_external_references_list(comp: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = comp.get("externalReferences")
    if not isinstance(refs, list):
        refs = []
        comp["externalReferences"] = refs
    return refs


def upsert_external_reference(comp: Dict[str, Any], ref_type: str, url: str) -> bool:
    if not ref_type:
        return False

    refs = ensure_external_references_list(comp)

    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if str(ref.get("type") or "").strip() == ref_type and str(ref.get("url") or "").strip() == url:
            return False

    refs.append({"type": ref_type, "url": url})
    return True


def set_unidentified_vcs_reference(comp: Dict[str, Any]) -> bool:
    current = comp.get("externalReferences")
    desired = [{"type": "vcs", "url": ""}]

    if current == desired:
        return False

    comp["externalReferences"] = desired
    return True


def apply_component_reference_policy(cdx: Dict[str, Any]) -> Dict[str, int]:
    stats = {
        "rpm_components_total": 0,
        "identified_distribution_refs_added": 0,
        "identified_distribution_refs_missing_path": 0,
        "unidentified_vcs_placeholders_set": 0,
    }

    components = cdx.get("components")
    if not isinstance(components, list):
        return stats

    for comp in components:
        if not isinstance(comp, dict):
            continue
        if not is_rpm_component(comp):
            continue

        stats["rpm_components_total"] += 1

        props = get_properties_map(comp)
        has_provided_by = GOST_PROVIDED_BY_NAME in props

        if has_provided_by:
            location_paths = get_syft_location_paths(comp)
            distribution_added = False

            for raw_path in location_paths:
                uri = path_to_file_uri(raw_path)
                if not uri:
                    continue
                if upsert_external_reference(comp, "distribution", uri):
                    stats["identified_distribution_refs_added"] += 1
                distribution_added = True
                break

            if not distribution_added:
                stats["identified_distribution_refs_missing_path"] += 1
        else:
            if set_unidentified_vcs_reference(comp):
                stats["unidentified_vcs_placeholders_set"] += 1

    return stats


def cmd_rpm(args: argparse.Namespace) -> int:
    if shutil.which("syft") is None:
        print("error: syft not found in PATH", file=sys.stderr)
        return 2

    if shutil.which("rpm") is None:
        print("error: rpm not found in PATH", file=sys.stderr)
        return 2

    scan_target = Path(args.scan_target).resolve()
    compare_root = Path(args.compare_root).resolve()
    report_file = Path(args.report).resolve()
    updated_sbom_file = Path(args.output).resolve()

    if not scan_target.exists():
        print(f"error: scan_target does not exist: {scan_target}", file=sys.stderr)
        return 1
    if not scan_target.is_dir():
        print(f"error: scan_target must be a directory: {scan_target}", file=sys.stderr)
        return 1

    if not compare_root.exists():
        print(f"error: compare_root does not exist: {compare_root}", file=sys.stderr)
        return 1
    if not compare_root.is_dir():
        print(f"error: compare_root must be a directory: {compare_root}", file=sys.stderr)
        return 1

    env = os.environ.copy()
    env.setdefault("SYFT_FILE_METADATA_DIGESTS", "sha256")

    try:
        cdx = run_syft(scan_target, env)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    raw_cdx_for_save = json.dumps(cdx, ensure_ascii=False, indent=2) + "\n"

    try:
        scan_stats = enrich_scan_target_components(cdx, scan_target, debug=args.debug)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    compare_stats = {
        "compare_rpm_total": 0,
        "compare_matched_by_sha256": 0,
        "compare_unmatched": 0,
        "compare_buildhost_empty": 0,
        "compare_rpm_query_errors": 0,
    }

    try:
        compare_stats = compare_with_other_root(cdx, compare_root, debug=args.debug)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    removed_cert_props = 0
    if args.remove_cert:
        removed_cert_props = remove_properties_from_all_components(
            cdx,
            [GOST_PROVIDED_BY_NAME],
        )
        if args.debug:
            print(f"removed cert properties: {removed_cert_props}", file=sys.stderr)

    default_props_added = add_default_properties_to_all_components(cdx)

    filtered_components = extract_filtered_sbom_components(cdx)

    rpm_files = find_rpm_files(compare_root)
    disk_index = index_disk_rpms(rpm_files)

    version_mismatches, missing_on_disk = compare_components(filtered_components, disk_index)
    provided_by_added = add_provided_by_for_found_components(filtered_components, disk_index)

    reference_policy_stats = apply_component_reference_policy(cdx)

    metadata = cdx.setdefault("metadata", {})
    props = metadata.setdefault("properties", [])
    if not isinstance(props, list):
        props = []
        metadata["properties"] = props

    stats = {}
    stats.update(scan_stats)
    stats.update(compare_stats)
    stats["removed_cert_properties"] = removed_cert_props
    stats["default_props_added"] = default_props_added
    stats["filtered_components_for_final_compare"] = len(filtered_components)
    stats["final_compare_rpm_files_found"] = len(rpm_files)
    stats["final_version_mismatches"] = len(version_mismatches)
    stats["final_missing_on_disk"] = len(missing_on_disk)
    stats["final_provided_by_added"] = provided_by_added
    stats.update(reference_policy_stats)

    props.append(
        {
            "name": "rpm-enrichment:stats",
            "value": json.dumps(stats, ensure_ascii=False),
        }
    )

    # Auto reorder before writing final SBOM.
    cdx = reorder_components(cdx)

    write_report(version_mismatches, missing_on_disk, report_file)
    updated_sbom_file.write_text(json.dumps(cdx, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.keep_intermediate:
        raw_cdx_path = updated_sbom_file.with_name(updated_sbom_file.stem + ".syft.cdx.json")
        raw_cdx_path.write_text(raw_cdx_for_save, encoding="utf-8")

    print(f"written report: {report_file}")
    print(f"written updated sbom: {updated_sbom_file}")
    print("Reorder applied: yes")
    print(json.dumps(stats, ensure_ascii=False, indent=2))

    merge_whl_into_sbom(cdx, scan_target, updated_sbom_file)

    should_run_cve = bool(getattr(args, "auto_cve_rpm", False)) or getattr(args, "cve_rpm_args", None) is not None

    if should_run_cve:
        raw_cve_args = list(getattr(args, "cve_rpm_args", None) or [])

        if raw_cve_args:
            # Compatibility mode: allow passing the original CVE scanner arguments
            # after --cve-rpm. If the SBOM path is omitted, use the freshly generated one.
            if raw_cve_args[0].startswith("-"):
                cve_args = [str(updated_sbom_file)] + raw_cve_args
            else:
                cve_args = raw_cve_args
        else:
            cve_args = [str(updated_sbom_file)]

            cve_branch = str(getattr(args, "cve_branch", "") or "").strip()
            if cve_branch:
                cve_args.append(f"--{cve_branch}")

            if getattr(args, "cve_json", False):
                cve_args.append("--json")
            else:
                cve_output = str(getattr(args, "cve_output", "") or "").strip()
                if cve_output:
                    cve_args.extend(["-o", cve_output])

            if getattr(args, "cve_verbose", False):
                cve_args.append("--verbose")
            if getattr(args, "cve_no_cache", False):
                cve_args.append("--no-cache")
            if getattr(args, "cve_update_cache", False):
                cve_args.append("--update-cache")

        print("running CVE scanner for generated SBOM...", flush=True)
        cve_rc = cmd_cve_rpm(argparse.Namespace(cve_args=cve_args))
        if cve_rc != 0:
            print(f"error: CVE scanner exited with code {cve_rc}", file=sys.stderr)
            return cve_rc

    return 0


def cmd_cve_rpm(args: argparse.Namespace) -> int:
    """Run the bundled ALT Linux CVE scanner script and pass all remaining args to it."""
    script_path = Path(__file__).resolve().with_name("sbom_alt_cve_working.py")
    if not script_path.is_file():
        print(f"error: CVE scanner script not found: {script_path}", file=sys.stderr)
        return 1

    cmd = [sys.executable, str(script_path)] + list(args.cve_args or [])
    try:
        return subprocess.run(cmd).returncode
    except KeyboardInterrupt:
        return 130


def cmd_binary(args: argparse.Namespace) -> int:
    """Run the bundled binary SBOM builder and pass all remaining args to it."""
    script_path = Path(__file__).resolve().with_name("sbom_binary.py")
    if not script_path.is_file():
        print(f"error: binary SBOM script not found: {script_path}", file=sys.stderr)
        return 1

    cmd = [sys.executable, str(script_path)] + list(args.binary_args or [])
    try:
        return subprocess.run(cmd).returncode
    except KeyboardInterrupt:
        return 130


def cmd_repack_deps(args: argparse.Namespace) -> int:
    """Run recursive archive unpacking and generate CycloneDX SBOM via Trivy."""
    script_path = Path(__file__).resolve().with_name("sbom_repack_deps.py")
    if not script_path.is_file():
        print(f"error: repack deps script not found: {script_path}", file=sys.stderr)
        return 1

    cmd = [sys.executable, str(script_path)] + list(args.repack_deps_args or [])
    try:
        return subprocess.run(cmd).returncode
    except KeyboardInterrupt:
        return 130


def merge_whl_into_sbom(
    sbom: Dict[str, Any],
    scan_dir: Path,
    output_file: Path,
) -> int:
    """
    If .whl files are found in scan_dir, run sbom_whl.py on them,
    load the result and merge its components into sbom in-place.
    Writes the merged SBOM back to output_file.
    Returns number of whl components merged (0 = nothing to do).
    """
    whl_files = list(scan_dir.rglob("*.whl"))
    if not whl_files:
        return 0

    print(f"\n[whl] Found {len(whl_files)} .whl file(s) in {scan_dir} — running sbom_whl.py")

    whl_script = Path(__file__).resolve().with_name("sbom_whl.py")
    if not whl_script.is_file():
        print(f"[whl] warning: sbom_whl.py not found at {whl_script} — skipping", file=sys.stderr)
        return 0

    tmp_whl_sbom = output_file.with_name(output_file.stem + ".whl.tmp.json")
    tmp_errors = output_file.parent / "debug" / "whl.errors.json"

    cmd = [
        sys.executable, str(whl_script),
        str(scan_dir),
        "-o", str(tmp_whl_sbom),
        "--errors-output", str(tmp_errors),
    ]
    try:
        rc = subprocess.run(cmd).returncode
    except KeyboardInterrupt:
        return 0

    if rc != 0:
        print(f"[whl] warning: sbom_whl.py exited with code {rc} — skipping merge", file=sys.stderr)
        return 0

    if not tmp_whl_sbom.exists():
        print("[whl] warning: sbom_whl.py produced no output — skipping merge", file=sys.stderr)
        return 0

    try:
        whl_sbom = json.loads(tmp_whl_sbom.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[whl] warning: could not read whl SBOM: {e} — skipping merge", file=sys.stderr)
        return 0
    finally:
        try:
            tmp_whl_sbom.unlink(missing_ok=True)
        except Exception:
            pass

    whl_components = whl_sbom.get("components") or []
    if not whl_components:
        return 0

    # Dedup by purl — don't add if already present in main SBOM
    existing_purls = {
        c.get("purl") for c in (sbom.get("components") or []) if c.get("purl")
    }
    new_components = [c for c in whl_components if c.get("purl") not in existing_purls]
    skipped = len(whl_components) - len(new_components)

    sbom.setdefault("components", []).extend(new_components)
    sbom["components"] = reorder_components({"components": sbom["components"]})["components"]

    output_file.write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"[whl] Merged {len(new_components)} whl component(s) into {output_file}")
    if skipped:
        print(f"[whl] Skipped {skipped} duplicate(s) already present in SBOM")

    return len(new_components)


# =============================================================================
# CLI
# =============================================================================

def build_rpm_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom_tool.py --rpm",
        description="Run syft on RPM folder, enrich components and write updated SBOM",
    )
    parser.add_argument("scan_target", help="Directory with RPM files to scan with syft")
    parser.add_argument("--compare-root", required=True,
        help="Directory with reference RPMs for SHA-256 comparison and name/version matching")
    parser.add_argument("--remove-cert", action="store_true",
        help="Remove GOST:provided_by from all components before final filtering/report stage")
    parser.add_argument("--keep-intermediate", action="store_true",
        help="Keep raw syft CycloneDX JSON next to final updated SBOM file")
    parser.add_argument("--debug", action="store_true", help="Print matching diagnostics to stderr")
    parser.add_argument("-o", "--output", default=UPDATED_SBOM_FILE_DEFAULT,
        help=f"Output updated SBOM JSON path. Default: {UPDATED_SBOM_FILE_DEFAULT}")
    parser.add_argument("--report", default=REPORT_FILE_DEFAULT,
        help=f"Output report path. Default: {REPORT_FILE_DEFAULT}")
    parser.add_argument("--no-cve-rpm", dest="auto_cve_rpm", action="store_false",
        help="Disable automatic CVE scan")
    parser.set_defaults(auto_cve_rpm=True, cve_rpm_args=None)
    parser.add_argument("--cve-branch", choices=["p9", "p10", "p11", "c9f2", "c10f2"], default="",
        help="ALT Linux branch for automatic CVE scan")
    parser.add_argument("--cve-output", default="cve_report_alt.xlsx",
        help="CVE XLSX output path. Default: cve_report_alt.xlsx")
    parser.add_argument("--cve-json", action="store_true",
        help="Print CVE results as JSON instead of writing XLSX")
    parser.add_argument("--cve-verbose", action="store_true", help="Write verbose CVE log")
    parser.add_argument("--cve-no-cache", action="store_true", help="Ignore cached ALT OVAL data")
    parser.add_argument("--cve-update-cache", action="store_true", help="Update ALT OVAL cache")
    parser.add_argument("--cve-rpm", dest="cve_rpm_args", nargs=argparse.REMAINDER,
        help="Run bundled ALT Linux CVE scanner after writing SBOM; pass CVE options after this flag")
    return parser


def build_deb_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom_tool.py --deb",
        description="Scan folder with .deb packages and generate CycloneDX SBOM",
    )
    parser.add_argument("folder", help="Path to folder with .deb packages")
    parser.add_argument("package_list", nargs="?", default="",
        help="TXT file with Debian package filenames. "
             "Packages NOT found in this list will get GOST:provided_by=Astra Linux")
    parser.add_argument("--with-dependencies", action="store_true",
        help="Include internal dependencies between found .deb packages in SBOM")
    parser.add_argument("-o", "--output", default="deb.json",
        help="Output SBOM JSON path. Default: deb.json")
    parser.add_argument("--errors-output", default="debug/deb.errors.json",
        help="Output errors JSON path. Default: debug/deb.errors.json")
    return parser


def build_binary_repack_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom_tool.py --binary-repack",
        description=(
            "Run sbom_binary.py and sbom_repack_deps.py on the same package directory, "
            "sharing a single unpack step. Produces binary.json and repack.cdx.json."
        ),
    )
    parser.add_argument("pkg_dir", help="Directory with .deb/.rpm/whl/archive packages")
    parser.add_argument("source_sbom", nargs="?", default="",
        help="Optional source SBOM JSON for ghost-dependency diff (passed to sbom_binary.py)")
    parser.add_argument("--unpack-dir", default="./unpacked",
        help="Shared unpack directory for both tools. Default: ./unpacked")
    parser.add_argument("--binary-output", default="binary.json",
        help="Output path for sbom_binary.py result. Default: binary.json")
    parser.add_argument("--repack-output", default="repack.cdx.json",
        help="Output path for sbom_repack_deps.py result. Default: repack.cdx.json")
    parser.add_argument("--output-dir", default="./debug",
        help="Output directory for ghost-dependencies reports. Default: ./debug")
    parser.add_argument("--max-depth", type=int, default=8,
        help="Max nested archive unpack depth for sbom_repack_deps.py. Default: 8")
    parser.add_argument("--all-deps", action="store_true",
        help="Pass --all-deps to sbom_binary.py")
    parser.add_argument("--trivy-arg", action="append", default=[],
        help="Extra argument passed to Trivy (repeat for multiple)")
    return parser


def cmd_binary_repack(args: argparse.Namespace) -> int:
    here = Path(__file__).resolve().parent
    binary_script = here / "sbom_binary.py"
    repack_script = here / "sbom_repack_deps.py"

    for script in (binary_script, repack_script):
        if not script.exists():
            print(f"error: script not found: {script}", file=sys.stderr)
            return 1

    pkg_dir = Path(args.pkg_dir).resolve()
    if not pkg_dir.exists() or not pkg_dir.is_dir():
        print(f"error: pkg_dir does not exist or is not a directory: {pkg_dir}", file=sys.stderr)
        return 1

    unpack_dir = Path(args.unpack_dir).resolve()

    # ── Step 1: sbom_binary.py ────────────────────────────────────────────────
    print(f"\n[binary-repack] Step 1/2 — sbom_binary.py → {args.binary_output}\n")
    binary_cmd = [
        sys.executable, str(binary_script),
        str(pkg_dir),
        "--output", args.binary_output,
        "--unpack-dir", str(unpack_dir),
        "--output-dir", args.output_dir,
        "--errors-output", str(Path(args.output_dir) / "binary.errors.txt"),
    ]
    if args.source_sbom:
        binary_cmd.insert(3, args.source_sbom)
    if args.all_deps:
        binary_cmd.append("--all-deps")

    try:
        rc = subprocess.run(binary_cmd).returncode
    except KeyboardInterrupt:
        return 130
    if rc != 0:
        print(f"\n[binary-repack] sbom_binary.py exited with code {rc}", file=sys.stderr)
        return rc

    # ── Step 2: sbom_repack_deps.py — reuse already-unpacked dir ─────────────
    print(f"\n[binary-repack] Step 2/2 — sbom_repack_deps.py → {args.repack_output}\n")
    repack_cmd = [
        sys.executable, str(repack_script),
        str(pkg_dir),
        "--output", args.repack_output,
        "--unpack-dir", str(unpack_dir),
        "--max-depth", str(args.max_depth),
        "--stats-output", str(Path(args.output_dir) / "repack.stats.json"),
    ]
    for trivy_arg in (args.trivy_arg or []):
        repack_cmd += ["--trivy-arg", trivy_arg]

    try:
        rc = subprocess.run(repack_cmd).returncode
    except KeyboardInterrupt:
        return 130
    if rc != 0:
        print(f"\n[binary-repack] sbom_repack_deps.py exited with code {rc}", file=sys.stderr)
        return rc

    print(f"\n[binary-repack] Done.")
    print(f"  binary SBOM : {args.binary_output}")
    print(f"  repack SBOM : {args.repack_output}")
    print(f"  debug files : {args.output_dir}/")
    return 0


def print_usage() -> None:
    print(
        "usage: sbom_tool.py --rpm <scan_target> --compare-root <dir> [options]\n"
        "       sbom_tool.py --deb <folder> [package_list.txt] [options]\n"
        "       sbom_tool.py --binary-repack <pkg_dir> [source_sbom.json] [options]\n"
        "\n"
        "modes:\n"
        "  --rpm            Run syft on RPM folder, enrich components and write updated SBOM\n"
        "  --deb            Scan folder with .deb packages and generate CycloneDX SBOM\n"
        "  --binary-repack  Run sbom_binary.py + sbom_repack_deps.py on same directory\n"
        "\n"
        "pass --help after the mode flag for detailed options, e.g.:\n"
        "  sbom_tool.py --rpm --help\n"
        "  sbom_tool.py --deb --help\n"
        "  sbom_tool.py --binary-repack --help\n",
        file=sys.stderr,
    )


def main() -> int:
    argv = sys.argv[1:]

    if not argv:
        print_usage()
        return 1

    mode = argv[0]
    rest = argv[1:]

    if mode == "--rpm":
        parser = build_rpm_parser()
        args = parser.parse_args(rest)
        return cmd_rpm(args)

    if mode == "--deb":
        parser = build_deb_parser()
        args = parser.parse_args(rest)
        return cmd_deb(args)

    if mode == "--binary-repack":
        parser = build_binary_repack_parser()
        args = parser.parse_args(rest)
        return cmd_binary_repack(args)

    print(f"error: unknown mode '{mode}'\n", file=sys.stderr)
    print_usage()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
