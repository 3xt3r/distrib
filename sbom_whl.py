#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sbom_whl.py — scan a directory of .whl files and generate a CycloneDX 1.6 SBOM.

For each wheel the script:
  1. Opens the archive and reads the METADATA file inside *.dist-info/METADATA
  2. Falls back to parsing the wheel filename if METADATA is missing or unreadable
  3. Normalises the package name to lowercase with hyphens (PEP 503 / PURL spec)
  4. Builds a pkg:pypi/<name>@<version> PURL
  5. Emits a CycloneDX component with type=library, ecosystem=pypi

Usage:
  python3 sbom_whl.py ./wheels
  python3 sbom_whl.py ./wheels -o whl.json
  python3 sbom_whl.py ./wheels -o whl.json --errors-output debug/whl.errors.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Wheel filename grammar  (PEP 427)
# {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
# ---------------------------------------------------------------------------
_WHL_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"-(?P<version>[^-]+)"
    r"(-(?P<build>[^-]+))?"
    r"-(?P<python>[^-]+)"
    r"-(?P<abi>[^-]+)"
    r"-(?P<platform>[^-]+)"
    r"\.whl$",
    re.IGNORECASE,
)


def _normalise_name(name: str) -> str:
    """PEP 503 canonical name: lowercase, runs of [-_.] → single hyphen."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------

@dataclass
class WheelInfo:
    name: str           # normalised (PEP 503)
    version: str
    summary: str = ""
    home_page: str = ""
    author: str = ""
    license_: str = ""
    requires_python: str = ""
    sha256: str = ""
    filename: str = ""
    source: str = ""    # "metadata" | "filename"


def _parse_metadata_text(text: str) -> Dict[str, str]:
    """Parse RFC 822-style METADATA into a flat dict (first value wins)."""
    result: Dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith(" ") or line.startswith("\t"):
            continue  # folded continuation – skip for simple fields
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key and key not in result:
            result[key] = value
    return result


def _read_metadata_from_wheel(whl_path: Path) -> Optional[Dict[str, str]]:
    """
    Open the zip and find *.dist-info/METADATA.
    Returns parsed dict or None if not found / unreadable.
    """
    try:
        with zipfile.ZipFile(whl_path, "r") as zf:
            candidates = [
                n for n in zf.namelist()
                if re.match(r"[^/]+\.dist-info/METADATA$", n, re.IGNORECASE)
            ]
            if not candidates:
                return None
            # prefer the first match (there should be exactly one)
            with zf.open(candidates[0]) as fh:
                text = fh.read().decode("utf-8", errors="replace")
            return _parse_metadata_text(text)
    except Exception:
        return None


def _parse_filename(filename: str) -> Optional[Tuple[str, str]]:
    """Return (normalised_name, version) from wheel filename, or None."""
    m = _WHL_RE.match(filename)
    if not m:
        return None
    return _normalise_name(m.group("name")), m.group("version")


def extract_wheel_info(whl_path: Path) -> Optional[WheelInfo]:
    """
    Extract WheelInfo from a .whl file.
    Strategy: METADATA first, fallback to filename parsing.
    Returns None if both strategies fail.
    """
    digest = _sha256(whl_path)
    meta = _read_metadata_from_wheel(whl_path)

    if meta and meta.get("name") and meta.get("version"):
        return WheelInfo(
            name=_normalise_name(meta["name"]),
            version=meta["version"],
            summary=meta.get("summary", ""),
            home_page=_extract_home_page(meta),
            author=meta.get("author", "") or meta.get("author-email", ""),
            license_=meta.get("license", ""),
            requires_python=meta.get("requires-python", ""),
            sha256=digest,
            filename=whl_path.name,
            source="metadata",
        )

    parsed = _parse_filename(whl_path.name)
    if parsed:
        name, version = parsed
        return WheelInfo(
            name=name,
            version=version,
            sha256=digest,
            filename=whl_path.name,
            source="filename",
        )

    return None


# ---------------------------------------------------------------------------
# CycloneDX builder
# ---------------------------------------------------------------------------

def _is_valid_iri(url: str) -> bool:
    """
    Check that a URL is a valid IRI-reference acceptable by CycloneDX 1.6.
    Must start with a recognized scheme and contain no bare spaces.
    """
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if " " in url:
        return False
    # Must start with http/https/ftp or urn: schemes
    return bool(re.match(r"^(https?|ftp)://\S+$", url, re.IGNORECASE))


def _extract_home_page(meta: Dict[str, str]) -> str:
    """
    Extract a clean homepage URL from METADATA.
    'Home-page' is a plain URL; 'Project-URL' is 'Label, URL' — parse it.
    """
    home = meta.get("home-page", "").strip()
    if _is_valid_iri(home):
        return home

    # Project-URL: Homepage, https://...
    project_url = meta.get("project-url", "").strip()
    if project_url and "," in project_url:
        _, _, url_part = project_url.partition(",")
        url_part = url_part.strip()
        if _is_valid_iri(url_part):
            return url_part

    return ""


def _make_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name}@{version}"


def _make_component(info: WheelInfo) -> Dict[str, Any]:
    purl = _make_purl(info.name, info.version)
    comp: Dict[str, Any] = {
        "type": "library",
        "bom-ref": purl,
        "name": info.name,
        "version": info.version,
        "purl": purl,
        "properties": [
            {"name": "syft:package:type", "value": "python"},
            {"name": "whl:filename", "value": info.filename},
            {"name": "whl:metadata_source", "value": info.source},
            {"name": "GOST:attack_surface", "value": "no"},
            {"name": "GOST:security_function", "value": "no"},
        ],
    }

    if info.sha256:
        comp["hashes"] = [{"alg": "SHA-256", "content": info.sha256}]

    if info.summary:
        comp["description"] = info.summary

    if info.license_:
        comp["licenses"] = [{"license": {"name": info.license_}}]

    external_refs = []
    if info.home_page and _is_valid_iri(info.home_page):
        external_refs.append({
            "type": "website",
            "url": info.home_page,
        })
    pypi_url = f"https://pypi.org/project/{info.name}/{info.version}/"
    if _is_valid_iri(pypi_url):
        external_refs.append({
            "type": "distribution",
            "url": pypi_url,
        })
    if external_refs:
        comp["externalReferences"] = external_refs

    return comp


def build_sbom(components: List[Dict[str, Any]], source_dir: Path) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {"vendor": "sbom_whl", "name": "sbom_whl.py", "version": "1.0.0"},
            ],
            "component": {
                "type": "application",
                "name": source_dir.name,
                "description": f"Python wheel packages from {source_dir}",
            },
        },
        "components": components,
    }


# ---------------------------------------------------------------------------
# Main scan logic
# ---------------------------------------------------------------------------

def scan_wheels(
    input_dir: Path,
    output_file: Path,
    errors_file: Path,
) -> int:
    whl_files = sorted(input_dir.rglob("*.whl"))
    if not whl_files:
        print(f"[!] No .whl files found in {input_dir}", file=sys.stderr)
        return 1

    print(f"[*] Found {len(whl_files)} .whl file(s) in {input_dir}")

    components: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    seen_purls: Dict[str, str] = {}  # purl → filename (dedup)

    for whl_path in whl_files:
        print(f"  [*] Processing {whl_path.name}")
        info = extract_wheel_info(whl_path)

        if info is None:
            msg = f"Could not extract name/version from {whl_path.name}"
            print(f"  [!] {msg}")
            errors.append({"file": whl_path.name, "error": msg})
            continue

        purl = _make_purl(info.name, info.version)

        if purl in seen_purls:
            msg = f"Duplicate purl {purl} — already seen in {seen_purls[purl]}, skipping {whl_path.name}"
            print(f"  [!] {msg}")
            errors.append({"file": whl_path.name, "error": msg, "duplicate_of": seen_purls[purl]})
            continue

        seen_purls[purl] = whl_path.name
        comp = _make_component(info)
        components.append(comp)
        print(f"  [+] {purl}  (source: {info.source})")

    # write errors
    if errors:
        errors_file.parent.mkdir(parents=True, exist_ok=True)
        errors_file.write_text(
            json.dumps(errors, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"[!] {len(errors)} error(s) written to {errors_file}")

    if not components:
        print("[!] No components to write — aborting", file=sys.stderr)
        return 1

    sbom = build_sbom(components, input_dir)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(sbom, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"[+] Done: {output_file}")
    print(f"    components : {len(components)}")
    print(f"    errors     : {len(errors)}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a directory of .whl files and generate a CycloneDX 1.6 SBOM",
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing .whl files (searched recursively)",
    )
    parser.add_argument(
        "-o", "--output",
        default="whl.json",
        help="Output CycloneDX SBOM JSON path. Default: whl.json",
    )
    parser.add_argument(
        "--errors-output",
        default="debug/whl.errors.json",
        help="Output errors JSON path. Default: debug/whl.errors.json",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    input_dir = Path(args.input_dir).resolve()
    if not input_dir.exists() or not input_dir.is_dir():
        print(f"error: input_dir does not exist or is not a directory: {input_dir}", file=sys.stderr)
        return 1

    return scan_wheels(
        input_dir=input_dir,
        output_file=Path(args.output).resolve(),
        errors_file=Path(args.errors_output).resolve(),
    )


if __name__ == "__main__":
    raise SystemExit(main())
