#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sbom_repack_deps.py — recursively unpack package/archive contents and generate
CycloneDX SBOM from the unpacked tree via Trivy.

Usage:
  python3 sbom_repack_deps.py /path/to/packages
  python3 sbom_repack_deps.py /path/to/packages -o sbom-repacked.cdx.json
  python3 sbom_repack_deps.py /path/to/packages --unpack-dir ./repacked --max-depth 10

Through sbom_tool.py:
  python3 sbom_tool.py --repack-deps /path/to/packages
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


DEFAULT_OUTPUT = "repack.cdx.json"
DEFAULT_UNPACK_DIR = "./repacked-deps"

ARCHIVE_SUFFIXES = {
    ".deb", ".rpm",
    ".zip", ".jar", ".war", ".ear", ".whl",
    ".tar", ".tgz", ".tbz", ".tbz2", ".txz", ".tlz",
    ".gz", ".bz2", ".xz", ".lzma", ".zst", ".zstd",
    ".7z",
}

TAR_SUFFIX_CHAINS = {
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tar.zst", ".tar.zstd",
}


class RepackError(RuntimeError):
    pass


def require_tool(tool: str) -> None:
    if shutil.which(tool) is None:
        raise RepackError(f"required tool not found in PATH: {tool}")


def check_tool(tool: str) -> bool:
    return shutil.which(tool) is not None


def sha1_text(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="replace")).hexdigest()[:10]


def safe_part(value: str, limit: int = 80) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in value)
    cleaned = cleaned.strip("._") or "archive"
    return cleaned[:limit]


def unique_extract_dir(root: Path, archive_path: Path, depth: int) -> Path:
    name = safe_part(archive_path.name)
    digest = sha1_text(str(archive_path.resolve() if archive_path.exists() else archive_path))
    out = root / f"d{depth}_{name}_{digest}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def is_within_directory(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def safe_extract_zip(zip_path: Path, dest: Path) -> int:
    count = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if not name or name.startswith("/") or ".." in Path(name).parts:
                continue

            target = dest / name
            if not is_within_directory(dest, target):
                continue

            # Unix symlink in ZIP: skip it for safety.
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                continue

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            with zf.open(info, "r") as src:
                safe_write_bytes(target, src.read())
                count += 1
    return count


def safe_extract_tar(tar_path: Path, dest: Path) -> int:
    count = 0
    with tarfile.open(tar_path, mode="r:*") as tf:
        for member in tf.getmembers():
            name = member.name.replace("\\", "/")
            if not name or name.startswith("/") or ".." in Path(name).parts:
                continue

            target = dest / name
            if not is_within_directory(dest, target):
                continue

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            # Skip symlinks, hardlinks, devices and special files.
            if not member.isfile():
                continue

            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            safe_write_bytes(target, extracted.read())
            count += 1
    return count


def unpack_deb(deb_path: Path, dest: Path) -> int:
    require_tool("dpkg-deb")
    proc = subprocess.run(
        ["dpkg-deb", "-x", str(deb_path), str(dest)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RepackError(proc.stderr.strip() or f"dpkg-deb failed for {deb_path}")
    return count_files(dest)


def unpack_rpm(rpm_path: Path, dest: Path) -> int:
    require_tool("rpm2cpio")
    require_tool("cpio")

    rpm2cpio = subprocess.Popen(
        ["rpm2cpio", str(rpm_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        proc = subprocess.run(
            ["cpio", "-idm", "--no-absolute-filenames"],
            stdin=rpm2cpio.stdout,
            cwd=str(dest),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    finally:
        if rpm2cpio.stdout:
            rpm2cpio.stdout.close()
        _, rpm_err = rpm2cpio.communicate()

    if rpm2cpio.returncode not in (0, None):
        msg = rpm_err.decode("utf-8", errors="replace") if isinstance(rpm_err, bytes) else str(rpm_err)
        raise RepackError(msg.strip() or f"rpm2cpio failed for {rpm_path}")
    if proc.returncode != 0:
        raise RepackError(proc.stderr.strip() or f"cpio failed for {rpm_path}")
    return count_files(dest)


def unpack_single_compressed(path: Path, dest: Path, kind: str) -> int:
    output_name = path.name
    for suffix in (".gz", ".bz2", ".xz", ".lzma", ".zst", ".zstd"):
        if output_name.lower().endswith(suffix):
            output_name = output_name[: -len(suffix)] or "decompressed"
            break
    output_path = dest / output_name

    if kind == "gz":
        with gzip.open(path, "rb") as src:
            safe_write_bytes(output_path, src.read())
    elif kind == "bz2":
        safe_write_bytes(output_path, bz2.decompress(path.read_bytes()))
    elif kind in {"xz", "lzma"}:
        safe_write_bytes(output_path, lzma.decompress(path.read_bytes()))
    elif kind == "zst":
        if check_tool("zstd"):
            proc = subprocess.run(
                ["zstd", "-d", "-c", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        elif check_tool("unzstd"):
            proc = subprocess.run(
                ["unzstd", "-c", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        else:
            raise RepackError("zst archive found, but neither zstd nor unzstd is available")
        if proc.returncode != 0:
            raise RepackError(proc.stderr.decode("utf-8", errors="replace").strip() or f"zstd failed for {path}")
        safe_write_bytes(output_path, proc.stdout)
    else:
        raise RepackError(f"unsupported compression kind: {kind}")

    return 1


def unpack_7z(path: Path, dest: Path) -> int:
    tool = "7z" if check_tool("7z") else "7za" if check_tool("7za") else ""
    if not tool:
        raise RepackError("7z archive found, but neither 7z nor 7za is available")
    proc = subprocess.run(
        [tool, "x", "-y", f"-o{dest}", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RepackError(proc.stderr.strip() or f"{tool} failed for {path}")
    return count_files(dest)


def suffix_chain(path: Path) -> str:
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) >= 2:
        two = "".join(suffixes[-2:])
        if two in TAR_SUFFIX_CHAINS:
            return two
    return suffixes[-1] if suffixes else ""


def looks_like_archive(path: Path) -> bool:
    if not path.is_file():
        return False
    chain = suffix_chain(path)
    if chain in ARCHIVE_SUFFIXES or chain in TAR_SUFFIX_CHAINS:
        return True
    try:
        if zipfile.is_zipfile(path):
            return True
    except Exception:
        pass
    try:
        if tarfile.is_tarfile(path):
            return True
    except Exception:
        pass
    return False


def unpack_archive(path: Path, dest: Path) -> int:
    chain = suffix_chain(path)
    lower_name = path.name.lower()

    if chain == ".deb":
        return unpack_deb(path, dest)
    if chain == ".rpm":
        return unpack_rpm(path, dest)

    if chain in TAR_SUFFIX_CHAINS or chain == ".tar" or tarfile.is_tarfile(path):
        return safe_extract_tar(path, dest)

    if chain in {".zip", ".jar", ".war", ".ear", ".whl"} or zipfile.is_zipfile(path):
        return safe_extract_zip(path, dest)

    if chain == ".gz" and not lower_name.endswith(".tar.gz"):
        return unpack_single_compressed(path, dest, "gz")
    if chain == ".bz2" and not lower_name.endswith(".tar.bz2"):
        return unpack_single_compressed(path, dest, "bz2")
    if chain in {".xz", ".lzma"} and not (lower_name.endswith(".tar.xz") or lower_name.endswith(".tar.lzma")):
        return unpack_single_compressed(path, dest, chain.lstrip("."))
    if chain in {".zst", ".zstd"} and not (lower_name.endswith(".tar.zst") or lower_name.endswith(".tar.zstd")):
        return unpack_single_compressed(path, dest, "zst")

    if chain == ".7z":
        return unpack_7z(path, dest)

    raise RepackError(f"unsupported archive format: {path}")


def count_files(path: Path) -> int:
    return sum(1 for p in path.rglob("*") if p.is_file())


def copy_non_archive(source: Path, raw_root: Path, input_root: Optional[Path]) -> None:
    if input_root and source.is_relative_to(input_root):
        rel = source.relative_to(input_root)
    else:
        rel = Path(source.name)
    target = raw_root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copy2(source, target)


def iter_initial_files(input_path: Path) -> Tuple[List[Path], Optional[Path]]:
    if input_path.is_file():
        return [input_path], input_path.parent
    if input_path.is_dir():
        return sorted(p for p in input_path.rglob("*") if p.is_file()), input_path
    raise RepackError(f"input path not found: {input_path}")


def repack_recursively(input_path: Path, unpack_dir: Path, max_depth: int) -> dict:
    if unpack_dir.exists():
        print(f"[*] Очищаю старый каталог: {unpack_dir}")
        shutil.rmtree(unpack_dir)
    unpack_dir.mkdir(parents=True, exist_ok=True)

    raw_root = unpack_dir / "raw-files"
    extracted_root = unpack_dir / "extracted"
    raw_root.mkdir(parents=True, exist_ok=True)
    extracted_root.mkdir(parents=True, exist_ok=True)

    initial_files, input_root = iter_initial_files(input_path)
    queue: List[Tuple[Path, int]] = [(p, 0) for p in initial_files]
    seen: set[Path] = set()
    archive_count = 0
    extracted_file_count = 0
    copied_file_count = 0
    errors: List[str] = []

    while queue:
        path, depth = queue.pop(0)
        try:
            resolved = path.resolve()
        except Exception:
            resolved = path

        if resolved in seen:
            continue
        seen.add(resolved)

        if depth > max_depth:
            errors.append(f"max depth exceeded: {path}")
            continue

        if not path.is_file():
            continue

        if not looks_like_archive(path):
            # Preserve top-level non-archive files. Nested non-archive files already live inside unpack_dir.
            if depth == 0:
                copy_non_archive(path, raw_root, input_root)
                copied_file_count += 1
            continue

        out_dir = unique_extract_dir(extracted_root, path, depth)
        print(f"[*] Распаковываю: {path} -> {out_dir}")
        try:
            before = count_files(out_dir)
            unpack_archive(path, out_dir)
            after = count_files(out_dir)
            extracted_now = max(0, after - before)
            extracted_file_count += extracted_now
            archive_count += 1
        except Exception as e:
            msg = f"{path}: {e}"
            print(f"  [!] {msg}")
            errors.append(msg)
            continue

        # Do not keep nested archive copies after they were unpacked; this keeps Trivy input cleaner.
        try:
            if path.resolve().is_relative_to(unpack_dir.resolve()):
                path.unlink(missing_ok=True)
        except Exception:
            pass

        for child in sorted(out_dir.rglob("*")):
            if child.is_file() and looks_like_archive(child):
                queue.append((child, depth + 1))

    stats = {
        "input_files_seen": len(initial_files),
        "archives_unpacked": archive_count,
        "files_extracted": extracted_file_count,
        "top_level_non_archives_copied": copied_file_count,
        "errors": errors,
    }

    print(f"[*] Распаковано архивов: {archive_count}")
    print(f"[*] Извлечено файлов: {extracted_file_count}")
    if copied_file_count:
        print(f"[*] Скопировано обычных файлов верхнего уровня: {copied_file_count}")
    if errors:
        print(f"[!] Ошибок распаковки: {len(errors)}")

    return stats


def run_trivy_fs(unpack_dir: Path, output: Path, trivy_args: List[str]) -> None:
    require_tool("trivy")
    output.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "trivy",
        "fs",
        "--format",
        "cyclonedx",
        "--output",
        str(output),
        *trivy_args,
        str(unpack_dir),
    ]

    print("[*] Запускаю Trivy:")
    print("    " + " ".join(cmd))

    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        raise RepackError(f"trivy exited with code {proc.returncode}")


def write_stats(stats: dict, stats_path: Path) -> None:
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[*] Статистика распаковки: {stats_path}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recursively unpack packages/archives and generate CycloneDX SBOM using Trivy"
    )
    parser.add_argument("input", help="Input file or directory with packages/archives")
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output CycloneDX SBOM path. Default: {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--unpack-dir",
        default=DEFAULT_UNPACK_DIR,
        help=f"Directory for recursive unpacking. Default: {DEFAULT_UNPACK_DIR}",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=8,
        help="Maximum nested archive unpack depth. Default: 8",
    )
    parser.add_argument(
        "--stats-output",
        default="./debug/repack.stats.json",
        help="JSON file with unpacking statistics. Default: ./debug/repack.stats.json",
    )
    parser.add_argument(
        "--keep-unpacked",
        action="store_true",
        help="Keep unpack directory after Trivy finishes. Default: keep it anyway for inspection; option is accepted for compatibility.",
    )
    parser.add_argument(
        "--trivy-arg",
        action="append",
        default=[],
        help="Extra argument passed to Trivy. Repeat for multiple args, e.g. --trivy-arg=--skip-dirs --trivy-arg=vendor",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    input_path = Path(args.input).resolve()
    output = Path(args.output).resolve()
    unpack_dir = Path(args.unpack_dir).resolve()
    stats_output = Path(args.stats_output).resolve()

    if args.max_depth < 0:
        print("error: --max-depth must be >= 0", file=sys.stderr)
        return 1

    try:
        stats = repack_recursively(input_path, unpack_dir, max_depth=args.max_depth)
        write_stats(stats, stats_output)
        run_trivy_fs(unpack_dir, output, list(args.trivy_arg or []))
    except RepackError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    print(f"[+] Готово: {output}")
    print(f"[+] Trivy CycloneDX SBOM собран по распакованному каталогу: {unpack_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
