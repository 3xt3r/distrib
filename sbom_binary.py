#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sbom_binary.py — build a binary SBOM from unpacked .deb/.rpm contents and optionally
compare a source SBOM against the generated binary SBOM.

Usage:
  python3 sbom_binary.py /path/to/packages
  python3 sbom_binary.py /path/to/packages source-sbom.json
  python3 sbom_binary.py /path/to/packages source-sbom.json -o sbom-full.json --output-dir binary-reports
  python3 sbom_binary.py /path/to/packages source-sbom.json --all-deps

Through sbom_tool.py:
  python3 sbom_tool.py --binary /path/to/packages
  python3 sbom_tool.py --binary /path/to/packages source-sbom.json -o sbom-full.json --output-dir binary-reports
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


BINARY_ECOSYSTEMS = {"golang", "cargo", "maven", "nuget"}


def require_tools(tools: List[str]) -> None:
    """Проверить наличие обязательных внешних утилит."""
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        for tool in missing:
            print(f"[!] Не найден обязательный инструмент: {tool}", file=sys.stderr)
        raise SystemExit(1)


def check_tool(tool: str) -> bool:
    """Проверить наличие инструмента, вернуть False если нет."""
    return shutil.which(tool) is not None


def prepare_unpack_dir(unpack_dir: Path) -> None:
    """Очистить и заново создать каталог распаковки."""
    if unpack_dir.exists():
        print(f"[*] Очищаю старый каталог распаковки: {unpack_dir}")
        shutil.rmtree(unpack_dir)
    unpack_dir.mkdir(parents=True, exist_ok=True)


def unpack_debs(pkg_dir: Path, unpack_dir: Path) -> None:
    """Распаковать все deb-пакеты рекурсивно."""
    debs = sorted(pkg_dir.rglob("*.deb"))
    if not debs:
        print(f"[*] deb-файлы не найдены в {pkg_dir}")
        return

    require_tools(["dpkg-deb"])

    for deb in debs:
        name = deb.stem
        out = unpack_dir / name
        out.mkdir(parents=True, exist_ok=True)
        print(f"[*] Распаковываю deb {deb} -> {out}")
        subprocess.run(["dpkg-deb", "-x", str(deb), str(out)], check=True)


def unpack_rpms(pkg_dir: Path, unpack_dir: Path) -> None:
    """Распаковать все rpm-пакеты рекурсивно."""
    rpms = sorted(pkg_dir.rglob("*.rpm"))
    if not rpms:
        print(f"[*] rpm-файлы не найдены в {pkg_dir}")
        return

    require_tools(["rpm2cpio", "cpio"])

    for rpm in rpms:
        name = rpm.stem
        out = unpack_dir / name
        out.mkdir(parents=True, exist_ok=True)
        print(f"[*] Распаковываю rpm {rpm} -> {out}")

        rpm2cpio = subprocess.Popen(
            ["rpm2cpio", str(rpm)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            subprocess.run(
                ["cpio", "-idm"],
                stdin=rpm2cpio.stdout,
                cwd=str(out),
                capture_output=True,
                text=True,
                check=True,
            )
        finally:
            if rpm2cpio.stdout:
                rpm2cpio.stdout.close()
            rpm2cpio.wait()


def find_elf_binaries(unpack_dir: Path) -> List[str]:
    """Найти ELF executable бинарники."""
    require_tools(["file"])

    result: List[str] = []
    for path in unpack_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            out = subprocess.run(
                ["file", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            text = out.stdout
            if "ELF" in text and "executable" in text:
                result.append(str(path))
        except Exception:
            continue

    print(f"[*] Найдено ELF-бинарников: {len(result)}")
    return result


def is_go_binary(binary: str) -> bool:
    """Проверить, что бинарник Go."""
    result = subprocess.run(
        ["go", "version", "-m", binary],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def is_rust_binary(binary: str) -> bool:
    """Проверить, что бинарник Rust по строкам."""
    result = subprocess.run(
        ["strings", binary],
        capture_output=True,
        text=True,
        errors="ignore",
        check=False,
    )
    text = result.stdout.lower()
    rust_markers = [
        "rustc",
        "cargo",
        "/rustc/",
        "rust_begin_unwind",
        "rust_eh_personality",
    ]
    return any(marker in text for marker in rust_markers)


def find_dotnet_apps(unpack_dir: Path, errors: List[str]) -> List[str]:
    """
    Найти .NET приложения по *.deps.json.

    Логика:
    - Ищем *.deps.json рекурсивно.
    - Для каждого foo.deps.json ожидаем рядом foo.dll.
    - Если парная dll найдена — считаем это .NET приложением.
    - Если dll нет — пишем в errors.
    """
    result: List[str] = []
    deps_files = sorted(unpack_dir.rglob("*.deps.json"))

    if not deps_files:
        print("[*] .NET deps.json не найдены")
        return result

    for deps_path in deps_files:
        base_name = deps_path.name.removesuffix(".deps.json")
        expected_dll = deps_path.with_name(base_name + ".dll")

        if expected_dll.exists():
            result.append(str(deps_path))
            print(f"  [+] .NET приложение найдено: {deps_path}")
        else:
            msg = (
                f"[.NET] Найден {deps_path}, но рядом отсутствует "
                f"{expected_dll.name}"
            )
            print(f"  [!] {msg}")
            errors.append(msg)

    print(f"[*] Найдено .NET приложений: {len(result)}")
    return result


def find_java_artifacts(unpack_dir: Path, errors: List[str]) -> List[str]:
    """
    Найти Java артефакты: jar/war/ear.
    Если найдены .class файлы без jar/war/ear рядом — писать в errors.
    """
    result: List[str] = []

    for ext in ["*.jar", "*.war", "*.ear"]:
        for path in unpack_dir.rglob(ext):
            result.append(str(path))
            print(f"  [+] Java артефакт найден: {path}")

    class_dirs = set()
    for path in unpack_dir.rglob("*.class"):
        class_dirs.add(path.parent)

    for class_dir in sorted(class_dirs):
        archives = []
        for ext in ("*.jar", "*.war", "*.ear"):
            archives.extend(class_dir.glob(ext))

        if not archives:
            msg = f"[Java] .class файлы найдены без jar/war/ear рядом: {class_dir}"
            print(f"  [!] {msg}")
            errors.append(msg)

    print(f"[*] Найдено Java артефактов: {len(result)}")
    return result


def collect_sbom(target: str) -> Optional[Dict[str, Any]]:
    """Получить SBOM через syft для бинарников, deps.json и jar/war/ear."""
    result = subprocess.run(
        ["syft", "packages", target, "-o", "cyclonedx-json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"  [!] syft ошибка для {target}: {result.stderr.strip()}")
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  [!] Не удалось распарсить JSON для {target}")
        return None


def build_merged_sbom(source_sboms: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Собрать единый SBOM.

    У каждого компонента в properties появится source-binary — список источников,
    из которых этот компонент был собран.
    """
    if not source_sboms:
        return {}

    merged = dict(source_sboms[0][1])
    merged["components"] = []

    components_map: Dict[str, Dict[str, Any]] = {}

    for source_path, sbom in source_sboms:
        source_name = Path(source_path).name

        for component in sbom.get("components", []) or []:
            if not isinstance(component, dict):
                continue

            purl = component.get("purl") or component.get("name")
            if not purl:
                continue

            if purl not in components_map:
                comp = dict(component)
                props = comp.get("properties")
                if not isinstance(props, list):
                    props = []
                comp["properties"] = list(props) + [
                    {"name": "source-binary", "value": source_name}
                ]
                components_map[purl] = comp
            else:
                props = components_map[purl].get("properties")
                if not isinstance(props, list):
                    props = []
                    components_map[purl]["properties"] = props

                existing_sources = [
                    p.get("value")
                    for p in props
                    if isinstance(p, dict) and p.get("name") == "source-binary"
                ]
                if source_name not in existing_sources:
                    props.append({"name": "source-binary", "value": source_name})

    merged["components"] = list(components_map.values())

    total = len(merged["components"])
    shared = sum(
        1
        for c in merged["components"]
        if sum(
            1 for p in c.get("properties", []) or []
            if isinstance(p, dict) and p.get("name") == "source-binary"
        ) > 1
    )

    print(f"[*] Итого уникальных компонентов: {total}")
    print(f"[*] Из них общих для нескольких источников: {shared}")
    return merged


def get_purl_ecosystem(purl: str) -> Optional[str]:
    """
    Извлечь экосистему из purl.
    pkg:golang/... -> golang
    pkg:maven/...  -> maven
    pkg:nuget/...  -> nuget
    pkg:cargo/...  -> cargo
    pkg:generic/.. -> generic
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    try:
        return purl.split(":", 1)[1].split("/", 1)[0].lower()
    except IndexError:
        return None


def build_purl_map(sbom: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    purl -> компонент.
    Исключает компоненты:
    - без purl
    - с экосистемой generic
    """
    result: Dict[str, Dict[str, Any]] = {}
    for c in sbom.get("components", []) or []:
        if not isinstance(c, dict):
            continue
        purl = c.get("purl")
        if not purl:
            continue
        if get_purl_ecosystem(str(purl)) == "generic":
            continue
        result[str(purl)] = c
    return result


def build_dep_graph(sbom: Dict[str, Any]) -> Dict[str, List[str]]:
    """ref -> [dependsOn purl, ...]"""
    graph: Dict[str, List[str]] = {}
    for dep in sbom.get("dependencies", []) or []:
        if not isinstance(dep, dict):
            continue
        ref = dep.get("ref")
        depends_on = dep.get("dependsOn", [])
        if ref:
            graph[str(ref)] = [str(x) for x in depends_on if x]
    return graph


def find_chain_to(target_purl: str, graph: Dict[str, List[str]]) -> List[List[str]]:
    """
    Найти все цепочки от корневых зависимостей до target_purl.
    Возвращает список цепочек, каждая — список purl от корня до target.
    """
    reverse: Dict[str, List[str]] = {}
    for parent, children in graph.items():
        for child in children:
            reverse.setdefault(child, []).append(parent)

    chains: List[List[str]] = []
    queue: List[List[str]] = [[target_purl]]
    visited_paths = set()

    while queue:
        path = queue.pop(0)
        current = path[0]
        parents = reverse.get(current, [])

        if not parents:
            chain_key = tuple(path)
            if chain_key not in visited_paths:
                visited_paths.add(chain_key)
                chains.append(list(path))
        else:
            for parent in parents:
                if parent not in path:
                    queue.append([parent] + path)

    return chains


def format_chain(chain: List[str], purl_map: Dict[str, Dict[str, Any]]) -> List[str]:
    """Форматировать цепочку как имя@версия."""
    result = []
    for purl in chain:
        comp = purl_map.get(purl)
        if comp:
            result.append(f"{comp.get('name', purl)}@{comp.get('version', '?')}")
        else:
            result.append(purl)
    return result


def make_key(comp: Dict[str, Any]) -> str:
    return f"{comp.get('name', '')}@{comp.get('version', '')}"


def build_binary_sbom(pkg_dir: Path, output_file: Path, unpack_dir: Path, errors_file: Path) -> int:
    print(f"[*] Источник пакетов: {pkg_dir}")
    print(f"[*] Выходной файл: {output_file}")

    if not pkg_dir.exists() or not pkg_dir.is_dir():
        print(f"[!] Каталог не найден: {pkg_dir}", file=sys.stderr)
        return 1

    require_tools(["syft", "strings", "file"])

    has_go = check_tool("go")
    if not has_go:
        print("[!] go не найден — Go бинарники будут пропущены")

    prepare_unpack_dir(unpack_dir)

    errors: List[str] = []

    try:
        unpack_debs(pkg_dir, unpack_dir)
        unpack_rpms(pkg_dir, unpack_dir)
    except subprocess.CalledProcessError as e:
        print(f"[!] Ошибка распаковки: {e}", file=sys.stderr)
        return 1

    source_sboms: List[Tuple[str, Dict[str, Any]]] = []
    seen_targets = set()

    print("[*] Ищу ELF-бинарники...")
    binaries = find_elf_binaries(unpack_dir)

    for binary in binaries:
        print(f"[*] Проверяю бинарник {binary}")
        sbom = None

        if has_go and is_go_binary(binary):
            print("  [+] Go бинарник — собираю SBOM")
            sbom = collect_sbom(binary)
        elif is_rust_binary(binary):
            print("  [+] Rust бинарник — собираю SBOM")
            sbom = collect_sbom(binary)
        else:
            print("  [-] Пропускаю — не Go/Rust")

        if sbom and binary not in seen_targets:
            source_sboms.append((binary, sbom))
            seen_targets.add(binary)

    print("[*] Ищу .NET приложения...")
    dotnet_apps = find_dotnet_apps(unpack_dir, errors)

    for deps_json in dotnet_apps:
        print(f"[*] Собираю SBOM для .NET: {deps_json}")
        sbom = collect_sbom(deps_json)
        if sbom and deps_json not in seen_targets:
            source_sboms.append((deps_json, sbom))
            seen_targets.add(deps_json)

    print("[*] Ищу Java артефакты...")
    java_artifacts = find_java_artifacts(unpack_dir, errors)

    for artifact in java_artifacts:
        print(f"[*] Собираю SBOM для Java: {artifact}")
        sbom = collect_sbom(artifact)
        if sbom and artifact not in seen_targets:
            source_sboms.append((artifact, sbom))
            seen_targets.add(artifact)

    if errors:
        errors_file.write_text("\n".join(errors) + "\n", encoding="utf-8")
        print(f"[!] Проблемы записаны в {errors_file} ({len(errors)} шт.)")
    else:
        print("[+] Ошибок не найдено")

    if not source_sboms:
        print("[!] Ни одного источника для SBOM не найдено")
        return 1

    print(f"[*] Собираю единый SBOM из {len(source_sboms)} источников...")
    merged = build_merged_sbom(source_sboms)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"[+] Готово: {output_file}")

    stdlib = [c for c in merged.get("components", []) if isinstance(c, dict) and c.get("name") == "stdlib"]
    if stdlib:
        versions = sorted({c.get("version", "unknown") for c in stdlib})
        print(f"[+] Go stdlib версии: {versions}")

    return 0


def diff_source_binary(source_path: Path, binary_path: Path, output_dir: Path, all_deps: bool) -> int:
    if all_deps:
        print("[*] Режим: --all-deps — в финальный SBOM войдут все зависимости из source")
    else:
        print(f"[*] Режим: по умолчанию — только экосистемы: {', '.join(sorted(BINARY_ECOSYSTEMS))}")

    print(f"[*] Загружаю source SBOM: {source_path}")
    source_sbom = json.loads(source_path.read_text(encoding="utf-8"))

    print(f"[*] Загружаю binary SBOM: {binary_path}")
    binary_sbom = json.loads(binary_path.read_text(encoding="utf-8"))

    output_dir.mkdir(parents=True, exist_ok=True)

    source_map = build_purl_map(source_sbom)
    binary_map = build_purl_map(binary_sbom)

    print(f"[*] Компонентов в source SBOM (без generic): {len(source_map)}")
    print(f"[*] Компонентов в binary SBOM (без generic): {len(binary_map)}")

    binary_keys = {make_key(c) for c in binary_map.values()}
    print(f"[*] Уникальных name@version в binary: {len(binary_keys)}")

    def is_relevant(purl: str) -> bool:
        if all_deps:
            return True
        eco = get_purl_ecosystem(purl)
        return eco in BINARY_ECOSYSTEMS

    candidate_purls = {purl for purl in source_map if is_relevant(purl)}
    irrelevant_purls = {purl for purl in source_map if not is_relevant(purl)}

    skipped = len(irrelevant_purls)
    if skipped > 0:
        print(f"[*] Пропущено компонентов из других экосистем: {skipped}")

    missing_purls = [
        purl for purl in candidate_purls
        if make_key(source_map[purl]) not in binary_keys
    ]

    print(f"[*] Компонентов в source но не в binary: {len(missing_purls)}")

    dep_graph = build_dep_graph(source_sbom)

    ghost_report = []
    for purl in missing_purls:
        comp = source_map[purl]
        chains = find_chain_to(purl, dep_graph)
        formatted_chains = [format_chain(c, source_map) for c in chains]

        ghost_report.append({
            "name": comp.get("name"),
            "version": comp.get("version"),
            "purl": purl,
            "ecosystem": get_purl_ecosystem(purl),
            "type": comp.get("type"),
            "dependency_chains": formatted_chains if formatted_chains else [[make_key(comp)]],
        })

    ghost_report.sort(key=lambda x: (x.get("ecosystem") or "", x.get("name") or ""))

    ghost_path = output_dir / "ghost-dependencies.json"
    ghost_path.write_text(json.dumps(ghost_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[+] Призрачные зависимости: {ghost_path}")

    ghost_txt_path = output_dir / "ghost-dependencies.txt"
    with ghost_txt_path.open("w", encoding="utf-8") as f:
        f.write(f"Зависимости из исходников не попавшие в бинарный SBOM: {len(ghost_report)}\n")
        f.write("=" * 80 + "\n\n")
        for item in ghost_report:
            f.write(f"{item['name']}@{item['version']}  [{item.get('ecosystem', '?')}]\n")
            f.write(f"  purl: {item['purl']}\n")
            if item["dependency_chains"]:
                f.write("  Цепочки зависимостей:\n")
                for chain in item["dependency_chains"]:
                    f.write(f"    {' -> '.join(chain)}\n")
            f.write("\n")
    print(f"[+] Текстовый отчёт: {ghost_txt_path}")

    exclude_purls = set(missing_purls) | irrelevant_purls

    all_source_purls = {
        c["purl"] for c in source_sbom.get("components", []) or []
        if isinstance(c, dict) and c.get("purl")
    }
    generic_and_missing_purls = {
        purl for purl in all_source_purls
        if get_purl_ecosystem(str(purl)) == "generic"
    }
    exclude_purls = exclude_purls | generic_and_missing_purls

    filtered_sbom = dict(source_sbom)
    filtered_sbom["components"] = [
        c for c in source_sbom.get("components", []) or []
        if isinstance(c, dict) and c.get("purl") and c.get("purl") not in exclude_purls
    ]

    filtered_deps = []
    for dep in source_sbom.get("dependencies", []) or []:
        if not isinstance(dep, dict):
            continue
        if dep.get("ref") in exclude_purls:
            continue
        filtered_dep = dict(dep)
        filtered_dep["dependsOn"] = [
            d for d in dep.get("dependsOn", []) or []
            if d not in exclude_purls
        ]
        filtered_deps.append(filtered_dep)
    filtered_sbom["dependencies"] = filtered_deps

    filtered_path = output_dir / "sbom-source-filtered.json"
    filtered_path.write_text(json.dumps(filtered_sbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[+] Отфильтрованный source SBOM: {filtered_path}")

    print("\n[*] Итог:")
    print(f"    Всего в source (включая generic/без purl): {len(source_sbom.get('components', []))}")
    print(f"    После фильтрации generic и без purl:       {len(source_map)}")
    print(f"    Из них релевантных экосистем:              {len(candidate_purls)}")
    print(f"    Нерелевантных экосистем:                   {len(irrelevant_purls)}")
    print(f"    Всего в binary:                            {len(binary_map)}")
    print(f"    Не попали в binary (призрачные):           {len(missing_purls)}")
    print(f"    Остались в filtered SBOM:                  {len(filtered_sbom['components'])}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build binary SBOM from .deb/.rpm packages and optionally compare source vs binary SBOM"
    )
    parser.add_argument(
        "pkg_dir",
        nargs="?",
        default=".",
        help="Directory with .deb/.rpm packages. Default: current directory",
    )
    parser.add_argument(
        "source_sbom",
        nargs="?",
        default="",
        help="Optional source SBOM JSON. If provided, ghost-dependencies reports are generated",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="sbom-full.json",
        help="Output binary SBOM JSON path. Default: sbom-full.json",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory for ghost-dependencies reports. Default: current directory",
    )
    parser.add_argument(
        "--unpack-dir",
        default="./unpacked",
        help="Temporary unpack directory. It will be removed and recreated. Default: ./unpacked",
    )
    parser.add_argument(
        "--errors-output",
        default="errors.txt",
        help="Output text file for Java/.NET detection warnings. Default: errors.txt",
    )
    parser.add_argument(
        "--all-deps",
        action="store_true",
        help="When source SBOM is provided, check/keep all ecosystems instead of only Go/Rust/Maven/NuGet",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    pkg_dir = Path(args.pkg_dir).resolve()
    output_file = Path(args.output).resolve()
    unpack_dir = Path(args.unpack_dir).resolve()
    errors_file = Path(args.errors_output).resolve()

    rc = build_binary_sbom(pkg_dir, output_file, unpack_dir, errors_file)
    if rc != 0:
        return rc

    if args.source_sbom:
        return diff_source_binary(
            source_path=Path(args.source_sbom).resolve(),
            binary_path=output_file,
            output_dir=Path(args.output_dir).resolve(),
            all_deps=bool(args.all_deps),
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
