# sbom_tool.py

Инструмент для генерации **Software Bill of Materials (SBOM)** в формате [CycloneDX 1.6](https://cyclonedx.org/).  
Поддерживает RPM, DEB, WHL пакеты, бинарный анализ, CVE-сканирование и полный пайплайн в одну команду.

---

## Быстрый старт

```bash
# Всё в одной папке — скрипт сам определит что сканировать
python3 sbom_tool.py --scan-full ./packages --compare-root ./RPM_disk

# + CVE-скан
python3 sbom_tool.py --scan-full ./packages --compare-root ./RPM_disk --cve-branch c10f2
```

---

## Режимы

```
python3 sbom_tool.py --scan-full <dir> --compare-root <dir> [options]
python3 sbom_tool.py --rpm <scan_target> --compare-root <dir> [options]
python3 sbom_tool.py --deb <folder> [package_list.txt] [options]
python3 sbom_tool.py --binary-repack <pkg_dir> [options]
```

Справка по режиму:

```bash
python3 sbom_tool.py --scan-full --help
python3 sbom_tool.py --rpm --help
python3 sbom_tool.py --deb --help
python3 sbom_tool.py --binary-repack --help
```

---

## Режим `--scan-full` ★

Принимает одну директорию, **автоматически определяет** какие типы пакетов в ней есть и запускает нужные шаги. На выходе отдельные SBOM по каждому типу и итоговый `merged.json`.

### Синтаксис

```
python3 sbom_tool.py --scan-full <scan_dir> [options]
```

| Аргумент | Описание |
|---|---|
| `scan_dir` | Директория с пакетами (`.rpm`, `.deb`, `.whl`, архивы — всё вместе) |

### Авто-детекция

| Найдено в директории | Запускаемый шаг | Выходной файл |
|---|---|---|
| `.rpm` | rpm-скан через syft + обогащение | `alt.json` |
| `.deb` | deb-скан (чтение control.tar) | `deb.json` |
| `.whl` или архивы (`.zip`, `.jar`, `.tar.gz` и др.) | binary-repack (sbom_binary + Trivy) | `binary.json` |
| Всё вместе | все три шага | + `merged.json` |

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--compare-root <dir>` | — | Эталонные RPM (обязателен если найдены `.rpm`) |
| `--no-cve-rpm` | — | Отключить CVE-скан после rpm-шага |
| `--cve-branch` | (все) | Ветка Alt Linux: `p9`, `p10`, `p11`, `c9f2`, `c10f2` |
| `--cve-output <file>` | `cve_report_alt.xlsx` | Путь к CVE-отчёту |
| `--package-list <file>` | — | TXT со списком deb-пакетов для маркировки `GOST:provided_by` |
| `--with-dependencies` | — | Граф зависимостей между .deb пакетами |
| `--source-sbom <file>` | — | Source SBOM для ghost-dependency diff (binary-repack шаг) |
| `--max-depth <N>` | `8` | Глубина вложенности архивов для Trivy |
| `-o`, `--output <file>` | `merged.json` | Итоговый объединённый SBOM |
| `--output-dir <dir>` | `./debug` | Директория для debug-файлов |

### Примеры

```bash
# Базовый — только rpm
python3 sbom_tool.py --scan-full ./packages \
  --compare-root ./RPM_disk

# rpm + CVE
python3 sbom_tool.py --scan-full ./packages \
  --compare-root ./RPM_disk \
  --cve-branch c10f2

# deb + whl (compare-root не нужен)
python3 sbom_tool.py --scan-full ./packages

# Всё вместе
python3 sbom_tool.py --scan-full ./packages \
  --compare-root ./RPM_disk \
  --cve-branch c10f2 \
  -o merged.json
```

---

## Режим `--rpm`

Запускает **syft** на директории с RPM-файлами, обогащает компоненты (SHA-256, buildhost), сравнивает с эталоном, запускает CVE-сканер.

### Синтаксис

```
python3 sbom_tool.py --rpm <scan_target> --compare-root <dir> [options]
```

| Аргумент | Описание |
|---|---|
| `scan_target` | Директория с RPM-файлами для сканирования через syft |
| `--compare-root <dir>` | **(обязательно)** Эталонные RPM — для SHA-256 сравнения и матчинга по имени/версии |

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-o`, `--output <file>` | `alt.json` | Путь к выходному SBOM |
| `--report <file>` | `debug/report.txt` | Отчёт о расхождениях версий |
| `--no-cve-rpm` | — | Отключить CVE-скан |
| `--cve-branch` | (все) | Ветка Alt Linux: `p9`, `p10`, `p11`, `c9f2`, `c10f2` |
| `--cve-output <file>` | `cve_report_alt.xlsx` | Путь к CVE-отчёту |
| `--cve-json` | — | CVE-результаты в JSON вместо XLSX |
| `--cve-verbose` | — | Подробный лог `scan_cve.log` |
| `--cve-no-cache` | — | Игнорировать кэш ALT OVAL |
| `--cve-update-cache` | — | Обновить кэш ALT OVAL |
| `--remove-cert` | — | Удалить `GOST:provided_by` до финального этапа |
| `--keep-intermediate` | — | Сохранить исходный JSON от syft |
| `--debug` | — | Диагностика матчинга в stderr |

### Примеры

```bash
python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk

python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk \
  --cve-branch c10f2 \
  -o alt.json \
  --cve-output cve_report_alt.xlsx
```

### Выходные файлы

| Файл | Описание |
|---|---|
| `alt.json` | Обогащённый CycloneDX SBOM |
| `cve_report_alt.xlsx` | CVE-отчёт по пакетам |
| `debug/report.txt` | Расхождения версий между SBOM и эталоном |

#### Столбцы `cve_report_alt.xlsx`

| Столбец | Описание |
|---|---|
| `package` | Имя пакета |
| `version` | Версия пакета |
| `source_rpm` | Имя source RPM-файла |
| `buildhost` | Хост сборки |
| `gost_provider` | `yes` если помечен `GOST:provided_by=Alt Linux` |
| `ecosystem` | Экосистема (rpm, pypi, npm и др.) |
| `latest_by_branch` | Последние версии по веткам Alt Linux |
| `max_severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `findings_cve` | Количество CVE |
| `vuln_ids` | Идентификаторы уязвимостей |

### Что делает инструмент

1. Запускает `syft` → базовый CycloneDX SBOM
2. Вычисляет SHA-256 и `buildhost` для каждого RPM
3. Сравнивает с эталоном по SHA-256 → `GOST:provided_by=Alt Linux`
4. Сверяет имена/версии с эталоном → `debug/report.txt`
5. Добавляет GOST-поля всем компонентам
6. Сортирует по экосистеме
7. Запускает CVE-сканер

---

## Режим `--deb`

Сканирует `.deb`-файлы, читает метаданные напрямую из архивов без установки пакетов.

### Синтаксис

```
python3 sbom_tool.py --deb <folder> [package_list.txt] [options]
```

| Аргумент | Описание |
|---|---|
| `folder` | Директория с `.deb`-файлами |
| `package_list.txt` | *(необязательно)* Список пакетов — отсутствующие получают `GOST:provided_by=Astra Linux` |

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-o`, `--output <file>` | `deb.json` | Путь к выходному SBOM |
| `--with-dependencies` | — | Граф зависимостей между пакетами |
| `--errors-output <file>` | `debug/deb.errors.json` | Файл ошибок обработки |

### Примеры

```bash
python3 sbom_tool.py --deb ./debs
python3 sbom_tool.py --deb ./debs package-list.txt --with-dependencies
```

### Формат `package_list.txt`

```
libfoo_1.2.3-1_amd64.deb
libbar_4.5.6_all.deb
# строки с # игнорируются
```

### Выходные файлы

| Файл | Описание |
|---|---|
| `deb.json` | CycloneDX SBOM |
| `debug/deb.errors.json` | Пакеты, которые не удалось обработать |

---

## Режим `--binary-repack`

Запускает `sbom_binary.py` и `sbom_repack_deps.py` на одной директории, используя общую директорию распаковки.

### Синтаксис

```
python3 sbom_tool.py --binary-repack <pkg_dir> [options]
```

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--unpack-dir <dir>` | `./unpacked` | Общая директория распаковки |
| `--binary-output <file>` | `binary.json` | Выходной файл `sbom_binary.py` |
| `--repack-output <file>` | `repack.cdx.json` | Выходной файл `sbom_repack_deps.py` |
| `--output-dir <dir>` | `./debug` | Директория для отчётов |
| `--max-depth <N>` | `8` | Глубина вложенности архивов |
| `--all-deps` | — | Учитывать все экосистемы при diff |
| `--trivy-arg <arg>` | — | Дополнительный аргумент для Trivy |

### Примеры

```bash
python3 sbom_tool.py --binary-repack ./packages
python3 sbom_tool.py --binary-repack ./wheels        # .whl файлы
python3 sbom_tool.py --binary-repack ./packages source-sbom.json  # с diff
```

### Выходные файлы

| Файл | Описание |
|---|---|
| `binary.json` | Бинарный SBOM (Go/Rust/.NET/Java) |
| `repack.cdx.json` | CycloneDX SBOM от Trivy |
| `debug/binary_filtered.json` | Source SBOM после удаления призрачных зависимостей |
| `debug/ghost_dependencies.json` | Призрачные зависимости (JSON) |
| `debug/ghost_dependencies.txt` | Призрачные зависимости (текст) |
| `debug/binary.errors.txt` | Предупреждения Java/.NET |
| `debug/repack.stats.json` | Статистика распаковки |

---

## `sbom_binary.py` — бинарный SBOM (прямой вызов)

```
python3 sbom_binary.py <pkg_dir> [source_sbom.json] [options]
```

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-o`, `--output <file>` | `binary.json` | Выходной SBOM |
| `--output-dir <dir>` | `./debug` | Директория для отчётов |
| `--unpack-dir <dir>` | `./unpacked` | Временная директория распаковки |
| `--errors-output <file>` | `./debug/binary.errors.txt` | Предупреждения Java/.NET |
| `--all-deps` | — | Учитывать все экосистемы при diff |

Распаковывает `.deb`/`.rpm`, находит Go/Rust/.NET/Java артефакты, собирает SBOM через syft. При передаче `source_sbom.json` — выявляет призрачные зависимости.

---

## `sbom_repack_deps.py` — рекурсивная распаковка + Trivy (прямой вызов)

```
python3 sbom_repack_deps.py <input> [options]
```

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-o`, `--output <file>` | `repack.cdx.json` | Выходной SBOM |
| `--unpack-dir <dir>` | `./repacked-deps` | Директория распаковки |
| `--max-depth <N>` | `8` | Глубина вложенности |
| `--stats-output <file>` | `./debug/repack.stats.json` | Статистика |
| `--trivy-arg <arg>` | — | Доп. аргумент для Trivy |

Поддерживаемые форматы: `.deb`, `.rpm`, `.zip`, `.jar`, `.war`, `.ear`, `.whl`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, `.gz`, `.bz2`, `.xz`, `.lzma`, `.zst`, `.7z`

---

## `sbom_whl.py` — Python wheel SBOM (прямой вызов)

```
python3 sbom_whl.py <input_dir> [options]
```

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-o`, `--output <file>` | `whl.json` | Выходной SBOM |
| `--errors-output <file>` | `debug/whl.errors.json` | Файл ошибок |

Читает METADATA из каждого `.whl`, нормализует имя по PEP 503, строит `pkg:pypi/<name>@<version>`.

```
deepdiff-6.2.2-py3-none-any.whl   → pkg:pypi/deepdiff@6.2.2
scikit_learn-1.3.0-...-any.whl    → pkg:pypi/scikit-learn@1.3.0
Pillow-10.0.0-...-any.whl         → pkg:pypi/pillow@10.0.0
```

> `sbom_whl.py` вызывается автоматически из `--rpm` и `--deb` если в сканируемой директории найдены `.whl` файлы — результат мержится в основной SBOM.

---

## Зависимости

| Инструмент / библиотека | Нужен для |
|---|---|
| `syft` | `--rpm`, `sbom_binary.py` |
| `rpm` (CLI) | `--rpm` (запрос buildhost) |
| `trivy` | `sbom_repack_deps.py` |
| `dpkg-deb` | `sbom_binary.py`, `sbom_repack_deps.py` |
| `rpm2cpio` + `cpio` | `sbom_binary.py`, `sbom_repack_deps.py` |
| `go` (CLI) | `sbom_binary.py` (опционально) |
| `strings`, `file` | `sbom_binary.py` |
| `7z` / `7za` | `sbom_repack_deps.py` (опционально) |
| `zstd` / `unzstd` | `sbom_repack_deps.py` (опционально) |
| `requests` | `sbom_alt_cve_working.py` |
| `openpyxl` | `sbom_alt_cve_working.py` |

```bash
pip install requests openpyxl
```

---

## Сводная таблица выходных файлов

| Файл | Режим | Описание |
|---|---|---|
| `merged.json` | `--scan-full` | Итоговый объединённый SBOM |
| `alt.json` | `--rpm` | Обогащённый CycloneDX SBOM (Alt Linux) |
| `cve_report_alt.xlsx` | `--rpm` | CVE-отчёт |
| `deb.json` | `--deb` | CycloneDX SBOM из .deb-пакетов |
| `binary.json` | `--binary-repack` | Бинарный SBOM |
| `repack.cdx.json` | `--binary-repack` | CycloneDX SBOM от Trivy |
| `debug/report.txt` | `--rpm` | Расхождения версий с эталоном |
| `debug/deb.errors.json` | `--deb` | Ошибки обработки .deb |
| `debug/binary_filtered.json` | `sbom_binary.py` | Source SBOM без призрачных зависимостей |
| `debug/ghost_dependencies.json` | `sbom_binary.py` | Призрачные зависимости (JSON) |
| `debug/ghost_dependencies.txt` | `sbom_binary.py` | Призрачные зависимости (текст) |
| `debug/binary.errors.txt` | `sbom_binary.py` | Предупреждения Java/.NET |
| `debug/repack.stats.json` | `sbom_repack_deps.py` | Статистика распаковки |
| `debug/whl.errors.json` | `sbom_whl.py` | Ошибки обработки .whl |

---

## GOST-поля в SBOM

| Свойство | Значение | Описание |
|---|---|---|
| `GOST:attack_surface` | `no` | Признак поверхности атаки |
| `GOST:security_function` | `no` | Признак функции безопасности |
| `GOST:provided_by` | `Alt Linux` / `Astra Linux` | Поставщик (только для идентифицированных) |
| `rpm:sha256` | `<hash>` | SHA-256 RPM-файла |
| `rpm:buildhost` | `<host>` | Хост сборки пакета |