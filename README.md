# sbom_tool.py

Инструмент для генерации **Software Bill of Materials (SBOM)** в формате [CycloneDX 1.6](https://cyclonedx.org/).  
Поддерживает RPM- и DEB-пакеты, обогащение метаданными, сравнение с эталоном и CVE-сканирование.

---

## Соглашение об именовании файлов

| Тип файла | Куда пишется |
|---|---|
| Основные SBOM (`sbom_*.json`) | рабочая директория |
| CVE-отчёт (`cve_report_alt.xlsx`) | рабочая директория |
| Побочные файлы (отчёты, ошибки, статистика) | `./debug/` |

---

## Использование

```
python3 sbom_tool.py --rpm <scan_target> --compare-root <dir> [options]
python3 sbom_tool.py --deb <folder> [package_list.txt] [options]
```

Справка по режиму:

```bash
python3 sbom_tool.py --rpm --help
python3 sbom_tool.py --deb --help
```

---

## Режим `--rpm`

<<<<<<< HEAD
Запускает **syft** на директории с RPM-файлами, обогащает компоненты метаданными (SHA-256, buildhost), сравнивает с эталонными пакетами по SHA-256 и имени/версии, запускает CVE-сканер.
=======
Режим работает для ALT Linux: запускает инструмент **syft** на директории с RPM-файлами, обогащает компоненты метаданными (SHA-256, buildhost), сравнивает с эталонными пакетами по SHA-256 и имени/версии, запускает CVE-сканер.
>>>>>>> f97913e (init)

### Синтаксис

```
python3 sbom_tool.py --rpm <scan_target> --compare-root <dir> [options]
```

| Аргумент | Описание |
|---|---|
| `scan_target` | Директория с RPM-файлами для сканирования через syft |
| `--compare-root <dir>` | **(обязательно)** Директория с эталонными RPM. Используется и для сравнения по SHA-256, и для финального матчинга по имени/версии |

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
<<<<<<< HEAD
| `-o`, `--output <file>` | `updated_sbom.json` | Путь к выходному SBOM JSON |
| `--report <file>` | `report.txt` | Путь к текстовому отчёту о расхождениях версий |
=======
| `-o`, `--output <file>` | `alt.json` | Путь к выходному SBOM JSON |
| `--report <file>` | `debug/report.txt` | Путь к отчёту о расхождениях версий |
>>>>>>> f97913e (init)
| `--no-cve-rpm` | — | Отключить автоматический CVE-скан после генерации SBOM |
| `--cve-branch` | (все) | Ветка Alt Linux для CVE-скана: `p9`, `p10`, `p11`, `c9f2`, `c10f2` |
| `--cve-output <file>` | `cve_report_alt.xlsx` | Путь к CVE-отчёту в формате XLSX |
| `--cve-json` | — | Выводить CVE-результаты в JSON вместо XLSX |
| `--cve-verbose` | — | Писать подробный лог `scan_cve.log` |
| `--cve-no-cache` | — | Игнорировать кэш ALT OVAL при CVE-скане |
| `--cve-update-cache` | — | Обновить кэш ALT OVAL перед CVE-сканом |
| `--cve-rpm [args...]` | — | Передать произвольные аргументы CVE-сканеру напрямую |
| `--remove-cert` | — | Удалить `GOST:provided_by` у всех компонентов до финального этапа |
| `--keep-intermediate` | — | Сохранить исходный JSON от syft рядом с итоговым SBOM |
| `--debug` | — | Печатать диагностику матчинга в stderr |

### Примеры

```bash
# Базовый скан
python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk

# + CVE-скан по ветке c10f2
python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk \
  --cve-branch c10f2

<<<<<<< HEAD
# + CVE-скан по ветке p10
python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk \
  --cve-branch p10

# Указать выходные файлы явно
python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk \
  -o updated_sbom.json \
  --cve-output cve_report.xlsx
=======
# Указать выходные файлы явно
python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk \
  -o alt.json \
  --cve-output cve_report_alt.xlsx
>>>>>>> f97913e (init)

# Без CVE-скана
python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk \
  --no-cve-rpm
<<<<<<< HEAD

# CVE-скан с произвольными аргументами
python3 sbom_tool.py --rpm ./scan_target \
  --compare-root ./RPM_disk \
  --cve-rpm --c10f2 -o cve_report.xlsx
=======
>>>>>>> f97913e (init)
```

### Выходные файлы

| Файл | Описание |
|---|---|
| `alt.json` | Обогащённый CycloneDX SBOM |
| `cve_report_alt.xlsx` | CVE-отчёт по пакетам |
| `debug/report.txt` | Расхождения версий между SBOM и эталоном |

#### Столбцы листа CVE-отчёта (`cve_report_alt.xlsx`)

| Столбец | Описание |
|---|---|
| `package` | Имя пакета |
| `version` | Версия пакета |
| `source_rpm` | Имя source RPM-файла |
| `buildhost` | Хост сборки пакета |
| `gost_provider` | `yes` если пакет помечен `GOST:provided_by=Alt Linux` |
| `ecosystem` | Экосистема пакета (rpm, pypi, npm и др.) |
| `latest_by_branch` | Последние доступные версии по веткам Alt Linux |
| `max_severity` | Максимальная критичность CVE: CRITICAL / HIGH / MEDIUM / LOW |
| `findings_cve` | Количество найденных CVE |
| `vuln_ids` | Список идентификаторов уязвимостей (CVE-...) |

### Что делает инструмент в этом режиме

1. Запускает `syft` на `scan_target` → получает базовый CycloneDX SBOM
2. Для каждого RPM-файла в `scan_target` вычисляет SHA-256 и запрашивает `buildhost` через `rpm -qp`
3. Сравнивает пакеты по SHA-256 с эталонными RPM из `--compare-root`; совпавшие помечаются `GOST:provided_by=Alt Linux`
<<<<<<< HEAD
4. Финально сверяет имена/версии компонентов с теми же RPM из `--compare-root`; расхождения попадают в `report.txt`
=======
4. Финально сверяет имена/версии компонентов с теми же RPM из `--compare-root`; расхождения попадают в `debug/report.txt`
>>>>>>> f97913e (init)
5. Добавляет стандартные GOST-поля (`GOST:attack_surface=no`, `GOST:security_function=no`) всем компонентам
6. Сортирует компоненты по экосистеме (rpm → deb → npm → pypi → ...)
7. Запускает CVE-сканер (если не передан `--no-cve-rpm`)

---

## Режим `--deb`

Режим работает для Astra Linux: cканирует директорию с `.deb`-файлами и генерирует CycloneDX SBOM. Читает метаданные напрямую из архивов — установка пакетов не требуется.

### Синтаксис

```
python3 sbom_tool.py --deb <folder> [package_list.txt] [options]
```

| Аргумент | Описание |
|---|---|
| `folder` | Директория с `.deb`-файлами |
| `package_list.txt` | *(необязательно)* Список пакетов в формате Debian-имён файлов. Пакеты, **не найденные** в списке, получают `GOST:provided_by=Astra Linux` |

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-o`, `--output <file>` | `deb.json` | Путь к выходному SBOM JSON |
| `--with-dependencies` | — | Включить в SBOM граф внутренних зависимостей между пакетами |
| `--errors-output <file>` | `debug/deb.errors.json` | Путь к файлу с ошибками обработки |

### Примеры

```bash
# Просто просканировать папку
python3 sbom_tool.py --deb ./debs

# С фильтром по списку (остальные → Astra Linux)
python3 sbom_tool.py --deb ./debs package-list.txt

# С графом зависимостей
python3 sbom_tool.py --deb ./debs package-list.txt \
  --with-dependencies
```

### Формат `package_list.txt`

Каждая строка — имя `.deb`-файла в стандартном формате Debian:

```
libfoo_1.2.3-1_amd64.deb
libbar_4.5.6_all.deb
# строки с # — комментарии и игнорируются
```

Пакеты из `folder`, **присутствующие** в списке — включаются в SBOM как есть.  
Пакеты, **отсутствующие** в списке — получают свойство `GOST:provided_by=Astra Linux`.

### Выходные файлы

| Файл | Описание |
|---|---|
| `deb.json` | CycloneDX SBOM из .deb-пакетов |
| `debug/deb.errors.json` | Пакеты, которые не удалось обработать |

### Что делает инструмент в этом режиме

1. Рекурсивно находит все `.deb`-файлы в `folder`
2. Для каждого читает `control.tar.*` прямо из `.deb`-архива (без распаковки на диск)
3. Извлекает метаданные: `Package`, `Version`, `Architecture`, `Depends`, `Homepage` и др.
4. Вычисляет SHA-256 каждого файла
5. Если передан `package_list.txt` — применяет правила маркировки `GOST:provided_by`
6. Если передан `--with-dependencies` — строит граф зависимостей по полям `Depends` и `Pre-Depends`
7. Сортирует компоненты по экосистеме и записывает CycloneDX SBOM

---

## `sbom_binary.py` — бинарный SBOM

Распаковывает `.deb`/`.rpm` пакеты, ищет внутри Go/Rust/.NET/Java артефакты, собирает по ним SBOM через syft. Опционально сравнивает исходный SBOM с бинарным и выявляет «призрачные» зависимости.

### Синтаксис

```
python3 sbom_binary.py <pkg_dir> [source_sbom.json] [options]
```

| Аргумент | Описание |
|---|---|
| `pkg_dir` | Директория с `.deb`/`.rpm` пакетами. По умолчанию: текущая директория |
| `source_sbom.json` | *(необязательно)* Source SBOM для сравнения с бинарным |

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-o`, `--output <file>` | `binary.json` | Путь к выходному бинарному SBOM |
| `--output-dir <dir>` | `./debug` | Директория для отчётов о призрачных зависимостях и отфильтрованного SBOM |
| `--unpack-dir <dir>` | `./unpacked` | Временная директория для распаковки (очищается перед запуском) |
| `--errors-output <file>` | `./debug/binary.errors.txt` | Файл с предупреждениями по Java/.NET |
| `--all-deps` | — | При сравнении учитывать все экосистемы, а не только Go/Rust/Maven/NuGet |

### Примеры

```bash
# Просто собрать бинарный SBOM
python3 sbom_binary.py ./packages

# Сравнить с исходным SBOM → отчёты в ./debug
python3 sbom_binary.py ./packages source-sbom.json

# Явно указать файлы
python3 sbom_binary.py ./packages source-sbom.json \
  -o binary.json \
  --output-dir ./debug

# Сравнение по всем экосистемам
python3 sbom_binary.py ./packages source-sbom.json --all-deps
```

### Выходные файлы

| Файл | Описание |
|---|---|
| `binary.json` | Объединённый бинарный CycloneDX SBOM |
| `debug/binary_filtered.json` | Source SBOM с удалёнными призрачными зависимостями |
| `debug/ghost_dependencies.json` | Зависимости из source-SBOM, не попавшие в бинарник (JSON) |
| `debug/ghost_dependencies.txt` | То же самое, читаемый текстовый формат с цепочками зависимостей |
| `debug/binary.errors.txt` | Предупреждения: `.deps.json` без `.dll`, `.class` без `.jar` и т.п. |

### Что делает скрипт

1. Распаковывает все `.deb` (через `dpkg-deb -x`) и `.rpm` (через `rpm2cpio | cpio`) из `pkg_dir`
2. Находит ELF-бинарники и определяет их тип: Go (`go version -m`), Rust (по строкам в бинарнике)
3. Находит `.NET` приложения по парам `*.deps.json` + `*.dll`
4. Находит Java артефакты: `*.jar`, `*.war`, `*.ear`
5. Для каждого найденного артефакта запускает `syft` и собирает CycloneDX SBOM
6. Объединяет все SBOM в один, дедуплицируя компоненты по `purl`
7. Если передан `source_sbom.json` — сравнивает с бинарным SBOM и формирует отчёты в `./debug`

---

## `sbom_repack_deps.py` — рекурсивная распаковка + Trivy

Рекурсивно распаковывает вложенные архивы любой глубины (`.deb`, `.rpm`, `.zip`, `.jar`, `.war`, `.whl`, `.tar.*`, `.gz`, `.7z` и др.), затем запускает **Trivy** на распакованном дереве и генерирует CycloneDX SBOM.

### Синтаксис

```
python3 sbom_repack_deps.py <input> [options]
```

| Аргумент | Описание |
|---|---|
| `input` | Файл или директория с пакетами/архивами |

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `-o`, `--output <file>` | `repack.cdx.json` | Путь к выходному CycloneDX SBOM |
| `--unpack-dir <dir>` | `./repacked-deps` | Директория для рекурсивной распаковки (очищается перед запуском) |
| `--max-depth <N>` | `8` | Максимальная глубина вложенности архивов |
| `--stats-output <file>` | `./debug/repack.stats.json` | JSON-файл со статистикой распаковки |
| `--trivy-arg <arg>` | — | Дополнительный аргумент для Trivy (повторять для нескольких) |
| `--keep-unpacked` | — | Принимается для совместимости; распакованная директория сохраняется всегда |

### Примеры

```bash
# Базовый запуск
python3 sbom_repack_deps.py ./packages

# .whl файлы
python3 sbom_repack_deps.py ./wheels

# Указать выходной файл
python3 sbom_repack_deps.py ./packages -o repack.cdx.json

# Ограничить глубину вложенности
python3 sbom_repack_deps.py ./packages --max-depth 5

# Передать дополнительные флаги в Trivy
python3 sbom_repack_deps.py ./packages \
  --trivy-arg=--skip-dirs \
  --trivy-arg=vendor
```

### Поддерживаемые форматы архивов

`.deb`, `.rpm`, `.zip`, `.jar`, `.war`, `.ear`, `.whl`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, `.gz`, `.bz2`, `.xz`, `.lzma`, `.zst`, `.7z`

### Выходные файлы

| Файл | Описание |
|---|---|
| `repack.cdx.json` | CycloneDX SBOM от Trivy |
| `debug/repack.stats.json` | Статистика: кол-во архивов, файлов, ошибок распаковки |

### Что делает скрипт

1. Обходит входную директорию (или файл) и ставит все архивы в очередь на распаковку
2. Для каждого архива создаёт уникальную поддиректорию и извлекает содержимое безопасным методом (без path traversal, без symlink-атак)
3. Найденные внутри вложенные архивы добавляет обратно в очередь (до достижения `--max-depth`)
4. Не-архивные файлы верхнего уровня копирует в `raw-files/`
5. После завершения распаковки запускает `trivy fs --format cyclonedx` на всём дереве
6. Сохраняет статистику в `debug/`

---

## Зависимости

| Инструмент / библиотека | Нужен для |
|---|---|
| `syft` | `--rpm`, `sbom_binary.py` |
| `rpm` (CLI) | `--rpm` (запрос buildhost) |
| `trivy` | `sbom_repack_deps.py` |
| `dpkg-deb` | `sbom_binary.py`, `sbom_repack_deps.py` (распаковка .deb) |
| `rpm2cpio` + `cpio` | `sbom_binary.py`, `sbom_repack_deps.py` (распаковка .rpm) |
| `go` (CLI) | `sbom_binary.py` (определение Go-бинарников; опционально) |
| `strings`, `file` | `sbom_binary.py` (определение Rust-бинарников) |
| `7z` или `7za` | `sbom_repack_deps.py` (только для `.7z` архивов; опционально) |
| `zstd` или `unzstd` | `sbom_repack_deps.py` (только для `.zst` архивов; опционально) |
| `requests` | `sbom_alt_cve_working.py` (загрузка ALT OVAL) |
| `openpyxl` | `sbom_alt_cve_working.py` (генерация XLSX-отчёта) |

Установка Python-зависимостей:

```bash
pip install requests openpyxl
```

---

## Сводная таблица выходных файлов

| Файл | Скрипт/режим | Описание |
|---|---|---|
<<<<<<< HEAD
| `updated_sbom.json` | `--rpm` | Обогащённый CycloneDX SBOM |
| `report.txt` | `--rpm` | Расхождения версий между SBOM и эталоном |
| `cve_report.xlsx` | `--rpm` | CVE-отчёт по пакетам |
| `sbom.json` | `--deb` | CycloneDX SBOM из .deb-пакетов |
| `sbom.errors.json` | `--deb` | Пакеты, которые не удалось обработать |
| `sbom-full.json` | `sbom_binary.py` | Объединённый бинарный SBOM |
| `ghost-dependencies.json` | `sbom_binary.py` | Призрачные зависимости (JSON) |
| `ghost-dependencies.txt` | `sbom_binary.py` | Призрачные зависимости (текст) |
| `sbom-source-filtered.json` | `sbom_binary.py` | Отфильтрованный source SBOM |
| `errors.txt` | `sbom_binary.py` | Предупреждения Java/.NET |
| `sbom-repacked-trivy.cdx.json` | `sbom_repack_deps.py` | CycloneDX SBOM от Trivy |
| `repack-deps.stats.json` | `sbom_repack_deps.py` | Статистика распаковки |
=======
| `alt.json` | `--rpm` | Обогащённый CycloneDX SBOM (Alt Linux) |
| `cve_report_alt.xlsx` | `--rpm` | CVE-отчёт по пакетам |
| `deb.json` | `--deb` | CycloneDX SBOM из .deb-пакетов |
| `binary.json` | `sbom_binary.py` | Объединённый бинарный SBOM |
| `repack.cdx.json` | `sbom_repack_deps.py` | CycloneDX SBOM от Trivy |
| `debug/report.txt` | `--rpm` | Расхождения версий между SBOM и эталоном |
| `debug/deb.errors.json` | `--deb` | Пакеты .deb, которые не удалось обработать |
| `debug/binary_filtered.json` | `sbom_binary.py` | Source SBOM после удаления призрачных зависимостей |
| `debug/ghost_dependencies.json` | `sbom_binary.py` | Призрачные зависимости (JSON) |
| `debug/ghost_dependencies.txt` | `sbom_binary.py` | Призрачные зависимости (текст) |
| `debug/binary.errors.txt` | `sbom_binary.py` | Предупреждения Java/.NET |
| `debug/repack.stats.json` | `sbom_repack_deps.py` | Статистика распаковки |
>>>>>>> f97913e (init)

---

## GOST-поля в SBOM

Инструмент добавляет следующие свойства (`properties`) к компонентам:

| Свойство | Значение | Описание |
|---|---|---|
| `GOST:attack_surface` | `no` | Признак поверхности атаки |
| `GOST:security_function` | `no` | Признак функции безопасности |
| `GOST:provided_by` | `Alt Linux` / `Astra Linux` | Поставщик пакета (только для идентифицированных) |
| `rpm:sha256` | `<hash>` | SHA-256 RPM-файла |
| `rpm:buildhost` | `<host>` | Хост сборки пакета |
