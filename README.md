# sbom_tool.py

Инструмент для генерации **Software Bill of Materials (SBOM)** в формате [CycloneDX 1.6](https://cyclonedx.org/).  
Поддерживает RPM- и DEB-пакеты, обогащение метаданными, сравнение с эталоном и CVE-сканирование.

---

## Использование

```
python3 sbom_tool.py --rpm <scan_target> <rpm_dir> [options]
python3 sbom_tool.py --deb <folder> [package_list.txt] [options]
```

Справка по режиму:

```bash
python3 sbom_tool.py --rpm --help
python3 sbom_tool.py --deb --help
```

---

## Режим `--rpm`

Запускает **syft** на директории с RPM-файлами, обогащает компоненты метаданными (SHA-256, buildhost), опционально сравнивает с эталонными пакетами и запускает CVE-сканер.

### Синтаксис

```
python3 sbom_tool.py --rpm <scan_target> <rpm_dir> [options]
```

| Аргумент | Описание |
|---|---|
| `scan_target` | Директория с RPM-файлами для сканирования через syft |
| `rpm_dir` | Директория с RPM-файлами для финального сравнения имён/версий |

### Опции

| Флаг | По умолчанию | Описание |
|---|---|---|
| `--compare-root <dir>` | — | Директория с эталонными RPM для сравнения по SHA-256. Совпавшие пакеты получают `GOST:provided_by=Alt Linux` |
| `-o`, `--output <file>` | `updated_sbom.json` | Путь к выходному SBOM JSON |
| `--report <file>` | `report.txt` | Путь к текстовому отчёту о расхождениях версий |
| `--no-cve-rpm` | — | Отключить автоматический CVE-скан после генерации SBOM |
| `--cve-branch` | (все) | Ветка Alt Linux для CVE-скана: `p9`, `p10`, `p11`, `c9f2`, `c10f2` |
| `--cve-output <file>` | `cve_report.xlsx` | Путь к CVE-отчёту в формате XLSX |
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
python3 sbom_tool.py --rpm ./scan_target ./RPM_disk

# + сравнение с эталонными RPM
python3 sbom_tool.py --rpm ./scan_target ./RPM_disk \
  --compare-root ./reference_rpms

# + CVE-скан по ветке c10f2
python3 sbom_tool.py --rpm ./scan_target ./RPM_disk \
  --compare-root ./reference_rpms \
  --cve-branch c10f2

# Указать выходные файлы явно
python3 sbom_tool.py --rpm ./scan_target ./RPM_disk \
  --compare-root ./reference_rpms \
  -o updated_sbom.json \
  --cve-output cve_report.xlsx

# Без CVE-скана
python3 sbom_tool.py --rpm ./scan_target ./RPM_disk \
  --no-cve-rpm

# CVE-скан с произвольными аргументами
python3 sbom_tool.py --rpm ./scan_target ./RPM_disk \
  --cve-rpm --c10f2 -o cve_report.xlsx
```

### Что делает инструмент в этом режиме

1. Запускает `syft` на `scan_target` → получает базовый CycloneDX SBOM
2. Для каждого RPM-файла в `scan_target` вычисляет SHA-256 и запрашивает `buildhost` через `rpm -qp`
3. Если указан `--compare-root` — сравнивает пакеты по SHA-256 с эталонными RPM; совпавшие помечаются `GOST:provided_by=Alt Linux`
4. Пакеты, собранные на `*.altlinux.org`, но отсутствующие в `rpm_dir`, попадают в отчёт о расхождениях
5. Добавляет стандартные GOST-поля (`GOST:attack_surface=no`, `GOST:security_function=no`) всем компонентам
6. Сортирует компоненты по экосистеме (rpm → deb → npm → pypi → ...)
7. Запускает CVE-сканер (если не передан `--no-cve-rpm`)

---

## Режим `--deb`

Сканирует директорию с `.deb`-файлами и генерирует CycloneDX SBOM. Читает метаданные напрямую из архивов — установка пакетов не требуется.

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
| `-o`, `--output <file>` | `sbom.json` | Путь к выходному SBOM JSON |
| `--with-dependencies` | — | Включить в SBOM граф внутренних зависимостей между пакетами |
| `--errors-output <file>` | `sbom.errors.json` | Путь к файлу с ошибками обработки |

### Примеры

```bash
# Просто просканировать папку
python3 sbom_tool.py --deb ./debs

# С фильтром по списку (остальные → Astra Linux)
python3 sbom_tool.py --deb ./debs package-list.txt

# С графом зависимостей
python3 sbom_tool.py --deb ./debs package-list.txt \
  --with-dependencies

# Указать выходной файл
python3 sbom_tool.py --deb ./debs package-list.txt \
  -o sbom.json
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

### Что делает инструмент в этом режиме

1. Рекурсивно находит все `.deb`-файлы в `folder`
2. Для каждого читает `control.tar.*` прямо из `.deb`-архива (без распаковки на диск)
3. Извлекает метаданные: `Package`, `Version`, `Architecture`, `Depends`, `Homepage` и др.
4. Вычисляет SHA-256 каждого файла
5. Если передан `package_list.txt` — применяет правила маркировки `GOST:provided_by`
6. Если передан `--with-dependencies` — строит граф зависимостей по полям `Depends` и `Pre-Depends`
7. Сортирует компоненты по экосистеме и записывает CycloneDX SBOM

---

## Зависимости

| Инструмент / библиотека | Нужен для |
|---|---|
| `syft` | Режим `--rpm` (сканирование) |
| `rpm` (CLI) | Режим `--rpm` (запрос buildhost) |
| `requests` | CVE-скан (загрузка ALT OVAL) |
| `openpyxl` | CVE-скан (генерация XLSX-отчёта) |

Установка Python-зависимостей:

```bash
pip install requests openpyxl
```

---

## Структура выходных файлов

| Файл | Режим | Описание |
|---|---|---|
| `updated_sbom.json` | `--rpm` | Обогащённый CycloneDX SBOM |
| `report.txt` | `--rpm` | Расхождения версий между SBOM и диском |
| `cve_report.xlsx` | `--rpm` | CVE-отчёт по пакетам |
| `sbom.json` | `--deb` | CycloneDX SBOM из .deb-пакетов |
| `sbom.errors.json` | `--deb` | Пакеты, которые не удалось обработать |

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
