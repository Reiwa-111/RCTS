# RCTS Sandbox

**Текущая версия проекта:** `0.3.0`
**Версия бинарного формата:** `1` (формат RCTS v0.1)
**Статус:** исследовательский прототип; не использовать как единственное средство защиты важных данных.
**Язык:** C++20
**Криптографическая библиотека:** OpenSSL 3.x (минимум 3.0)

RCTS — локальная CLI-утилита для шифрования произвольных файлов в потоковый аутентифицированный контейнер. Это не новый шифр: криптографическую защиту содержимого обеспечивает AES-256-GCM из OpenSSL. Проект исследует формат контейнера, обработку файлов блоками и представление случайного ключа в виде 32 Unicode-символов.

> **Предупреждение:** RCTS v0.1 не проходил независимый криптографический аудит. До выполнения критериев выпуска 1.0 не используй его для единственных копий, критически важных или чувствительных данных. Делай резервные копии.

## Состояние 0.3.0 (формат v0.1 без изменений)

Реализовано в `src/main.cpp`:

- генерация 32 случайных байтов через `RAND_bytes`;
- представление каждого байта одной кодовой точкой из `U+4E00..U+4EFF` (32 символа, UTF-8);
- строгая проверка файла ключа;
- HKDF-SHA-256 выводит отдельный ключ контейнера из мастер-ключа и 16-байтовой соли;
- потоковое шифрование блоками по 1 MiB с AES-256-GCM;
- 16-байтовый тег для каждой записи;
- привязка заголовка, индекса, длины и флагов каждой записи через AAD;
- эксклюзивное создание временного файла в каталоге назначения (`O_CREAT | O_EXCL` на POSIX, `CreateFileW` с `CREATE_NEW` на Windows), без схемы «проверить `exists`, затем открыть»;
- проверка `flush`, `fsync`/`_commit` и `close` до публикации результата;
- публикация ключевого файла и контейнера через no-clobber rename/link без перезаписи существующего пути;
- ограниченное чтение ключевого файла (не более 1024 байт) и требование обычного файла для ключа и входа;
- на POSIX новые файлы создаются с правами `0600`; Windows использует защищённый DACL для текущего пользователя, SYSTEM и local Administrators;
- проверка структуры, аутентичности и отсутствия хвостовых данных при расшифровании.
- best-effort очистка локальных буферов ключей и plaintext через `OPENSSL_cleanse` (не гарантирует стирание всех копий памяти).
- конкурентные проверки публикации, 80 детерминированных мутаций байтов и отдельные fault-injection тесты для create/write/sync/close/publish.

Формат v0.1 ограничен 65 536 записями, то есть максимумом 64 GiB открытых данных. Точные размеры содержимого раскрываются. Подробнее: [спецификация](docs/SPECIFICATION.md) и [формат контейнера](docs/FORMAT.md).

Публикация использует no-clobber rename (Linux `renameat2`, Windows `MoveFileExW`) с hard-link fallback. На неподдерживаемых файловых системах операция завершается ошибкой без перезаписи.

## Сборка

Требования:

- C++20-компилятор;
- CMake 3.20 или новее;
- OpenSSL 3.0 или новее (компонент Crypto);
- Python 3.8+ для запуска тестов.

Linux (GCC или Clang):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Fault-injection build (only for testing; do not ship this binary):

```sh
cmake -S . -B build-fault -DCMAKE_BUILD_TYPE=Debug -DRCTS_ENABLE_FAULT_INJECTION=ON
cmake --build build-fault --parallel
ctest --test-dir build-fault --output-on-failure
```

Windows (Visual Studio):

```powershell
cmake -S . -B build -A x64 -DCMAKE_PREFIX_PATH="C:/path/to/openssl"
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

Путь к OpenSSL зависит от способа его установки. Если CMake сам находит OpenSSL, `CMAKE_PREFIX_PATH` не нужен. Исполняемый файл обычно находится в `build/rcts` на одноконфигурационных генераторах и в `build/Release/rcts.exe` для Visual Studio.

MSYS2 (UCRT64, текущая проверенная среда):

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake \
  mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-python
cmake -S . -B build -G "MinGW Makefiles" -DOPENSSL_ROOT_DIR="C:/msys64/ucrt64"
cmake --build build --parallel
export PATH="/c/msys64/ucrt64/bin:$PATH"   # OpenSSL/runtime DLLs для запуска тестов
ctest --test-dir build --output-on-failure
```

Без добавления `/c/msys64/ucrt64/bin` в `PATH` `rcts.exe` может не загрузиться с ошибкой загрузчика DLL, а не с ошибкой RCTS.

## Использование

```sh
# Создать новый ключевой файл. Существующий файл не перезаписывается.
rcts keygen secret.key

# Зашифровать файл.
rcts encrypt secret.key input.bin output.rct

# Расшифровать контейнер.
rcts decrypt secret.key output.rct restored.bin
```

На Linux пример прямого запуска после сборки: `./build/rcts keygen secret.key`.

Коды возврата: `0` — успех, `1` — ошибка операции (включая отказ перезаписывать существующий путь и ошибку аутентификации), `2` — неверные аргументы командной строки.

Ключевой файл — это полный секрет для доступа к данным. Храни его отдельно от контейнера и сделай безопасную резервную копию. Не отправляй ключ в чаты, не коммить в Git и не оставляй его в логах. Потеря ключа означает потерю доступа к содержимому. Исключение — явно публичный демонстрационный ключ в `tests/vectors/`; он опубликован только для теста и непригоден для реальных данных.

## Структура репозитория

```text
RCTS/
├── CMakeLists.txt
├── README.md
├── CHANGELOG.md
├── VERSION
├── LICENSE
├── CONTRIBUTING.md
├── LICENSE_STATUS.md
├── SHA256SUMS.txt
├── .gitignore
├── .gitattributes
├── src/
│   └── main.cpp
├── tests/
│   ├── smoke_test.py
│   ├── encryption_kat.py
│   ├── fault_test.py
│   └── vectors/
│       ├── README.md
│       ├── hello-world-v0.1.key
│       ├── hello-world-v0.1.rct
│       └── encrypt-hello-world-v0.1.rct
└── docs/
    ├── ARCHITECTURE.md
    ├── DECISIONS.md
    ├── DEVELOPMENT.md
    ├── FORMAT.md
    ├── KEY_FORMAT.md
    ├── ROADMAP.md
    ├── SECURITY.md
    ├── SPECIFICATION.md
    └── TESTING.md
```

## Документация

- [Спецификация RCTS v0.1](docs/SPECIFICATION.md)
- [Бинарный формат контейнера](docs/FORMAT.md)
- [Формат ключа](docs/KEY_FORMAT.md)
- [Архитектура текущей реализации](docs/ARCHITECTURE.md)
- [Модель угроз и ограничения](docs/SECURITY.md)
- [Тестирование](docs/TESTING.md)
- [Сборка и разработка](docs/DEVELOPMENT.md)
- [Журнал архитектурных решений](docs/DECISIONS.md)
- [Дорожная карта до 1.0](docs/ROADMAP.md)
- [Правовой статус лицензии](LICENSE_STATUS.md)
- [Правила внесения изменений](CONTRIBUTING.md)

## Принцип развития

Сначала надёжность реализации и проверяемость, потом дополнительные функции. Не добавляй «собственную криптографию», случайные преобразования байтов или декоративную обфускацию ради усложнения. Любое изменение криптографического формата требует отдельного дизайна, новой версии формата, тест-векторов и независимого анализа. См. [ROADMAP.md](docs/ROADMAP.md).

## License

RCTS is distributed under [Apache License 2.0](LICENSE). OpenSSL is a separate dependency under its own license.
