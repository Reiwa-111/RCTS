# last updated: 0.3.0 | 2026-11-20 | BUILD AND WORKFLOW

# Разработка и сборка

## Требования

- CMake 3.20+;
- C++20-компилятор;
- OpenSSL 3.0+ с компонентом Crypto;
- Python 3.8+ для CTest.

## Обычная сборка

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## MSYS2 (UCRT64)

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake \
  mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-python
cmake -S . -B build -G "MinGW Makefiles" -DOPENSSL_ROOT_DIR="C:/msys64/ucrt64"
cmake --build build --parallel
export PATH="/c/msys64/ucrt64/bin:$PATH"
ctest --test-dir build --output-on-failure
```

`PATH` нужен для загрузки runtime/OpenSSL DLL при запуске `rcts.exe` и тестов.

## Отладочная сборка

```sh
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug --parallel
ctest --test-dir build-debug --output-on-failure
```

## Fault-injection build

Hooks are disabled by default. Enable them only in a separate testing binary, never a release build:


```sh
cmake -S . -B build-fault -DCMAKE_BUILD_TYPE=Debug -DRCTS_ENABLE_FAULT_INJECTION=ON
cmake --build build-fault --parallel
ctest --test-dir build-fault --output-on-failure
```

The suite injects `create`, `write`, `sync`, `close`, and `publish` failures into keygen/encrypt/decrypt.

## File permissions and publication

POSIX outputs use mode `0600`. Windows uses a protected DACL for the current user, SYSTEM and local Administrators. Linux tries `renameat2(RENAME_NOREPLACE)` then hard-link fallback; Windows tries no-replace `MoveFileExW` then hard-link fallback. Parent-directory sync on POSIX is best-effort.


## Sanitizers (GCC/Clang, если поддерживаются toolchain)

```sh
cmake -S . -B build-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan --parallel
ctest --test-dir build-asan --output-on-failure
```

В UCRT64 MinGW могут отсутствовать `libasan`/`libubsan`; тогда sanitizer-сборка не линкуется. Используй Linux/Clang или MSVC с установленным runtime. Не отмечай sanitizer-прогон выполненным, если линковка не удалась.

Для дополнительных проверок без sanitizer runtime можно собрать Release с `-D_GLIBCXX_ASSERTIONS -fstack-protector-strong -Werror`.

## OpenSSL

Проверь, что CMake находит именно OpenSSL 3.x:

```sh
openssl version
cmake -S . -B build -DOPENSSL_ROOT_DIR="/path/to/openssl"
```

На Windows используй путь к установленной сборке OpenSSL и совместимый с ней компилятор/архитектуру. Не смешивай, например, библиотеку x86 с исполняемым файлом x64.

## Стиль изменений

- Сохранять C++20 и минимизировать новые зависимости.
- Не реализовывать AES, GCM, HKDF или генератор случайных чисел самостоятельно.
- Не менять бинарную совместимость RCTS v0.1 молча.
- Сначала добавлять регрессионный тест, затем исправление.
- Не маскировать ошибки криптографической проверки.
- Не логировать ключи, plaintext, теги или чувствительные буферы.
- Для каждой новой функции документировать влияние на модель угроз, формат, CLI и совместимость.
- Не считать успешную компиляцию доказательством корректности.

## Предлагаемое разделение модулей

Модульный рефакторинг может быть выполнен после закрепления тестовой базы. Возможные границы:

- `crypto`: HKDF, AES-GCM, CSPRNG и очистка секретов;
- `format`: заголовок, записи, framing и валидация;
- `key`: кодирование/декодирование мастер-ключа;
- `io`: безопасные временные файлы, чтение/запись и публикация;
- `cli`: аргументы, сообщения и exit codes.

Это целевая идея, не текущее состояние. Рефакторинг не должен одновременно менять криптографию и бинарный формат.
