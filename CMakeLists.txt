cmake_minimum_required(VERSION 3.20)
project(RCTSSandbox VERSION 0.3.1 LANGUAGES CXX)

option(RCTS_ENABLE_WARNINGS "Enable strict compiler warnings" ON)
option(RCTS_ENABLE_FAULT_INJECTION
  "Build test-only failure injection hooks (never enable for release binaries)" OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_executable(rcts src/main.cpp src/entry.cpp src/cli.cpp src/operations.cpp src/file_io.cpp src/crypto.cpp src/key_codec.cpp)
target_compile_features(rcts PRIVATE cxx_std_20)
target_compile_definitions(rcts PRIVATE RCTS_VERSION="${PROJECT_VERSION}")
target_link_libraries(rcts PRIVATE OpenSSL::Crypto)

if(RCTS_ENABLE_FAULT_INJECTION)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        message(FATAL_ERROR "Fault injection must not be enabled for Release builds")
    endif()
    target_compile_definitions(rcts PRIVATE RCTS_ENABLE_FAULT_INJECTION RCTS_TEST_BUILD)
else()
    target_compile_definitions(rcts PRIVATE RCTS_PRODUCTION_TARGET)
endif()

if(WIN32)
    # Advapi32 provides the token, SID and security-descriptor APIs used for
    # the private output DACL.
    target_link_libraries(rcts PRIVATE Advapi32)
    if(MINGW)
        # The entry point is wmain so that non-ASCII command-line paths survive
        # the Windows ANSI code page.
        target_link_options(rcts PRIVATE -municode)
    endif()
else()
    # Exposes renameat2()/RENAME_NOREPLACE for atomic no-clobber publication.
    target_compile_definitions(rcts PRIVATE _GNU_SOURCE)
endif()

if(RCTS_ENABLE_WARNINGS)
    if(MSVC)
        target_compile_options(rcts PRIVATE /W4 /permissive-)
    else()
        target_compile_options(rcts PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
            -Wshadow -Wformat=2 -Wundef
        )
    endif()
endif()

include(GNUInstallDirs)
install(TARGETS rcts RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES README.md CHANGELOG.md VERSION LICENSE LICENSE_STATUS.md
        DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(DIRECTORY docs/ DESTINATION "${CMAKE_INSTALL_DOCDIR}/docs"
        PATTERN "AI_HANDOFF.md" EXCLUDE
        PATTERN "QA_REPORT.md" EXCLUDE
        PATTERN "EXTERNAL_REVIEW_QWEN.md" EXCLUDE)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
    add_test(
        NAME rcts_smoke
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke_test.py" "$<TARGET_FILE:rcts>"
    )
    set_tests_properties(rcts_smoke PROPERTIES TIMEOUT 300)

    add_test(
        NAME rcts_release_randomness
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/release_randomness.py"
                "$<TARGET_FILE:rcts>"
    )
    set_tests_properties(rcts_release_randomness PROPERTIES TIMEOUT 60)

    # Separate test-only binary with deterministic salt/nonce injection. It is not installed.
    add_executable(rcts-kat src/main.cpp src/entry.cpp src/cli.cpp src/operations.cpp src/file_io.cpp src/crypto.cpp src/key_codec.cpp)
    target_compile_features(rcts-kat PRIVATE cxx_std_20)
    target_compile_definitions(rcts-kat PRIVATE
        RCTS_VERSION="${PROJECT_VERSION}"
        RCTS_ENABLE_KAT
        RCTS_TEST_BUILD
    )
    target_link_libraries(rcts-kat PRIVATE OpenSSL::Crypto)
    if(WIN32)
        target_link_libraries(rcts-kat PRIVATE Advapi32)
        if(MINGW)
            target_link_options(rcts-kat PRIVATE -municode)
        endif()
    else()
        target_compile_definitions(rcts-kat PRIVATE _GNU_SOURCE)
    endif()
    add_test(
        NAME rcts_encryption_kat
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/encryption_kat.py"
                "$<TARGET_FILE:rcts-kat>"
    )
    set_tests_properties(rcts_encryption_kat PROPERTIES TIMEOUT 60)

    add_executable(rcts-crypto-api-test tests/crypto_api_test.cpp src/crypto.cpp)
    target_compile_features(rcts-crypto-api-test PRIVATE cxx_std_20)
    target_link_libraries(rcts-crypto-api-test PRIVATE OpenSSL::Crypto)
    if(RCTS_ENABLE_WARNINGS)
        if(MSVC)
            target_compile_options(rcts-crypto-api-test PRIVATE /W4 /permissive-)
        else()
            target_compile_options(rcts-crypto-api-test PRIVATE
                -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
                -Wshadow -Wformat=2 -Wundef
            )
        endif()
    endif()
    add_test(NAME rcts_crypto_api COMMAND rcts-crypto-api-test)
    set_tests_properties(rcts_crypto_api PROPERTIES TIMEOUT 60)

    if(RCTS_ENABLE_FAULT_INJECTION)
        add_test(
            NAME rcts_fault_injection
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/fault_test.py" "$<TARGET_FILE:rcts>"
        )
        set_tests_properties(rcts_fault_injection PROPERTIES TIMEOUT 180)
    endif()
endif()
