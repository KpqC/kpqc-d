cmake_minimum_required(VERSION 3.18)

project(kpqc_d_native VERSION 0.1.0 LANGUAGES C)

option(KPQC_TEST_ENTROPY "Build deterministic entropy hooks for KATs" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(KPQC_CORE_SOURCES
    native/core_aimer128f.c
    native/core_aimer128s.c
    native/core_aimer192f.c
    native/core_aimer192s.c
    native/core_aimer256f.c
    native/core_aimer256s.c
    native/core_haetae2.c
    native/core_haetae3.c
    native/core_haetae5.c
    native/core_ntruplus768.c
    native/core_ntruplus864.c
    native/core_ntruplus1152.c
    native/core_smaugt128.c
    native/core_smaugt192.c
    native/core_smaugt256.c
    native/core_timer.c
)

set_source_files_properties(
    native/core_haetae2.c
    native/core_haetae3.c
    native/core_haetae5.c
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/HAETAE/include"
)
set_source_files_properties(
    native/core_ntruplus768.c
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/NTRUplus/NTRU+768"
)
set_source_files_properties(
    native/core_ntruplus864.c
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/NTRUplus/NTRU+864"
)
set_source_files_properties(
    native/core_ntruplus1152.c
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/NTRUplus/NTRU+1152"
)
set_source_files_properties(
    native/core_smaugt128.c
    native/core_smaugt192.c
    native/core_smaugt256.c
    native/core_timer.c
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/SMAUG-T/include"
)

add_library(kpqc_native STATIC ${KPQC_CORE_SOURCES})
set_target_properties(kpqc_native PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(KPQC_TEST_ENTROPY)
    target_compile_definitions(kpqc_native PRIVATE KPQC_TEST_ENTROPY)
    target_sources(kpqc_native PRIVATE native/test/aes.c native/test/aes_bridge.c)
endif()
