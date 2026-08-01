# Standalone Unity test tree for lib_c_facts.
cmake_minimum_required(VERSION 3.14)
project(p101_c_facts_tests C)
enable_testing()

set(P101_API_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/../api-manifest.tsv")
set(P101_UNIT_TEST_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/unit-test-manifest.tsv")
if(NOT EXISTS "${P101_API_MANIFEST}" OR NOT EXISTS "${P101_UNIT_TEST_MANIFEST}")
    message(FATAL_ERROR "Public API and unit-test manifests are required")
endif()
file(STRINGS "${P101_API_MANIFEST}" P101_API_ROWS REGEX "^p101_")
file(STRINGS "${P101_UNIT_TEST_MANIFEST}" P101_UNIT_ROWS REGEX "^p101_")
set(P101_API_FUNCTIONS "")
set(P101_UNIT_FUNCTIONS "")
foreach(row IN LISTS P101_API_ROWS)
    string(REGEX MATCH "^p101_[A-Za-z0-9_]+" function_name "${row}")
    list(APPEND P101_API_FUNCTIONS "${function_name}")
endforeach()
foreach(row IN LISTS P101_UNIT_ROWS)
    string(REGEX MATCH "^p101_[A-Za-z0-9_]+" function_name "${row}")
    list(APPEND P101_UNIT_FUNCTIONS "${function_name}")
endforeach()
set(P101_UNIT_FUNCTIONS_UNIQUE ${P101_UNIT_FUNCTIONS})
list(REMOVE_DUPLICATES P101_UNIT_FUNCTIONS_UNIQUE)
list(LENGTH P101_API_FUNCTIONS P101_API_COUNT)
list(LENGTH P101_UNIT_FUNCTIONS P101_UNIT_COUNT)
list(LENGTH P101_UNIT_FUNCTIONS_UNIQUE P101_UNIT_UNIQUE_COUNT)
if(NOT P101_API_COUNT EQUAL P101_UNIT_COUNT OR NOT P101_UNIT_COUNT EQUAL P101_UNIT_UNIQUE_COUNT)
    message(FATAL_ERROR "Every public API must have exactly one unit-test row")
endif()
foreach(function_name IN LISTS P101_API_FUNCTIONS)
    if(NOT function_name IN_LIST P101_UNIT_FUNCTIONS_UNIQUE)
        message(FATAL_ERROR "Missing unit test for ${function_name}")
    endif()
endforeach()

add_library(unity STATIC unity/unity.c)
target_include_directories(unity PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/unity")
target_compile_options(unity PRIVATE -w)

option(P101_TEST_COVERAGE "Instrument the code under test for coverage" OFF)
set(_COV "")
if (P101_TEST_COVERAGE)
    set(_COV --coverage)
endif ()

set(P101_LIBS p101_error p101_record p101_env p101_c p101_filesystem)
set(P101_PUBLIC_INCLUDE_DIRS "" CACHE STRING "Extra p101 include dirs")
set(P101_PUBLIC_LINK_DIRS "" CACHE STRING "Extra p101 link dirs")
separate_arguments(P101_PUBLIC_INCLUDE_DIRS_LIST NATIVE_COMMAND "${P101_PUBLIC_INCLUDE_DIRS}")
separate_arguments(P101_PUBLIC_LINK_DIRS_LIST NATIVE_COMMAND "${P101_PUBLIC_LINK_DIRS}")
set(_P101_INC_DIRS ${P101_PUBLIC_INCLUDE_DIRS_LIST} /usr/local/include /opt/homebrew/include /opt/local/include)
set(_P101_LIB_DIRS ${P101_PUBLIC_LINK_DIRS_LIST} /usr/local/lib /usr/local/lib64 /opt/homebrew/lib /opt/local/lib)

set(_P101_RESOLVED "")
foreach (_l IN LISTS P101_LIBS)
    unset(_P101_LIB_${_l} CACHE)
    unset(_P101_LIB_${_l})
    find_library(_P101_LIB_${_l} NAMES ${_l} PATHS ${_P101_LIB_DIRS} NO_DEFAULT_PATH)
    if (NOT _P101_LIB_${_l})
        find_library(_P101_LIB_${_l} NAMES ${_l})
    endif ()
    if (_P101_LIB_${_l})
        list(APPEND _P101_RESOLVED "${_P101_LIB_${_l}}")
    else ()
        message(WARNING "p101 library '${_l}' not found in ${_P101_LIB_DIRS} -- install the p101 libs first.")
    endif ()
endforeach ()

set(P101_CODE_UNDER_TEST
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/analysis.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/compile_command.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/facts.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/project.c"
)

file(GLOB _P101_LLVM_PREFIXES LIST_DIRECTORIES true "/usr/local/llvm*" "/usr/lib/llvm-*")
set(_P101_LLVM_INCLUDE_HINTS "")
set(_P101_LLVM_LIBRARY_HINTS "")
foreach(_P101_LLVM_PREFIX IN LISTS _P101_LLVM_PREFIXES)
    list(APPEND _P101_LLVM_INCLUDE_HINTS "${_P101_LLVM_PREFIX}/include")
    list(APPEND _P101_LLVM_LIBRARY_HINTS "${_P101_LLVM_PREFIX}/lib")
endforeach()
find_path(P101_TEST_LIBCLANG_INCLUDE_DIR NAMES clang-c/Index.h
        HINTS /opt/homebrew/opt/llvm/include /usr/local/opt/llvm/include ${_P101_LLVM_INCLUDE_HINTS}
        REQUIRED)
find_library(P101_TEST_LIBCLANG_LIBRARY NAMES clang libclang
        HINTS /opt/homebrew/opt/llvm/lib /usr/local/opt/llvm/lib ${_P101_LLVM_LIBRARY_HINTS}
        REQUIRED)

function(p101_add_test name)
    add_executable(${name} ${ARGN} ${P101_CODE_UNDER_TEST})
    target_include_directories(${name} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/../include"
            "${P101_TEST_LIBCLANG_INCLUDE_DIR}"
            ${_P101_INC_DIRS}
    )
    target_link_libraries(${name} PRIVATE unity ${_P101_RESOLVED} "${P101_TEST_LIBCLANG_LIBRARY}")
    target_compile_definitions(${name} PRIVATE _POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)
    if(APPLE)
        target_compile_definitions(${name} PRIVATE _DARWIN_C_SOURCE)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_definitions(${name} PRIVATE _GNU_SOURCE)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        target_compile_definitions(${name} PRIVATE _BSD_SOURCE __BSD_VISIBLE)
    endif()
    target_compile_options(${name} PRIVATE ${_COV})
    target_link_options(${name} PRIVATE ${_COV})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

p101_add_test(test_facts test_facts.c)
p101_add_test(test_analysis test_analysis.c)
