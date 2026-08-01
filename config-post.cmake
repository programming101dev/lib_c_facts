file(GLOB P101_LLVM_PREFIXES
        LIST_DIRECTORIES true
        "/usr/local/llvm*"
        "/usr/lib/llvm-*")
set(P101_LLVM_INCLUDE_HINTS "")
set(P101_LLVM_LIBRARY_HINTS "")
foreach(P101_LLVM_PREFIX IN LISTS P101_LLVM_PREFIXES)
    list(APPEND P101_LLVM_INCLUDE_HINTS "${P101_LLVM_PREFIX}/include")
    list(APPEND P101_LLVM_LIBRARY_HINTS "${P101_LLVM_PREFIX}/lib")
endforeach()

find_path(P101_LIBCLANG_INCLUDE_DIR
        NAMES clang-c/Index.h
        HINTS
            /opt/homebrew/opt/llvm/include
            /usr/local/opt/llvm/include
            /usr/local/llvm19/include
            /usr/lib/llvm-22/include
            /usr/lib/llvm-21/include
            /usr/lib/llvm-20/include
            /usr/lib/llvm-19/include
            /usr/lib/llvm-18/include
            ${P101_LLVM_INCLUDE_HINTS})
if(NOT P101_LIBCLANG_INCLUDE_DIR)
    message(FATAL_ERROR
            "lib_c_facts requires the libclang C API header clang-c/Index.h. "
            "Install the development package for this platform "
            "(Ubuntu/Debian: libclang-dev; Fedora: clang-devel), then rerun configuration.")
endif()

find_library(P101_LIBCLANG_LIBRARY
        NAMES clang libclang
        HINTS
            /opt/homebrew/opt/llvm/lib
            /usr/local/opt/llvm/lib
            /usr/local/llvm19/lib
            /usr/lib/llvm-22/lib
            /usr/lib/llvm-21/lib
            /usr/lib/llvm-20/lib
            /usr/lib/llvm-19/lib
            /usr/lib/llvm-18/lib
            ${P101_LLVM_LIBRARY_HINTS}
        REQUIRED)

# libclang does not reliably discover its builtin headers from the shared
# library location on macOS. Record and validate the resource directory so
# embedded parsing sees stdarg.h, stdbool.h, and the other compiler headers
# without relying on the caller's environment. Prefer the libclang installation
# and also ask the selected Clang driver: package layouts are not uniform.
get_filename_component(P101_LIBCLANG_LIBRARY_DIR "${P101_LIBCLANG_LIBRARY}" DIRECTORY)
file(GLOB P101_LIBCLANG_RESOURCE_CANDIDATES
        LIST_DIRECTORIES true
        "${P101_LIBCLANG_LIBRARY_DIR}/clang/*")
execute_process(
        COMMAND "${CMAKE_C_COMPILER}" --print-resource-dir
        RESULT_VARIABLE P101_CLANG_RESOURCE_RESULT
        OUTPUT_VARIABLE P101_CLANG_RESOURCE_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
if(P101_CLANG_RESOURCE_RESULT EQUAL 0 AND NOT P101_CLANG_RESOURCE_DIR STREQUAL "")
    list(APPEND P101_LIBCLANG_RESOURCE_CANDIDATES "${P101_CLANG_RESOURCE_DIR}")
endif()
list(REMOVE_DUPLICATES P101_LIBCLANG_RESOURCE_CANDIDATES)
list(SORT P101_LIBCLANG_RESOURCE_CANDIDATES COMPARE NATURAL ORDER DESCENDING)
set(P101_LIBCLANG_RESOURCE_DIR "")
foreach(P101_LIBCLANG_RESOURCE_CANDIDATE IN LISTS P101_LIBCLANG_RESOURCE_CANDIDATES)
    if(EXISTS "${P101_LIBCLANG_RESOURCE_CANDIDATE}/include/stddef.h")
        set(P101_LIBCLANG_RESOURCE_DIR "${P101_LIBCLANG_RESOURCE_CANDIDATE}")
        break()
    endif()
endforeach()
if(P101_LIBCLANG_RESOURCE_DIR STREQUAL "")
    message(FATAL_ERROR
            "A usable Clang resource directory is required by lib_c_facts; "
            "neither libclang nor ${CMAKE_C_COMPILER} supplied one containing include/stddef.h")
endif()
add_compile_definitions(P101_LIBCLANG_RESOURCE_DIR="${P101_LIBCLANG_RESOURCE_DIR}")
message(STATUS "[libclang] resource directory: ${P101_LIBCLANG_RESOURCE_DIR}")

if(APPLE)
    if(NOT MAC_SYSROOT)
        execute_process(
                COMMAND xcrun --show-sdk-path
                RESULT_VARIABLE P101_MAC_SYSROOT_RESULT
                OUTPUT_VARIABLE MAC_SYSROOT
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)
    else()
        set(P101_MAC_SYSROOT_RESULT 0)
    endif()
    if(NOT P101_MAC_SYSROOT_RESULT EQUAL 0
            OR MAC_SYSROOT STREQUAL ""
            OR NOT EXISTS "${MAC_SYSROOT}/usr/include/stdio.h")
        message(FATAL_ERROR
                "A usable macOS SDK sysroot is required by lib_c_facts; "
                "xcrun did not supply one containing usr/include/stdio.h")
    endif()
    add_compile_definitions(P101_LIBCLANG_SYSROOT="${MAC_SYSROOT}")
    message(STATUS "[libclang] macOS SDK sysroot: ${MAC_SYSROOT}")
endif()

if(DEFINED P101_PUBLIC_INCLUDE_DIRS AND NOT P101_PUBLIC_INCLUDE_DIRS STREQUAL "")
    set(P101_LIBCLANG_PUBLIC_INCLUDE_DIRS "${P101_LIBCLANG_INCLUDE_DIR};${P101_PUBLIC_INCLUDE_DIRS}")
else()
    set(P101_LIBCLANG_PUBLIC_INCLUDE_DIRS "${P101_LIBCLANG_INCLUDE_DIR};/usr/local/include")
endif()
set(P101_PUBLIC_INCLUDE_DIRS "${P101_LIBCLANG_PUBLIC_INCLUDE_DIRS}" CACHE STRING "Extra public include dirs" FORCE)
list(APPEND p101_c_facts_LINK_LIBRARIES "${P101_LIBCLANG_LIBRARY}")
