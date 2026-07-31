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
            ${P101_LLVM_INCLUDE_HINTS}
        REQUIRED)

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

if(DEFINED P101_PUBLIC_INCLUDE_DIRS AND NOT P101_PUBLIC_INCLUDE_DIRS STREQUAL "")
    set(P101_LIBCLANG_PUBLIC_INCLUDE_DIRS "${P101_LIBCLANG_INCLUDE_DIR};${P101_PUBLIC_INCLUDE_DIRS}")
else()
    set(P101_LIBCLANG_PUBLIC_INCLUDE_DIRS "${P101_LIBCLANG_INCLUDE_DIR};/usr/local/include")
endif()
set(P101_PUBLIC_INCLUDE_DIRS "${P101_LIBCLANG_PUBLIC_INCLUDE_DIRS}" CACHE STRING "Extra public include dirs" FORCE)
list(APPEND p101_c_facts_LINK_LIBRARIES "${P101_LIBCLANG_LIBRARY}")
