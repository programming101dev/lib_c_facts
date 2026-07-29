# Standalone Unity test tree for lib_c_facts.
cmake_minimum_required(VERSION 3.14)
project(p101_c_facts_tests C)
enable_testing()

add_library(unity STATIC unity/unity.c)
target_include_directories(unity PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/unity")
target_compile_options(unity PRIVATE -w)

option(P101_TEST_COVERAGE "Instrument the code under test for coverage" OFF)
set(_COV "")
if (P101_TEST_COVERAGE)
    set(_COV --coverage)
endif ()

set(P101_LIBS p101_error p101_env p101_c p101_posix)
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
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/facts.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/project.c"
)

function(p101_add_test name)
    add_executable(${name} ${ARGN} ${P101_CODE_UNDER_TEST})
    target_include_directories(${name} PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/../include"
            ${_P101_INC_DIRS}
    )
    target_link_libraries(${name} PRIVATE unity ${_P101_RESOLVED})
    target_compile_options(${name} PRIVATE ${_COV})
    target_link_options(${name} PRIVATE ${_COV})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

p101_add_test(test_facts test_facts.c)
