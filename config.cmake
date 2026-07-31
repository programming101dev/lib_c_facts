# Project metadata
set(PROJECT_NAME "p101_c_facts")
set(PROJECT_VERSION "0.0.1")
set(PROJECT_DESCRIPTION "Programming 101 C fact stream parser")
set(PROJECT_LANGUAGE "C")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Common compiler flags
set(STANDARD_FLAGS
        -D_POSIX_C_SOURCE=200809L
        -D_XOPEN_SOURCE=700
        -Werror
)

set(DARWIN_STANDARD_FLAGS
        -D_DARWIN_C_SOURCE
)

set(LINUX_STANDARD_FLAGS
)

set(BSD_STANDARD_FLAGS
)

# Define library targets
set(LIBRARY_TARGETS p101_c_facts)

# Source files for the library
set(p101_c_facts_SOURCES
        src/facts.c
        src/project.c
)

# Header files for installation
set(p101_c_facts_HEADERS
        include/p101_c_facts/facts.h
        include/p101_c_facts/project.h
)

# Linked libraries required for this project
set(p101_c_facts_LINK_LIBRARIES
        p101_error
        p101_tool_event
        p101_env
        p101_c
        p101_filesystem
)
