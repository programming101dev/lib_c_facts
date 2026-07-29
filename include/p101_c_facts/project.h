#ifndef P101_C_FACTS_PROJECT_H
#define P101_C_FACTS_PROJECT_H

#include <p101_env/env.h>
#include <p101_error/error.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    bool p101_c_facts_find_clang_compile_database(const struct p101_env *env, struct p101_error *err, const char *project_directory, char *path, size_t path_size);

#ifdef __cplusplus
}
#endif

#endif    // P101_C_FACTS_PROJECT_H
