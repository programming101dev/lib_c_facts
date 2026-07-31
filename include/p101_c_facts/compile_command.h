#ifndef P101_C_FACTS_COMPILE_COMMAND_H
#define P101_C_FACTS_COMPILE_COMMAND_H

#include <p101_env/env.h>
#include <p101_error/error.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    struct p101_c_compile_command
    {
        const char        *directory;
        const char *const *arguments;
        size_t             argument_count;
    };

    typedef bool (*p101_c_compile_command_observer)(const struct p101_env *env, struct p101_error *err, const struct p101_c_compile_command *command, void *context);

    bool p101_c_facts_with_compile_command(const struct p101_env *env, struct p101_error *err, const char *compile_database, const char *source_path, p101_c_compile_command_observer observer, void *context);

#ifdef __cplusplus
}
#endif

#endif
