#include "p101_c_facts/project.h"
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_string.h>
#include <p101_env/wrapper.h>
#include <p101_filesystem/p101_dirent.h>
#include <p101_filesystem/p101_fnmatch.h>
#include <p101_filesystem/p101_ftw.h>
#include <p101_filesystem/p101_glob.h>
#include <p101_filesystem/p101_libgen.h>
#include <p101_filesystem/p101_stdio.h>
#include <p101_filesystem/p101_stdlib.h>
#include <p101_filesystem/p101_unistd.h>
#include <p101_filesystem/sys/p101_stat.h>
#include <p101_filesystem/sys/p101_statvfs.h>
#include <unistd.h>

enum
{
    PROJECT_PATH_SIZE = 4096
};

static bool is_clang_build_directory(const struct p101_env *env, const char *path);
static bool readable_file(const struct p101_env *env, const char *path);
static void trim_line_ending(const struct p101_env *env, char *text);

static void trim_line_ending(const struct p101_env *env, char *text)
{
    size_t length;

    P101_TRACE(env);
    length = p101_strlen(env, text);
    while(length > 0U && (text[length - 1U] == '\n' || text[length - 1U] == '\r'))
    {
        text[--length] = '\0';
    }
    P101_TRACE_EXIT(env);
}

static bool is_clang_build_directory(const struct p101_env *env, const char *path)
{
    static const char prefix[] = "build-clang";
    const char       *base_name;
    const char       *separator;
    bool              ret_val;
    int               comparison;

    P101_TRACE(env);
    separator  = p101_strrchr(env, path, '/');
    base_name  = (separator == NULL) ? path : separator + 1;
    ret_val    = false;
    comparison = p101_strncmp(env, base_name, prefix, sizeof(prefix) - 1U);
    if(comparison == 0 && (base_name[sizeof(prefix) - 1U] == '\0' || base_name[sizeof(prefix) - 1U] == '-'))
    {
        ret_val = true;
    }
    P101_TRACE_EXIT(env);
    return ret_val;
}

static bool readable_file(const struct p101_env *env, const char *path)
{
    bool ret_val;
    int  access_status;

    P101_TRACE(env);
    /* P101_ERROR_OPTIONAL rationale: access failure means unavailable. */
    access_status = p101_access(env, P101_ERROR_OPTIONAL, path, R_OK);
    ret_val       = access_status == 0;
    P101_TRACE_EXIT(env);
    return ret_val;
}

bool p101_c_facts_find_clang_compile_database(const struct p101_env *env, struct p101_error *err, const char *project_directory, char *path, size_t path_size)
{
    char        build_directory[PROJECT_PATH_SIZE];
    char        last_build_path[PROJECT_PATH_SIZE];
    const char *build_line;
    FILE       *stream;
    bool        found;
    bool        readable;
    bool        clang_build;
    bool        error_present;
    bool        no_error;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, found, false);
    found = false;
    if(project_directory == NULL || path == NULL || path_size == 0U)
    {
        P101_ERROR_RAISE_CHECK(err);
        goto done;
    }

    path[0] = '\0';
    p101_snprintf(env, err, last_build_path, sizeof(last_build_path), "%s/.last-build-dir", project_directory);
    error_present = p101_error_has_error(err);
    if(error_present)
    {
        goto done;
    }

    readable = readable_file(env, last_build_path);
    if(readable)
    {
        stream = p101_fopen(env, err, last_build_path, "r");
        if(stream == NULL)
        {
            goto done;
        }
        build_line    = p101_fgets(env, err, build_directory, sizeof(build_directory), stream);
        error_present = p101_error_has_error(err);
        if(error_present)
        {
            /* P101_ERROR_OPTIONAL rationale: preserve the read error while closing the temporary stream. */
            p101_fclose(env, P101_ERROR_OPTIONAL, stream);
            goto done;
        }
        if(build_line != NULL)
        {
            trim_line_ending(env, build_directory);
            clang_build = is_clang_build_directory(env, build_directory);
            if(clang_build)
            {
                if(build_directory[0] == '/')
                {
                    p101_snprintf(env, err, path, path_size, "%s/compile_commands.json", build_directory);
                }
                else
                {
                    p101_snprintf(env, err, path, path_size, "%s/%s/compile_commands.json", project_directory, build_directory);
                }
                no_error = p101_error_has_no_error(err);
                readable = false;
                if(no_error)
                {
                    readable = readable_file(env, path);
                }
                found = false;
                if(no_error && readable)
                {
                    found = true;
                }
            }
        }
        error_present = p101_error_has_error(err);
        if(error_present)
        {
            /* P101_ERROR_OPTIONAL rationale: preserve the discovery error while closing the temporary stream. */
            p101_fclose(env, P101_ERROR_OPTIONAL, stream);
            goto done;
        }
        p101_fclose(env, err, stream);
        error_present = p101_error_has_error(err);
        if(error_present || found)
        {
            goto done;
        }
    }

    p101_snprintf(env, err, path, path_size, "%s/build-clang/compile_commands.json", project_directory);
    no_error = p101_error_has_no_error(err);
    if(no_error)
    {
        found = readable_file(env, path);
    }

done:
    if(path != NULL && path_size > 0U && !found)
    {
        path[0] = '\0';
    }
    P101_WRAPPER_DONE(env);
    return found;
}
