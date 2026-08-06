#include "p101_c_facts/compile_command.h"
#include <clang-c/CXCompilationDatabase.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_stdlib.h>
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

enum
{
    COMPILE_COMMAND_PATH_SIZE = 4096
};

static char *copy_cx_string(const struct p101_env *env, struct p101_error *err, CXString value);
static char *copy_text(const struct p101_env *env, struct p101_error *err, const char *text);

static char *copy_text(const struct p101_env *env, struct p101_error *err, const char *text)
{
    char  *copy;
    size_t length;
    void  *storage;

    P101_TRACE_SCOPE(env);
    length  = p101_strlen(env, text);
    storage = p101_malloc(env, err, length + 1U);
    copy    = (char *)storage;
    if(copy != NULL)
    {
        p101_memcpy(env, copy, text, length + 1U);
    }
    return copy;
}

static char *copy_cx_string(const struct p101_env *env, struct p101_error *err, CXString value)
{
    char       *copy;
    const char *text;

    P101_TRACE_SCOPE(env);
    text = clang_getCString(value);
    copy = copy_text(env, err, text == NULL ? "" : text);
    clang_disposeString(value);
    return copy;
}

bool p101_c_facts_with_compile_command(const struct p101_env *env, struct p101_error *err, const char *compile_database, const char *source_path, p101_c_compile_command_observer observer, void *context)
{
    bool                        p101_single_result_;
    char                        database_directory[COMPILE_COMMAND_PATH_SIZE];
    const char                 *separator;
    char                        canonical_source[COMPILE_COMMAND_PATH_SIZE];
    CXCompilationDatabase_Error database_error;
    CXCompilationDatabase       database;
    CXCompileCommands           commands;
    unsigned                    command_index;
    unsigned                    command_count;
    bool                        found;
    bool                        result;
    const char                 *real_path;
    size_t                      database_length;
    bool                        error_present;
    bool                        no_error;

    P101_TRACE_SCOPE(env);
    P101_WRAPPER_FAULT_SCOPE_RETURN(env, err, result, false);
    real_path = NULL;
    if(compile_database != NULL && source_path != NULL && observer != NULL)
    {
        real_path = p101_realpath(env, err, source_path, canonical_source);
    }
    if(real_path == NULL)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    database_length = p101_strlen(env, compile_database);
    if(database_length >= sizeof(database_directory))
    {
        P101_ERROR_RAISE_USER(err, "The compilation-database path is too long.", 1);
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    p101_snprintf(env, err, database_directory, sizeof(database_directory), "%s", compile_database);
    error_present = p101_error_has_error(err);
    if(error_present)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    separator = p101_strrchr(env, database_directory, '/');
    if(separator == NULL)
    {
        p101_snprintf(env, err, database_directory, sizeof(database_directory), ".");
    }
    else
    {
        database_directory[(size_t)(separator - database_directory)] = '\0';
    }

    database = clang_CompilationDatabase_fromDirectory(database_directory, &database_error);
    if(database_error != CXCompilationDatabase_NoError)
    {
        P101_ERROR_RAISE_USER(err, "Unable to load the Clang compilation database.", 1);
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    commands      = clang_CompilationDatabase_getAllCompileCommands(database);
    command_count = clang_CompileCommands_getSize(commands);
    found         = false;
    result        = false;

    for(command_index = 0U; command_index < command_count && !found; command_index++)
    {
        CXCompileCommand command;
        CXString         cx_filename;
        char            *filename;
        char             canonical_filename[COMPILE_COMMAND_PATH_SIZE];
        const char      *canonical_result;
        int              path_comparison;

        command     = clang_CompileCommands_getCommand(commands, command_index);
        cx_filename = clang_CompileCommand_getFilename(command);
        filename    = copy_cx_string(env, err, cx_filename);
        /* P101_ERROR_OPTIONAL rationale: an absent entry is not a match. */
        canonical_result = NULL;
        path_comparison  = -1;
        if(filename != NULL)
        {
            canonical_result = p101_realpath(env, P101_ERROR_OPTIONAL, filename, canonical_filename);
        }
        if(canonical_result != NULL)
        {
            path_comparison = p101_strcmp(env, canonical_filename, canonical_source);
        }
        if(filename != NULL && canonical_result != NULL && path_comparison == 0)
        {
            struct p101_c_compile_command view;
            char                        **arguments;
            char                         *directory;
            unsigned                      argument_index;
            unsigned                      argument_count;
            CXString                      cx_directory;
            CXString                      cx_argument;

            found          = true;
            cx_directory   = clang_CompileCommand_getDirectory(command);
            directory      = copy_cx_string(env, err, cx_directory);
            argument_count = clang_CompileCommand_getNumArgs(command);
            {
                void *storage;

                storage   = p101_calloc(env, err, argument_count, sizeof(*arguments));
                arguments = (char **)storage;
            }
            no_error = p101_error_has_no_error(err);
            for(argument_index = 0U; arguments != NULL && argument_index < argument_count && no_error; argument_index++)
            {
                cx_argument               = clang_CompileCommand_getArg(command, argument_index);
                arguments[argument_index] = copy_cx_string(env, err, cx_argument);
                no_error                  = p101_error_has_no_error(err);
            }
            no_error = p101_error_has_no_error(err);
            if(arguments != NULL && directory != NULL && no_error)
            {
                view.directory      = directory;
                view.arguments      = (const char *const *)arguments;
                view.argument_count = argument_count;
                result              = observer(env, err, &view, context);
            }
            for(argument_index = 0U; arguments != NULL && argument_index < argument_count; argument_index++)
            {
                p101_free(env, arguments[argument_index]);
            }
            p101_free(env, (void *)arguments);
            p101_free(env, directory);
        }
        p101_free(env, filename);
    }

    clang_CompileCommands_dispose(commands);
    clang_CompilationDatabase_dispose(database);
    no_error = p101_error_has_no_error(err);
    if(!found && no_error)
    {
        P101_ERROR_RAISE_USER(err, "The compilation database has no command for the mutation candidate.", 1);
    }
    P101_WRAPPER_SCOPE_DONE();
    no_error = p101_error_has_no_error(err);
    if(result && no_error)
    {
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}
