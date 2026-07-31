#ifndef P101_C_FACTS_ANALYSIS_H
#define P101_C_FACTS_ANALYSIS_H

#include <p101_env/env.h>
#include <p101_error/error.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum p101_c_analysis_kind
    {
        P101_C_ANALYSIS_FILE,
        P101_C_ANALYSIS_INCLUDE,
        P101_C_ANALYSIS_FUNCTION,
        P101_C_ANALYSIS_CALL,
        P101_C_ANALYSIS_TYPE,
        P101_C_ANALYSIS_MACRO,
        P101_C_ANALYSIS_NOTE,
        P101_C_ANALYSIS_MUTATION,
        P101_C_ANALYSIS_DIAGNOSTIC
    };

    enum p101_c_mutation_kind
    {
        P101_C_MUTATION_NONE,
        P101_C_MUTATION_COMPARISON_BOUNDARY,
        P101_C_MUTATION_ERROR_PREDICATE,
        P101_C_MUTATION_SKIP_CLEANUP
    };

    struct p101_c_analysis_record
    {
        enum p101_c_analysis_kind kind;
        const char               *path;
        size_t                    line;
        size_t                    column;
        size_t                    start_offset;
        size_t                    end_offset;
        const char               *name;
        const char               *caller;
        const char               *type;
        const char               *return_type;
        const char               *error_argument;
        const char               *replacement;
        enum p101_c_mutation_kind mutation;
        bool                      is_header;
        bool                      is_definition;
        bool                      is_static;
        bool                      is_public;
        bool                      is_variadic;
        bool                      is_local_include;
        bool                      has_env_parameter;
        bool                      has_error_parameter;
        bool                      is_indirect;
    };

    struct p101_c_analysis_options
    {
        const char        *compile_database;
        const char *const *paths;
        size_t             path_count;
        const char *const *extra_arguments;
        size_t             extra_argument_count;
        bool               compile_database_only;
        bool               detailed_preprocessing;
        bool               include_headers_as_translation_units;
        bool               keep_going;
    };

    typedef bool (*p101_c_analysis_observer)(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_record *record, void *context);

    /*
     * Parse the admitted C/C++ translation units with libclang and emit
     * normalized semantic records. Record strings remain valid only for the
     * duration of the observer call.
     */
    bool p101_c_analysis_scan(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *context);

    const char *p101_c_analysis_kind_name(enum p101_c_analysis_kind kind);
    const char *p101_c_mutation_kind_name(enum p101_c_mutation_kind kind);

#ifdef __cplusplus
}
#endif

#endif
