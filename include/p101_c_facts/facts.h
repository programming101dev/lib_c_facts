#ifndef P101_C_FACTS_FACTS_H
#define P101_C_FACTS_FACTS_H

#include <p101_env/env.h>
#include <p101_error/error.h>
#include <stdbool.h>
#include <stddef.h>

#define P101_C_FACT_TAG "P101FACT"
#define P101_C_FACT_PREFIX "P101FACT\t"
#define P101_C_FACT_VERSION "6"

#ifdef __cplusplus
extern "C"
{
#endif

    enum p101_c_fact_status
    {
        P101_C_FACT_OK = 0,
        P101_C_FACT_OTHER,
        P101_C_FACT_BAD_VERSION,
        P101_C_FACT_MALFORMED
    };

    enum p101_c_fact_kind
    {
        P101_C_FACT_KIND_UNKNOWN = 0,
        P101_C_FACT_KIND_FILE,
        P101_C_FACT_KIND_INCLUDE,
        P101_C_FACT_KIND_FUNCTION,
        P101_C_FACT_KIND_CALL,
        P101_C_FACT_KIND_TYPE,
        P101_C_FACT_KIND_ENUM,
        P101_C_FACT_KIND_ENUMERATOR,
        P101_C_FACT_KIND_MACRO,
        P101_C_FACT_KIND_NOTE
    };

    struct p101_c_fact
    {
        enum p101_c_fact_kind kind;
        char                 *path;
        char                 *module;
        bool                  is_header;
        size_t                line;
        size_t                column;
        size_t                start;
        size_t                end;
        char                 *value;
        char                 *caller;
        char                 *usr;
        char                 *caller_usr;
        bool                  is_local;
        bool                  is_static;
        bool                  is_declaration;
        bool                  is_definition;
        bool                  has_env_parameter;
        bool                  has_error_parameter;
        bool                  is_indirect;
    };

    enum p101_c_fact_status p101_c_fact_parse_line(const struct p101_env *env, struct p101_error *err, char *line, struct p101_c_fact *fact);
    const char             *p101_c_fact_kind_name(enum p101_c_fact_kind kind);
    const char             *p101_c_fact_status_name(enum p101_c_fact_status status);

#ifdef __cplusplus
}
#endif

#endif    // P101_C_FACTS_FACTS_H
