#ifndef P101_C_FACTS_FACTS_H
#define P101_C_FACTS_FACTS_H

#include <p101_env/env.h>
#include <p101_error/error.h>
#include <stdbool.h>
#include <stddef.h>

#define P101_C_FACT_TAG "P101FACT"
#define P101_C_FACT_PREFIX "P101FACT\t"
#define P101_C_FACT_VERSION "2"

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
        char                 *value;
        bool                  flag1;
        bool                  flag2;
    };

    enum p101_c_fact_status p101_c_fact_parse_line(const struct p101_env *env, struct p101_error *err, char *line, struct p101_c_fact *fact);
    const char             *p101_c_fact_kind_name(enum p101_c_fact_kind kind);
    const char             *p101_c_fact_status_name(enum p101_c_fact_status status);

#ifdef __cplusplus
}
#endif

#endif    // P101_C_FACTS_FACTS_H
