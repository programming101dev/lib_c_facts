#include "p101_c_facts/facts.h"
#include <limits.h>
#include <p101_c/p101_stdlib.h>
#include <p101_c/p101_string.h>
#include <stdint.h>

enum
{
    FACT_PREFIX_LEN       = 9,
    FACT_MAX_FIELDS       = 16,
    FACT_BASE_FIELD_COUNT = 7,
    FACT_TAG_IDX          = 0,
    FACT_VERSION_IDX      = 1,
    FACT_KIND_IDX         = 2,
    FACT_PATH_IDX         = 3,
    FACT_MODULE_IDX       = 4,
    FACT_IS_HEADER_IDX    = 5,
    FACT_LINE_IDX         = 6,
    FACT_VALUE_IDX        = 7,
    FACT_FLAG1_IDX        = 8,
    FACT_FLAG2_IDX        = 9,
    FACT_VALUE_FIELDS     = 8,
    FACT_INCLUDE_FIELDS   = 9,
    FACT_FUNCTION_FIELDS  = 10,
    JSON_NUMBER_BASE      = 10
};

static size_t                split_fact_line(const struct p101_env *env, char *line, char *fields[], size_t field_count);
static void                  unescape_fact_field(const struct p101_env *env, char *field);
static char                 *find_char(char *text, char ch);
static enum p101_c_fact_kind parse_kind(const struct p101_env *env, const char *text);
static bool                  fact_text_bool(const struct p101_env *env, const char *text);
static bool                  parse_size(const struct p101_env *env, struct p101_error *err, const char *text, size_t *value);
static bool                  field_count_is_valid(enum p101_c_fact_kind kind, size_t field_count);

enum p101_c_fact_status p101_c_fact_parse_line(const struct p101_env *env, struct p101_error *err, char *line, struct p101_c_fact *fact)
{
    enum p101_c_fact_status status;
    char                   *fields[FACT_MAX_FIELDS];
    size_t                  field_count;
    char                   *newline;

    P101_TRACE(env);
    status = P101_C_FACT_MALFORMED;

    if(line == NULL || fact == NULL)
    {
        goto done;
    }
    p101_memset(env, fact, 0, sizeof(*fact));

    if(p101_strncmp(env, line, P101_C_FACT_PREFIX, FACT_PREFIX_LEN) != 0)
    {
        status = P101_C_FACT_OTHER;
        goto done;
    }

    newline = find_char(line, '\n');
    if(newline != NULL)
    {
        *newline = '\0';
    }
    newline = find_char(line, '\r');
    if(newline != NULL)
    {
        *newline = '\0';
    }

    field_count = split_fact_line(env, line, fields, FACT_MAX_FIELDS);
    if(field_count < FACT_BASE_FIELD_COUNT || p101_strcmp(env, fields[FACT_TAG_IDX], P101_C_FACT_TAG) != 0)
    {
        status = P101_C_FACT_MALFORMED;
        goto done;
    }

    if(p101_strcmp(env, fields[FACT_VERSION_IDX], P101_C_FACT_VERSION) != 0)
    {
        status = P101_C_FACT_BAD_VERSION;
        goto done;
    }

    fact->kind = parse_kind(env, fields[FACT_KIND_IDX]);
    if(!field_count_is_valid(fact->kind, field_count))
    {
        status = P101_C_FACT_MALFORMED;
        goto done;
    }

    if(!parse_size(env, err, fields[FACT_LINE_IDX], &fact->line))
    {
        status = P101_C_FACT_MALFORMED;
        goto done;
    }

    fact->path      = fields[FACT_PATH_IDX];
    fact->module    = fields[FACT_MODULE_IDX];
    fact->is_header = fact_text_bool(env, fields[FACT_IS_HEADER_IDX]);

    if(field_count > FACT_VALUE_IDX)
    {
        fact->value = fields[FACT_VALUE_IDX];
    }
    if(field_count > FACT_FLAG1_IDX)
    {
        fact->flag1 = fact_text_bool(env, fields[FACT_FLAG1_IDX]);
    }
    if(field_count > FACT_FLAG2_IDX)
    {
        fact->flag2 = fact_text_bool(env, fields[FACT_FLAG2_IDX]);
    }

    status = P101_C_FACT_OK;

done:
    return status;
}

const char *p101_c_fact_kind_name(enum p101_c_fact_kind kind)
{
    const char *name;

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(kind)
    {
        case P101_C_FACT_KIND_UNKNOWN:
            name = "UNKNOWN";
            break;
        case P101_C_FACT_KIND_FILE:
            name = "FILE";
            break;
        case P101_C_FACT_KIND_INCLUDE:
            name = "INCLUDE";
            break;
        case P101_C_FACT_KIND_FUNCTION:
            name = "FUNCTION";
            break;
        case P101_C_FACT_KIND_CALL:
            name = "CALL";
            break;
        case P101_C_FACT_KIND_TYPE:
            name = "TYPE";
            break;
        case P101_C_FACT_KIND_MACRO:
            name = "MACRO";
            break;
        case P101_C_FACT_KIND_NOTE:
            name = "NOTE";
            break;
        default:
            name = "unknown";
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

    return name;
}

const char *p101_c_fact_status_name(enum p101_c_fact_status status)
{
    const char *name;

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(status)
    {
        case P101_C_FACT_OK:
            name = "ok";
            break;
        case P101_C_FACT_OTHER:
            name = "other";
            break;
        case P101_C_FACT_BAD_VERSION:
            name = "bad_version";
            break;
        case P101_C_FACT_MALFORMED:
            name = "malformed";
            break;
        default:
            name = "unknown";
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

    return name;
}

static bool fact_text_bool(const struct p101_env *env, const char *text)
{
    bool ret_val;

    P101_TRACE(env);
    ret_val = false;
    if(text != NULL && p101_strcmp(env, text, "0") != 0)
    {
        ret_val = true;
    }
    return ret_val;
}

static size_t split_fact_line(const struct p101_env *env, char *line, char *fields[], size_t field_count)
{
    size_t count;
    char  *cursor;

    P101_TRACE(env);
    count  = 0U;
    cursor = line;
    while(count < field_count)
    {
        char *tab;

        fields[count++] = cursor;
        tab             = find_char(cursor, '\t');
        if(tab == NULL)
        {
            break;
        }
        *tab   = '\0';
        cursor = tab + 1;
    }

    for(size_t i = 0; i < count; i++)
    {
        unescape_fact_field(env, fields[i]);
    }

    return count;
}

static void unescape_fact_field(const struct p101_env *env, char *field)
{
    char *read_cursor;
    char *write_cursor;

    P101_TRACE(env);
    read_cursor  = field;
    write_cursor = field;
    while(*read_cursor != '\0')
    {
        if(read_cursor[0] == '\\' && read_cursor[1] != '\0')
        {
            read_cursor++;
            if(*read_cursor == 't')
            {
                *write_cursor++ = '\t';
            }
            else if(*read_cursor == 'n')
            {
                *write_cursor++ = '\n';
            }
            else if(*read_cursor == 'r')
            {
                *write_cursor++ = '\r';
            }
            else
            {
                *write_cursor++ = *read_cursor;
            }
            read_cursor++;
        }
        else
        {
            *write_cursor++ = *read_cursor++;
        }
    }
    *write_cursor = '\0';
}

static char *find_char(char *text, char ch)
{
    char *ret_val;

    ret_val = NULL;
    while(text != NULL && *text != '\0')
    {
        if(*text == ch)
        {
            ret_val = text;
            break;
        }
        text++;
    }
    return ret_val;
}

static enum p101_c_fact_kind parse_kind(const struct p101_env *env, const char *text)
{
    enum p101_c_fact_kind kind;

    P101_TRACE(env);
    kind = P101_C_FACT_KIND_UNKNOWN;
    if(p101_strcmp(env, text, "FILE") == 0)
    {
        kind = P101_C_FACT_KIND_FILE;
    }
    else if(p101_strcmp(env, text, "INCLUDE") == 0)
    {
        kind = P101_C_FACT_KIND_INCLUDE;
    }
    else if(p101_strcmp(env, text, "FUNCTION") == 0)
    {
        kind = P101_C_FACT_KIND_FUNCTION;
    }
    else if(p101_strcmp(env, text, "CALL") == 0)
    {
        kind = P101_C_FACT_KIND_CALL;
    }
    else if(p101_strcmp(env, text, "TYPE") == 0)
    {
        kind = P101_C_FACT_KIND_TYPE;
    }
    else if(p101_strcmp(env, text, "MACRO") == 0)
    {
        kind = P101_C_FACT_KIND_MACRO;
    }
    else if(p101_strcmp(env, text, "NOTE") == 0)
    {
        kind = P101_C_FACT_KIND_NOTE;
    }
    return kind;
}

static bool parse_size(const struct p101_env *env, struct p101_error *err, const char *text, size_t *value)
{
    bool          ok;
    char         *end;
    unsigned long parsed;

    P101_TRACE(env);
    ok     = false;
    parsed = p101_strtoul(env, err, text, &end, JSON_NUMBER_BASE);
    if(p101_error_has_error(err) || text == end || *end != '\0')
    {
        goto done;
    }
#if ULONG_MAX > SIZE_MAX
    if(parsed > SIZE_MAX)
    {
        goto done;
    }
#endif

    *value = parsed;
    ok     = true;

done:
    return ok;
}

static bool field_count_is_valid(enum p101_c_fact_kind kind, size_t field_count)
{
    bool ret_val;

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(kind)
    {
        case P101_C_FACT_KIND_UNKNOWN:
            ret_val = true;
            break;
        case P101_C_FACT_KIND_FILE:
            ret_val = field_count >= FACT_BASE_FIELD_COUNT;
            break;
        case P101_C_FACT_KIND_INCLUDE:
            ret_val = field_count >= FACT_INCLUDE_FIELDS;
            break;
        case P101_C_FACT_KIND_FUNCTION:
            ret_val = field_count >= FACT_FUNCTION_FIELDS;
            break;
        case P101_C_FACT_KIND_CALL:
        case P101_C_FACT_KIND_TYPE:
        case P101_C_FACT_KIND_MACRO:
        case P101_C_FACT_KIND_NOTE:
            ret_val = field_count >= FACT_VALUE_FIELDS;
            break;
        default:
            ret_val = false;
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

    return ret_val;
}
