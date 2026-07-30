#include "p101_c_facts/facts.h"
#include <p101_c/p101_string.h>
#include <p101_tool_event/event.h>
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
    FACT_CALL_FIELDS      = 10
};

static size_t                split_fact_line(const struct p101_env *env, char *line, char *fields[], size_t field_count);
static char                 *find_char(char *text, char ch);
static enum p101_c_fact_kind parse_kind(const struct p101_env *env, const char *text);
static bool                  parse_fact_bool(const struct p101_env *env, const char *text, bool *value);
static bool                  field_count_is_valid(enum p101_c_fact_kind kind, size_t field_count);

enum p101_c_fact_status p101_c_fact_parse_line(const struct p101_env *env, struct p101_error *err, char *line, struct p101_c_fact *fact)
{
    enum p101_c_fact_status status;
    char                   *fields[FACT_MAX_FIELDS];
    size_t                  field_count;
    char                   *newline;

    P101_TRACE_SCOPE(env);
    (void)err;
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

    if(!p101_tool_event_parse_size_field(fields[FACT_LINE_IDX], &fact->line))
    {
        status = P101_C_FACT_MALFORMED;
        goto done;
    }

    fact->path   = fields[FACT_PATH_IDX];
    fact->module = fields[FACT_MODULE_IDX];
    if(!parse_fact_bool(env, fields[FACT_IS_HEADER_IDX], &fact->is_header))
    {
        status = P101_C_FACT_MALFORMED;
        goto done;
    }

    if(field_count > FACT_VALUE_IDX)
    {
        fact->value = fields[FACT_VALUE_IDX];
    }
    if(field_count > FACT_FLAG1_IDX)
    {
        if(!parse_fact_bool(env, fields[FACT_FLAG1_IDX], &fact->flag1))
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
    }
    if(field_count > FACT_FLAG2_IDX)
    {
        if(!parse_fact_bool(env, fields[FACT_FLAG2_IDX], &fact->flag2))
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
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

static bool parse_fact_bool(const struct p101_env *env, const char *text, bool *value)
{
    P101_TRACE_SCOPE(env);
    if(text == NULL || value == NULL)
    {
        return false;
    }
    if(p101_strcmp(env, text, "0") == 0)
    {
        *value = false;
        return true;
    }
    if(p101_strcmp(env, text, "1") == 0)
    {
        *value = true;
        return true;
    }
    return false;
}

static size_t split_fact_line(const struct p101_env *env, char *line, char *fields[], size_t field_count)
{
    size_t count;
    char  *cursor;

    P101_TRACE_SCOPE(env);
    count  = 0U;
    cursor = line;
    while(count < field_count)
    {
        fields[count] = p101_tool_event_split(&cursor);
        if(fields[count] == NULL)
        {
            break;
        }
        count++;
        if(cursor == NULL)
        {
            break;
        }
    }

    for(size_t i = 0; i < count; i++)
    {
        p101_tool_event_unescape_field(fields[i]);
    }

    return count;
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

    P101_TRACE_SCOPE(env);
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
            ret_val = field_count >= FACT_CALL_FIELDS;
            break;
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
