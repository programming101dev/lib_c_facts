#include "p101_c_facts/facts.h"
#include <p101_c/p101_string.h>
#include <p101_env/wrapper.h>
#include <p101_record/record.h>
#include <stdint.h>

enum
{
    FACT_PREFIX_LEN       = 9,
    FACT_MAX_FIELDS       = 16,
    FACT_BASE_FIELD_COUNT = 7,
    FACT_VERSION_IDX      = 1,
    FACT_KIND_IDX         = 2,
    FACT_PATH_IDX         = 3,
    FACT_MODULE_IDX       = 4,
    FACT_IS_HEADER_IDX    = 5,
    FACT_LINE_IDX         = 6,
    FACT_VALUE_IDX        = 7,
    FACT_FLAG1_IDX        = 8,
    FACT_FLAG2_IDX        = 9,
    FACT_CALLER_IDX       = 10,
    FACT_NOTE_CALLER_IDX  = 8,
    FACT_NOTE_COLUMN_IDX  = 9,
    FACT_ENUM_TYPE_IDX    = 8,
    FACT_VALUE_FIELDS     = 8,
    FACT_INCLUDE_FIELDS   = 9,
    FACT_FUNCTION_FIELDS  = 10,
    FACT_CALL_FIELDS      = 11,
    FACT_NOTE_FIELDS      = 10
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
    P101_WRAPPER_FAULT_SCOPE_RETURN(env, err, status, P101_C_FACT_MALFORMED);
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
    /*
     * The prefix check above already proves that field zero is P101FACT.
     * Keeping a second tag comparison here would be an unreachable branch.
     */
    if(field_count < FACT_BASE_FIELD_COUNT || field_count > FACT_MAX_FIELDS)
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

    if(!p101_record_parse_size(fields[FACT_LINE_IDX], &fact->line))
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
    if((fact->kind == P101_C_FACT_KIND_INCLUDE || fact->kind == P101_C_FACT_KIND_FUNCTION || fact->kind == P101_C_FACT_KIND_CALL) && field_count > FACT_FLAG1_IDX)
    {
        if(!parse_fact_bool(env, fields[FACT_FLAG1_IDX], &fact->flag1))
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
    }
    if((fact->kind == P101_C_FACT_KIND_FUNCTION || fact->kind == P101_C_FACT_KIND_CALL) && field_count > FACT_FLAG2_IDX)
    {
        if(!parse_fact_bool(env, fields[FACT_FLAG2_IDX], &fact->flag2))
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
    }
    if(fact->kind == P101_C_FACT_KIND_CALL)
    {
        fact->caller = fields[FACT_CALLER_IDX];
    }
    else if(fact->kind == P101_C_FACT_KIND_ENUMERATOR)
    {
        fact->caller = fields[FACT_ENUM_TYPE_IDX];
    }
    else if(fact->kind == P101_C_FACT_KIND_NOTE)
    {
        fact->caller = fields[FACT_NOTE_CALLER_IDX];
        if(!p101_record_parse_size(fields[FACT_NOTE_COLUMN_IDX], &fact->column))
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
    }

    status = P101_C_FACT_OK;

done:
    P101_WRAPPER_SCOPE_DONE();
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
        case P101_C_FACT_KIND_ENUM:
            name = "ENUM";
            break;
        case P101_C_FACT_KIND_ENUMERATOR:
            name = "ENUMERATOR";
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
    bool p101_single_result_;
    P101_TRACE_SCOPE(env);
    if(p101_strcmp(env, text, "0") == 0)
    {
        *value              = false;
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    if(p101_strcmp(env, text, "1") == 0)
    {
        *value              = true;
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static size_t split_fact_line(const struct p101_env *env, char *line, char *fields[], size_t field_count)
{
    size_t p101_single_result_;
    size_t count;
    char  *cursor;

    P101_TRACE_SCOPE(env);
    count  = 0U;
    cursor = line;
    while(count < field_count && cursor != NULL)
    {
        fields[count] = p101_record_split(&cursor);
        count++;
    }

    if(count == field_count && cursor != NULL)
    {
        p101_single_result_ = field_count + 1U;
        goto p101_single_exit_;
    }

    for(size_t i = 0; i < count; i++)
    {
        p101_record_unescape_field(fields[i]);
    }

    p101_single_result_ = count;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static char *find_char(char *text, char ch)
{
    char *ret_val;

    ret_val = NULL;
    while(*text != '\0')
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
    else if(p101_strcmp(env, text, "ENUM") == 0)
    {
        kind = P101_C_FACT_KIND_ENUM;
    }
    else if(p101_strcmp(env, text, "ENUMERATOR") == 0)
    {
        kind = P101_C_FACT_KIND_ENUMERATOR;
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
    static const size_t minimum_fields[] = {
        [P101_C_FACT_KIND_UNKNOWN]    = 0U,
        [P101_C_FACT_KIND_FILE]       = FACT_BASE_FIELD_COUNT,
        [P101_C_FACT_KIND_INCLUDE]    = FACT_INCLUDE_FIELDS,
        [P101_C_FACT_KIND_FUNCTION]   = FACT_FUNCTION_FIELDS,
        [P101_C_FACT_KIND_CALL]       = FACT_CALL_FIELDS,
        [P101_C_FACT_KIND_TYPE]       = FACT_VALUE_FIELDS,
        [P101_C_FACT_KIND_ENUM]       = FACT_VALUE_FIELDS,
        [P101_C_FACT_KIND_ENUMERATOR] = FACT_INCLUDE_FIELDS,
        [P101_C_FACT_KIND_MACRO]      = FACT_VALUE_FIELDS,
        [P101_C_FACT_KIND_NOTE]       = FACT_NOTE_FIELDS,
    };

    return field_count >= minimum_fields[kind];
}
