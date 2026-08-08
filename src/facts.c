#include "p101_c_facts/facts.h"
#include <p101_c/p101_string.h>
#include <p101_env/wrapper.h>
#include <p101_record/record.h>
#include <stdint.h>

enum
{
    FACT_PREFIX_LEN                = 9,
    FACT_MAX_FIELDS                = 16,
    FACT_BASE_FIELD_COUNT          = 7,
    FACT_VERSION_IDX               = 1,
    FACT_KIND_IDX                  = 2,
    FACT_PATH_IDX                  = 3,
    FACT_MODULE_IDX                = 4,
    FACT_IS_HEADER_IDX             = 5,
    FACT_LINE_IDX                  = 6,
    FACT_VALUE_IDX                 = 7,
    FACT_FIRST_SEMANTIC_FLAG_IDX   = 8,
    FACT_SECOND_SEMANTIC_FLAG_IDX  = 9,
    FACT_CALL_INDIRECT_IDX         = 10,
    FACT_CALLER_IDX                = 11,
    FACT_FUNCTION_USR_IDX          = 10,
    FACT_FUNCTION_START_IDX        = 11,
    FACT_FUNCTION_END_IDX          = 12,
    FACT_CALL_USR_IDX              = 12,
    FACT_CALLER_USR_IDX            = 13,
    FACT_CALL_START_IDX            = 14,
    FACT_CALL_END_IDX              = 15,
    FACT_NOTE_CALLER_IDX           = 8,
    FACT_NOTE_COLUMN_IDX           = 9,
    FACT_NOTE_CALLER_USR_IDX       = 10,
    FACT_NOTE_START_IDX            = 11,
    FACT_NOTE_END_IDX              = 12,
    FACT_MACRO_DEFINITION_IDX      = 8,
    FACT_MACRO_CALLER_USR_IDX      = 9,
    FACT_MACRO_START_IDX           = 10,
    FACT_MACRO_END_IDX             = 11,
    FACT_ENUMERATOR_TYPE_IDX       = 8,
    FACT_TYPE_USR_IDX              = 8,
    FACT_ENUMERATOR_USR_IDX        = 9,
    FACT_ENUMERATOR_PARENT_USR_IDX = 10,
    FACT_INCLUDE_RESOLVED_IDX      = 9,
    FACT_VALUE_FIELDS              = 8,
    FACT_INCLUDE_FIELDS            = 10,
    FACT_TYPE_FIELDS               = 9,
    FACT_ENUMERATOR_FIELDS         = 11,
    FACT_MACRO_FIELDS              = 12,
    FACT_FUNCTION_FIELDS           = 13,
    FACT_CALL_FIELDS               = 16,
    FACT_NOTE_FIELDS               = 13
};

static size_t                split_fact_line(const struct p101_env *env, char *line, char *fields[], size_t field_count);
static enum p101_c_fact_kind parse_kind(const struct p101_env *env, const char *text);
static bool                  parse_fact_bool(const struct p101_env *env, const char *text, bool *value);
static bool                  field_count_is_valid(enum p101_c_fact_kind kind, size_t field_count);

enum p101_c_fact_status p101_c_fact_parse_line(const struct p101_env *env, struct p101_error *err, char *line, struct p101_c_fact *fact)
{
    enum p101_c_fact_status status;
    char                   *fields[FACT_MAX_FIELDS];
    size_t                  field_count;
    const char             *newline;
    int                     comparison;
    int                     parse_status;
    bool                    parsed;

    P101_TRACE_SCOPE(env);
    P101_WRAPPER_FAULT_SCOPE_RETURN(env, err, status, P101_C_FACT_MALFORMED);
    status = P101_C_FACT_MALFORMED;

    if(line == NULL || fact == NULL)
    {
        goto done;
    }
    p101_memset(env, fact, 0, sizeof(*fact));

    comparison = p101_strncmp(env, line, P101_C_FACT_PREFIX, FACT_PREFIX_LEN);
    if(comparison != 0)
    {
        status = P101_C_FACT_OTHER;
        goto done;
    }

    newline = p101_strchr(env, line, '\n');
    if(newline != NULL)
    {
        line[(size_t)(newline - line)] = '\0';
    }
    newline = p101_strchr(env, line, '\r');
    if(newline != NULL)
    {
        line[(size_t)(newline - line)] = '\0';
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

    comparison = p101_strcmp(env, fields[FACT_VERSION_IDX], P101_C_FACT_VERSION);
    if(comparison != 0)
    {
        status = P101_C_FACT_BAD_VERSION;
        goto done;
    }

    fact->kind = parse_kind(env, fields[FACT_KIND_IDX]);
    parsed     = field_count_is_valid(fact->kind, field_count);
    if(!parsed)
    {
        status = P101_C_FACT_MALFORMED;
        goto done;
    }

    parse_status = p101_record_parse_size(fields[FACT_LINE_IDX], &fact->line);
    parsed       = parse_status != 0;
    if(!parsed)
    {
        status = P101_C_FACT_MALFORMED;
        goto done;
    }

    fact->path   = fields[FACT_PATH_IDX];
    fact->module = fields[FACT_MODULE_IDX];
    parsed       = parse_fact_bool(env, fields[FACT_IS_HEADER_IDX], &fact->is_header);
    if(!parsed)
    {
        status = P101_C_FACT_MALFORMED;
        goto done;
    }

    if(field_count > FACT_VALUE_IDX)
    {
        fact->value = fields[FACT_VALUE_IDX];
    }
    if(fact->kind == P101_C_FACT_KIND_INCLUDE)
    {
        parsed = parse_fact_bool(env, fields[FACT_FIRST_SEMANTIC_FLAG_IDX], &fact->is_local);
        if(!parsed)
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
        /* An empty resolved path means the producer could not resolve the header. */
        fact->resolved = fields[FACT_INCLUDE_RESOLVED_IDX];
    }
    else if(fact->kind == P101_C_FACT_KIND_FUNCTION)
    {
        parsed = parse_fact_bool(env, fields[FACT_FIRST_SEMANTIC_FLAG_IDX], &fact->is_static);
        if(parsed)
        {
            parsed = parse_fact_bool(env, fields[FACT_SECOND_SEMANTIC_FLAG_IDX], &fact->is_declaration);
        }
        if(!parsed)
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
    }
    else if(fact->kind == P101_C_FACT_KIND_CALL)
    {
        parsed = parse_fact_bool(env, fields[FACT_FIRST_SEMANTIC_FLAG_IDX], &fact->has_env_parameter);
        if(parsed)
        {
            parsed = parse_fact_bool(env, fields[FACT_SECOND_SEMANTIC_FLAG_IDX], &fact->has_error_parameter);
        }
        if(!parsed)
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
    }
    if(fact->kind == P101_C_FACT_KIND_CALL)
    {
        parsed = parse_fact_bool(env, fields[FACT_CALL_INDIRECT_IDX], &fact->is_indirect);
        if(!parsed)
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
        fact->caller     = fields[FACT_CALLER_IDX];
        fact->usr        = fields[FACT_CALL_USR_IDX];
        fact->caller_usr = fields[FACT_CALLER_USR_IDX];
        parse_status     = p101_record_parse_size(fields[FACT_CALL_START_IDX], &fact->start);
        parsed           = parse_status != 0;
        if(parsed)
        {
            parse_status = p101_record_parse_size(fields[FACT_CALL_END_IDX], &fact->end);
            parsed       = parse_status != 0;
        }
        if(!parsed)
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
    }
    else if(fact->kind == P101_C_FACT_KIND_FUNCTION)
    {
        fact->usr    = fields[FACT_FUNCTION_USR_IDX];
        parse_status = p101_record_parse_size(fields[FACT_FUNCTION_START_IDX], &fact->start);
        parsed       = parse_status != 0;
        if(parsed)
        {
            parse_status = p101_record_parse_size(fields[FACT_FUNCTION_END_IDX], &fact->end);
            parsed       = parse_status != 0;
        }
        if(!parsed)
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
    }
    else if(fact->kind == P101_C_FACT_KIND_ENUMERATOR)
    {
        fact->caller     = fields[FACT_ENUMERATOR_TYPE_IDX];
        fact->usr        = fields[FACT_ENUMERATOR_USR_IDX];
        fact->caller_usr = fields[FACT_ENUMERATOR_PARENT_USR_IDX];
    }
    else if(fact->kind == P101_C_FACT_KIND_TYPE || fact->kind == P101_C_FACT_KIND_ENUM)
    {
        fact->usr = fields[FACT_TYPE_USR_IDX];
    }
    else if(fact->kind == P101_C_FACT_KIND_MACRO)
    {
        parsed = parse_fact_bool(env, fields[FACT_MACRO_DEFINITION_IDX], &fact->is_definition);
        if(parsed)
        {
            parse_status = p101_record_parse_size(fields[FACT_MACRO_START_IDX], &fact->start);
            parsed       = parse_status != 0;
        }
        if(parsed)
        {
            parse_status = p101_record_parse_size(fields[FACT_MACRO_END_IDX], &fact->end);
            parsed       = parse_status != 0;
        }
        if(!parsed)
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
        fact->caller_usr = fields[FACT_MACRO_CALLER_USR_IDX];
    }
    else if(fact->kind == P101_C_FACT_KIND_NOTE)
    {
        fact->caller     = fields[FACT_NOTE_CALLER_IDX];
        fact->caller_usr = fields[FACT_NOTE_CALLER_USR_IDX];
        parse_status     = p101_record_parse_size(fields[FACT_NOTE_START_IDX], &fact->start);
        parsed           = parse_status != 0;
        if(parsed)
        {
            parse_status = p101_record_parse_size(fields[FACT_NOTE_END_IDX], &fact->end);
            parsed       = parse_status != 0;
        }
        if(!parsed)
        {
            status = P101_C_FACT_MALFORMED;
            goto done;
        }
        parse_status = p101_record_parse_size(fields[FACT_NOTE_COLUMN_IDX], &fact->column);
        parsed       = parse_status != 0;
        if(!parsed)
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

enum p101_c_note_kind p101_c_note_kind_from_name(const struct p101_env *env, const char *name)
{
    enum p101_c_note_kind kind;

    P101_TRACE_SCOPE(env);
    kind = P101_C_NOTE_OTHER;
    if(name != NULL)
    {
        static const struct
        {
            const char           *name;
            enum p101_c_note_kind kind;
        } mappings[] = {
            {"ENV_CONTRACT",                                      P101_C_NOTE_ENV_CONTRACT           },
            {"ERROR_CONTRACT",                                    P101_C_NOTE_ERROR_CONTRACT         },
            {"ENV_USE",                                           P101_C_NOTE_ENV_USE                },
            {"ERROR_USE",                                         P101_C_NOTE_ERROR_USE              },
            {"TYPE_SEMANTIC_ROLE:p101:trace-scope",               P101_C_NOTE_TRACE_USE              },
            {"ERROR_CHECK",                                       P101_C_NOTE_ERROR_CHECK            },
            {"ERROR_OPTIONAL",                                    P101_C_NOTE_ERROR_OPTIONAL         },
            {"ERROR_DISCARD",                                     P101_C_NOTE_ERROR_DISCARD          },
            {"ERROR_PROPAGATED",                                  P101_C_NOTE_ERROR_PROPAGATED       },
            {"ERROR_UNCHECKED_CHAIN",                             P101_C_NOTE_ERROR_UNCHECKED_CHAIN  },
            {"FUNCTION_RETURN",                                   P101_C_NOTE_FUNCTION_RETURN        },
            {"FUNCTION_EARLY_RETURN",                             P101_C_NOTE_FUNCTION_EARLY_RETURN  },
            {"CALL_NOT_ISOLATED",                                 P101_C_NOTE_CALL_NOT_ISOLATED      },
            {"CALL_RESULT_DISCARDED",                             P101_C_NOTE_CALL_RESULT_DISCARDED  },
            {"SEMANTIC_ROLE:p101:termination-adapter",            P101_C_NOTE_TERMINATION_ADAPTER    },
            {"CALLEE_SEMANTIC_ROLE:p101:ownership:error:acquire", P101_C_NOTE_OWNERSHIP_ERROR_ACQUIRE},
            {"CALLEE_SEMANTIC_ROLE:p101:ownership:error:release", P101_C_NOTE_OWNERSHIP_ERROR_RELEASE},
            {"CALLEE_SEMANTIC_ROLE:p101:ownership:env:acquire",   P101_C_NOTE_OWNERSHIP_ENV_ACQUIRE  },
            {"CALLEE_SEMANTIC_ROLE:p101:ownership:env:release",   P101_C_NOTE_OWNERSHIP_ENV_RELEASE  },
        };

        for(size_t index = 0U; index < sizeof(mappings) / sizeof(mappings[0]); index++)
        {
            int comparison;

            comparison = p101_strcmp(env, name, mappings[index].name);
            if(comparison == 0)
            {
                kind = mappings[index].kind;
                break;
            }
        }
    }
    return kind;
}

const char *p101_c_note_kind_name(enum p101_c_note_kind kind)
{
    const char *name;

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(kind)
    {
        case P101_C_NOTE_ENV_CONTRACT:
            name = "ENV_CONTRACT";
            break;
        case P101_C_NOTE_ERROR_CONTRACT:
            name = "ERROR_CONTRACT";
            break;
        case P101_C_NOTE_ENV_USE:
            name = "ENV_USE";
            break;
        case P101_C_NOTE_ERROR_USE:
            name = "ERROR_USE";
            break;
        case P101_C_NOTE_TRACE_USE:
            name = "TYPE_SEMANTIC_ROLE:p101:trace-scope";
            break;
        case P101_C_NOTE_ERROR_CHECK:
            name = "ERROR_CHECK";
            break;
        case P101_C_NOTE_ERROR_OPTIONAL:
            name = "ERROR_OPTIONAL";
            break;
        case P101_C_NOTE_ERROR_DISCARD:
            name = "ERROR_DISCARD";
            break;
        case P101_C_NOTE_ERROR_PROPAGATED:
            name = "ERROR_PROPAGATED";
            break;
        case P101_C_NOTE_ERROR_UNCHECKED_CHAIN:
            name = "ERROR_UNCHECKED_CHAIN";
            break;
        case P101_C_NOTE_FUNCTION_RETURN:
            name = "FUNCTION_RETURN";
            break;
        case P101_C_NOTE_FUNCTION_EARLY_RETURN:
            name = "FUNCTION_EARLY_RETURN";
            break;
        case P101_C_NOTE_CALL_NOT_ISOLATED:
            name = "CALL_NOT_ISOLATED";
            break;
        case P101_C_NOTE_CALL_RESULT_DISCARDED:
            name = "CALL_RESULT_DISCARDED";
            break;
        case P101_C_NOTE_TERMINATION_ADAPTER:
            name = "SEMANTIC_ROLE:p101:termination-adapter";
            break;
        case P101_C_NOTE_OWNERSHIP_ERROR_ACQUIRE:
            name = "CALLEE_SEMANTIC_ROLE:p101:ownership:error:acquire";
            break;
        case P101_C_NOTE_OWNERSHIP_ERROR_RELEASE:
            name = "CALLEE_SEMANTIC_ROLE:p101:ownership:error:release";
            break;
        case P101_C_NOTE_OWNERSHIP_ENV_ACQUIRE:
            name = "CALLEE_SEMANTIC_ROLE:p101:ownership:env:acquire";
            break;
        case P101_C_NOTE_OWNERSHIP_ENV_RELEASE:
            name = "CALLEE_SEMANTIC_ROLE:p101:ownership:env:release";
            break;
        case P101_C_NOTE_OTHER:
        default:
            name = "OTHER";
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
    int  comparison;

    P101_TRACE_SCOPE(env);
    comparison = p101_strcmp(env, text, "0");
    if(comparison == 0)
    {
        *value              = false;
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    comparison = p101_strcmp(env, text, "1");
    if(comparison == 0)
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

static enum p101_c_fact_kind parse_kind(const struct p101_env *env, const char *text)
{
    enum p101_c_fact_kind kind;
    int                   comparison;

    P101_TRACE_SCOPE(env);
    kind       = P101_C_FACT_KIND_UNKNOWN;
    comparison = p101_strcmp(env, text, "FILE");
    if(comparison == 0)
    {
        kind = P101_C_FACT_KIND_FILE;
    }
    else
    {
        static const char *const names[] = {"INCLUDE", "FUNCTION", "CALL", "TYPE", "ENUM", "ENUMERATOR", "MACRO", "NOTE"};

        static const enum p101_c_fact_kind kinds[] = {P101_C_FACT_KIND_INCLUDE, P101_C_FACT_KIND_FUNCTION, P101_C_FACT_KIND_CALL, P101_C_FACT_KIND_TYPE, P101_C_FACT_KIND_ENUM, P101_C_FACT_KIND_ENUMERATOR, P101_C_FACT_KIND_MACRO, P101_C_FACT_KIND_NOTE};

        for(size_t index = 0U; index < sizeof(names) / sizeof(names[0]); index++)
        {
            comparison = p101_strcmp(env, text, names[index]);
            if(comparison == 0)
            {
                kind = kinds[index];
                break;
            }
        }
    }
    return kind;
}

static bool field_count_is_valid(enum p101_c_fact_kind kind, size_t field_count)
{
    static const size_t exact_fields[] = {
        [P101_C_FACT_KIND_UNKNOWN]    = FACT_BASE_FIELD_COUNT,
        [P101_C_FACT_KIND_FILE]       = FACT_BASE_FIELD_COUNT,
        [P101_C_FACT_KIND_INCLUDE]    = FACT_INCLUDE_FIELDS,
        [P101_C_FACT_KIND_FUNCTION]   = FACT_FUNCTION_FIELDS,
        [P101_C_FACT_KIND_CALL]       = FACT_CALL_FIELDS,
        [P101_C_FACT_KIND_TYPE]       = FACT_TYPE_FIELDS,
        [P101_C_FACT_KIND_ENUM]       = FACT_TYPE_FIELDS,
        [P101_C_FACT_KIND_ENUMERATOR] = FACT_ENUMERATOR_FIELDS,
        [P101_C_FACT_KIND_MACRO]      = FACT_MACRO_FIELDS,
        [P101_C_FACT_KIND_NOTE]       = FACT_NOTE_FIELDS,
    };

    return field_count == exact_fields[kind];
}
