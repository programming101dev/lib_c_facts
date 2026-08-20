#ifndef P101_C_FACTS_FACTS_H
#define P101_C_FACTS_FACTS_H

#include <p101_env/env.h>
#include <p101_error/error.h>
#include <stdbool.h>
#include <stddef.h>

#define P101_C_FACT_TAG "P101FACT"
#define P101_C_FACT_PREFIX "P101FACT\t"
#define P101_C_FACT_VERSION "8"

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
        P101_C_FACT_KIND_PARAMETER,
        P101_C_FACT_KIND_CALL,
        P101_C_FACT_KIND_TYPE,
        P101_C_FACT_KIND_ENUM,
        P101_C_FACT_KIND_ENUMERATOR,
        P101_C_FACT_KIND_MACRO,
        P101_C_FACT_KIND_NOTE
    };

    /*
     * The closed vocabulary of machine-generated NOTE names. It also covers
     * the fixed semantic-role annotations that the analysis emits verbatim:
     * the termination-adapter role and the error/env ownership roles.
     * Open-ended notes (any other semantic-role annotation,
     * FUNCTION_REFERENCE identities) map to P101_C_NOTE_OTHER and must be
     * interpreted from the note text. New kinds are appended so the numeric
     * value of an existing kind never changes.
     */
    enum p101_c_note_kind
    {
        P101_C_NOTE_OTHER = 0,
        P101_C_NOTE_ENV_CONTRACT,
        P101_C_NOTE_ERROR_CONTRACT,
        P101_C_NOTE_ENV_USE,
        P101_C_NOTE_ERROR_USE,
        P101_C_NOTE_TRACE_USE,
        P101_C_NOTE_ERROR_CHECK,
        P101_C_NOTE_ERROR_OPTIONAL,
        P101_C_NOTE_ERROR_DISCARD,
        P101_C_NOTE_ERROR_PROPAGATED,
        P101_C_NOTE_ERROR_UNCHECKED_CHAIN,
        P101_C_NOTE_ERROR_OUTPUT_UNCHECKED,
        P101_C_NOTE_FUNCTION_RETURN,
        P101_C_NOTE_FUNCTION_EARLY_RETURN,
        P101_C_NOTE_CALL_NOT_ISOLATED,
        P101_C_NOTE_CALL_RESULT_DISCARDED,
        P101_C_NOTE_TERMINATION_ADAPTER,
        P101_C_NOTE_OWNERSHIP_ERROR_ACQUIRE,
        P101_C_NOTE_OWNERSHIP_ERROR_RELEASE,
        P101_C_NOTE_OWNERSHIP_ENV_ACQUIRE,
        P101_C_NOTE_OWNERSHIP_ENV_RELEASE,
        P101_C_NOTE_SIGNATURE_ENV_ORDER,
        P101_C_NOTE_FIELD_REACH,
        P101_C_NOTE_ALLOC_SIZEOF_TYPE,
        P101_C_NOTE_MACRO_ARGUMENT_BARE,
        P101_C_NOTE_MACRO_STATEMENT_BARE,
        P101_C_NOTE_HANDLER_REGISTERED,
        P101_C_NOTE_MUST_CHECK_RESULT_DISCARDED,
        P101_C_NOTE_ERROR_CLEANUP_SHADOW,
        P101_C_NOTE_PARTIAL_RESULT_DISCARDED,
        P101_C_NOTE_UNCERTAIN_PROGRESS_RETRIED,
        P101_C_NOTE_CONDITION_WAIT_OUTSIDE_LOOP,
        P101_C_NOTE_POST_FORK_UNSAFE_CALL,
        P101_C_NOTE_ZERO_SIZE_ALLOCATION,
        P101_C_NOTE_OVERLAPPING_RESTRICTED_COPY,
        P101_C_NOTE_THREAD_AUTOMATIC_STORAGE_ESCAPE,
        P101_C_NOTE_ENV_BORROWED_POINTER_INVALIDATED,
        P101_C_NOTE_PATH_TOCTOU,
        P101_C_NOTE_SIGNAL_HANDLER_REGISTERED,
        P101_C_NOTE_SIGNAL_SHARED_OBJECT_ACCESS,
        P101_C_NOTE_RECURSIVE_CALL
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
        size_t                parameter_index;
        char                 *value;
        char                 *type;
        char                 *canonical_type;
        char                 *return_type;
        char                 *caller;
        char                 *usr;
        char                 *caller_usr;
        char                 *resolved; /* INCLUDE only: the resolved file, empty when unresolved. */
        bool                  is_local;
        bool                  is_static;
        bool                  is_declaration;
        bool                  is_definition;
        bool                  is_variadic;
        bool                  has_env_parameter;
        bool                  has_error_parameter;
        bool                  is_indirect;
    };

    enum p101_c_fact_status p101_c_fact_parse_line(const struct p101_env *env, struct p101_error *err, char *line, struct p101_c_fact *fact);
    const char             *p101_c_fact_kind_name(enum p101_c_fact_kind kind);
    const char             *p101_c_fact_status_name(enum p101_c_fact_status status);
    enum p101_c_note_kind   p101_c_note_kind_from_name(const struct p101_env *env, const char *name);
    const char             *p101_c_note_kind_name(enum p101_c_note_kind kind);

#ifdef __cplusplus
}
#endif

#endif    // P101_C_FACTS_FACTS_H
