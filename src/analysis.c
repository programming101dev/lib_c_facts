#include "p101_c_facts/analysis.h"
#include <clang-c/CXCompilationDatabase.h>
#include <clang-c/Index.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
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
#include <stdint.h>
#include <sys/stat.h>

enum
{
    ANALYSIS_PATH_SIZE              = 4096,
    ANALYSIS_NAME_SIZE              = 256,
    ANALYSIS_IDENTITY_SIZE          = 4096,
    ANALYSIS_MAX_ARGUMENTS          = 1024,
    ANALYSIS_INITIAL_MACRO_CAPACITY = 256,
    ANALYSIS_INITIAL_PATH_CAPACITY  = 64,
    NULL_POINTER_CAST_DEPTH         = 8
};

static const char   P101_ENV_TYPE_USR[]    = "c:@S@p101_env";
static const char   P101_ERROR_TYPE_USR[]  = "c:@S@p101_error";
static const size_t PATH_HASH_OFFSET_BASIS = (size_t)1469598103934665603ULL;
static const size_t PATH_HASH_PRIME        = (size_t)1099511628211ULL;

enum
{
    SEMANTIC_IDENTITY_CAPACITY = 16
};

typedef char analysis_path[ANALYSIS_PATH_SIZE];

struct path_admission_entry
{
    char *path;
    bool  admitted;
};

struct analysis_session
{
    const struct p101_env                *env;
    struct p101_error                    *err;
    const struct p101_c_analysis_options *options;
    struct path_admission_entry          *path_admissions;
    size_t                                path_admission_count;
    size_t                                path_admission_capacity;
};

struct cursor_ancestry
{
    CXCursor                      cursor;
    const struct cursor_ancestry *parent;
};

struct macro_expansion_range
{
    CXFile   file;
    unsigned start;
    unsigned end;
};

struct semantic_identity_state
{
    char   identity[ANALYSIS_IDENTITY_SIZE];
    bool   invalidated;
    size_t invalidated_after;
};

struct signal_action_binding
{
    char owner_identity[ANALYSIS_IDENTITY_SIZE];
    char handler_name[ANALYSIS_NAME_SIZE];
    char handler_usr[ANALYSIS_IDENTITY_SIZE];
};

struct scan_context
{
    const struct p101_env                *env;
    struct p101_error                    *err;
    const struct p101_c_analysis_options *options;
    struct analysis_session              *session;
    p101_c_analysis_observer              observer;
    void                                 *observer_context;
    CXTranslationUnit                     translation_unit;
    const char                           *current_function;
    const char                           *current_function_usr;
    char                                  current_enum[ANALYSIS_NAME_SIZE];
    char                                  current_enum_usr[ANALYSIS_IDENTITY_SIZE];
    char                                  pending_error_identity[ANALYSIS_IDENTITY_SIZE];
    char                                  pending_result_identity[ANALYSIS_IDENTITY_SIZE];
    char                                  pending_result_error_identity[ANALYSIS_IDENTITY_SIZE];
    size_t                                pending_result_end;
    bool                                  pending_result_reported;
    char                                  checked_error_identity[ANALYSIS_IDENTITY_SIZE];
    unsigned                              conditional_depth;
    size_t                                final_return_start;
    CXCursor                              final_return_label;
    bool                                  conditional_has_return;
    bool                                  inside_return;
    bool                                  stopped;
    bool                                  had_parse_failure;
    const struct cursor_ancestry         *ancestry;
    char                                  uncertain_progress_usr[ANALYSIS_IDENTITY_SIZE];
    char                                  uncertain_progress_identity[ANALYSIS_IDENTITY_SIZE];
    bool                                  post_fork_child_function;
    bool                                  current_recursion_bounded;
    struct semantic_identity_state        environment_borrows[SEMANTIC_IDENTITY_CAPACITY];
    size_t                                environment_borrow_count;
    char                                  checked_path_identity[ANALYSIS_IDENTITY_SIZE];
    struct signal_action_binding          signal_action_bindings[SEMANTIC_IDENTITY_CAPACITY];
    size_t                                signal_action_binding_count;
    struct macro_expansion_range         *macro_expansions;
    size_t                                macro_expansion_count;
    size_t                                macro_expansion_capacity;
};

struct inclusion_context
{
    struct scan_context *scan;
};

struct binary_operands
{
    CXCursor left;
    CXCursor right;
    unsigned count;
};

static bool path_is_admitted(struct analysis_session *session, const char *path);
static void path_admission_cache_destroy(struct analysis_session *session);
static bool path_has_source_suffix(const struct p101_env *env, const char *path);
static bool path_has_header_suffix(const struct p101_env *env, const char *path);
static bool scan_source(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, struct analysis_session *session, p101_c_analysis_observer observer, void *observer_context, const char *source, const char *directory,
                        const char *const arguments[], size_t argument_count);
static bool scan_directory(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, struct analysis_session *session, p101_c_analysis_observer observer, void *observer_context, const char *directory);
static bool scan_compile_database(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, struct analysis_session *session, p101_c_analysis_observer observer, void *observer_context);
static enum CXChildVisitResult visit_cursor(CXCursor cursor, CXCursor parent, CXClientData client_data);
static void                    visit_inclusion(CXFile included_file, CXSourceLocation *inclusion_stack, unsigned include_length, CXClientData client_data);
static void                    emit_cursor_record(struct scan_context *context, CXCursor cursor, CXCursor parent);
static char                   *enum_cursor_name(const struct p101_env *env, struct p101_error *err, CXCursor cursor, CXCursor parent);
static void                    emit_mutation_record(struct scan_context *context, CXCursor cursor, CXCursor parent, const char *path, size_t line, size_t column);
static bool                    emit_record(struct scan_context *context, const struct p101_c_analysis_record *record);
static char                   *copy_cx_string(const struct p101_env *env, struct p101_error *err, CXString value);
static char                   *copy_text(const struct p101_env *env, struct p101_error *err, const char *text);
static char                   *source_range_text(const struct p101_env *env, struct p101_error *err, CXTranslationUnit translation_unit, const char *path, size_t start, size_t end);
static char                   *include_target_text(const struct p101_env *env, struct p101_error *err, CXTranslationUnit translation_unit, CXCursor cursor, const char *path, bool *is_local);
static char                   *include_resolved_path(const struct p101_env *env, struct p101_error *err, CXCursor cursor);
static void                    cursor_location(const struct p101_env *env, struct p101_error *err, CXCursor cursor, char **path, size_t *line, size_t *column, size_t *offset);
static bool                    cursor_is_definition(CXCursor cursor);
static int                     function_parameter_index(const struct p101_env *env, CXCursor cursor, const char *record_usr);
static bool                    cursor_type_is_record_pointer(const struct p101_env *env, CXCursor cursor, const char *record_usr);
static bool                    function_has_semantic_role(const struct p101_env *env, CXCursor cursor, const char *role);
static bool                    function_result_must_be_checked(const struct p101_env *env, CXCursor cursor);
static bool                    ancestry_contains_loop(const struct scan_context *context);
static bool                    semantic_role_function_name(const struct p101_env *env, CXTranslationUnit translation_unit, const char *role, char *name, size_t name_size);
static void                    emit_function_semantic_roles(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *function);
static void                    emit_callee_semantic_roles(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *call);
static bool                    function_is_error_state_query(const struct p101_env *env, CXCursor cursor);
static size_t                  function_final_return_start(CXCursor cursor, CXCursor *label);
static bool                    call_discards_error(CXCursor cursor, unsigned argument_index);
static bool                    cursor_is_null_pointer_constant(CXCursor cursor);
static CXCursor                call_referenced_cursor(CXCursor cursor);
static bool                    call_uses_optional_error(const struct p101_env *env, CXCursor cursor, unsigned argument_index);
static bool                    call_is_generated_by_macro(CXCursor cursor);
static bool                    call_is_covered_by_macro_expansion(const struct scan_context *context, CXCursor cursor);
static bool                    call_has_written_invocation(struct scan_context *context, const char *path, size_t start, size_t end);
static enum CXChildVisitResult collect_macro_expansion(CXCursor cursor, CXCursor parent, CXClientData client_data);
static bool                    call_is_isolated(struct scan_context *context, CXCursor cursor, CXCursor parent);
static bool                    binary_parent_is_simple_assignment(CXCursor parent);
static char                   *cursor_argument_identity(const struct p101_env *env, struct p101_error *err, CXCursor cursor, unsigned index);
static char                   *call_operation_identity(const struct p101_env *env, struct p101_error *err, CXCursor call, CXCursor function);
static char                   *call_path_identity(const struct p101_env *env, struct p101_error *err, CXCursor call, CXCursor function);
static bool                    call_result_identity(struct scan_context *context, CXCursor parent, char *identity, size_t identity_size);
static bool                    result_use_requires_checked_error(struct scan_context *context, CXCursor cursor);
static bool                    call_has_role_or_usr(const struct p101_env *env, CXCursor function, const char *role, const char *const identities[], size_t identity_count);
static bool                    cursor_integer_value(CXCursor cursor, int64_t *value);
static bool                    argument_references_automatic_storage(CXCursor argument);
static bool                    cursor_is_signal_safe_shared_object(const struct p101_env *env, CXCursor cursor);
static void                    emit_secure_semantic_call_notes(struct scan_context *context, CXCursor cursor, CXCursor parent, CXCursor referenced, const struct p101_c_analysis_record *record, const char *path, size_t line, size_t column);
static void                    observe_semantic_reference(struct scan_context *context, CXCursor cursor, const char *path, size_t line, size_t column, size_t start, size_t end, bool is_header);
static void                    emit_note(struct scan_context *context, const char *path, size_t line, size_t column, size_t start, size_t end, bool is_header, const char *name);
static void                    emit_note_as(struct scan_context *context, const char *path, size_t line, size_t column, size_t start, size_t end, bool is_header, const char *name, const char *caller, const char *caller_usr);
static void                    cursor_extent_offsets(CXCursor cursor, size_t *start, size_t *end);
static enum CXChildVisitResult capture_binary_operands(CXCursor cursor, CXCursor parent, CXClientData client_data);
static void                    mutation_from_binary(struct scan_context *context, CXCursor cursor, const char *path, size_t line, size_t column);
static void                    mutation_from_call(struct scan_context *context, CXCursor cursor, CXCursor parent, const char *path, size_t line, size_t column);
static bool                    should_skip_directory(const struct p101_env *env, const char *name);
static bool                    command_argument_is_output(const struct p101_env *env, const char *argument);
static bool                    command_argument_takes_ignored_value(const struct p101_env *env, const char *argument);
static bool                    command_argument_takes_semantic_value(const struct p101_env *env, const char *argument);
static bool                    command_argument_is_semantic(const struct p101_env *env, const char *argument);
static void                    emit_signature_notes(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *record, const char *path, size_t line, size_t column);
static void                    emit_allocation_notes(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *record, const char *path, size_t line, size_t column);
static void                    emit_handler_notes(struct scan_context *context, CXCursor cursor, const char *path, size_t line, size_t column, bool is_header);
static void                    remember_signal_action_binding(struct scan_context *context, CXCursor cursor);
static void                    emit_macro_hygiene_notes(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *record, const char *path, size_t line, size_t column);
static void                    emit_field_reach_note(struct scan_context *context, CXCursor cursor, const char *path, size_t line, size_t column, bool is_header);
static bool                    callee_usr_is_allocator(const struct p101_env *env, const char *usr);
static bool                    callee_usr_registers_handler(const struct p101_env *env, const char *usr);

static enum CXChildVisitResult probe_sizeof_type(CXCursor candidate, CXCursor parent, CXClientData client_data);
static enum CXChildVisitResult probe_sizeof_expression_child(CXCursor candidate, CXCursor parent, CXClientData client_data);
static bool                    token_is_bare_operator(const struct p101_env *env, const char *spelling);

static char *copy_text(const struct p101_env *env, struct p101_error *err, const char *text)
{
    char  *copy;
    void  *storage;
    size_t length;

    P101_TRACE_SCOPE(env);
    if(text == NULL)
    {
        text = "";
    }
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
    const char *text;
    char       *copy;

    P101_TRACE_SCOPE(env);
    text = clang_getCString(value);
    copy = copy_text(env, err, text);
    clang_disposeString(value);
    return copy;
}

static bool has_suffix(const struct p101_env *env, const char *path, const char *suffix)
{
    bool   p101_single_result_;
    size_t path_length;
    size_t suffix_length;
    int    comparison;

    P101_TRACE_SCOPE(env);
    path_length   = p101_strlen(env, path);
    suffix_length = p101_strlen(env, suffix);
    if(path_length < suffix_length)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    comparison          = p101_strcmp(env, path + path_length - suffix_length, suffix);
    p101_single_result_ = comparison == 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool path_has_source_suffix(const struct p101_env *env, const char *path)
{
    bool p101_single_result_;
    bool matches;

    P101_TRACE_SCOPE(env);
    matches = has_suffix(env, path, ".c");
    if(!matches)
    {
        matches = has_suffix(env, path, ".cc");
    }
    if(!matches)
    {
        matches = has_suffix(env, path, ".cpp");
    }
    if(!matches)
    {
        matches = has_suffix(env, path, ".cxx");
    }
    if(!matches)
    {
        matches = has_suffix(env, path, ".m");
    }
    if(!matches)
    {
        matches = has_suffix(env, path, ".mm");
    }
    if(matches)
    {
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool path_has_header_suffix(const struct p101_env *env, const char *path)
{
    bool p101_single_result_;
    bool matches;

    P101_TRACE_SCOPE(env);
    matches = has_suffix(env, path, ".h");
    if(!matches)
    {
        matches = has_suffix(env, path, ".hh");
    }
    if(!matches)
    {
        matches = has_suffix(env, path, ".hpp");
    }
    if(!matches)
    {
        matches = has_suffix(env, path, ".hxx");
    }
    if(matches)
    {
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static size_t path_admission_hash(const char *path)
{
    size_t p101_single_result_;
    size_t hash;
    size_t index;
    size_t product;
    bool   wrapped;

    hash  = PATH_HASH_OFFSET_BASIS;
    index = 0U;
    while(path[index] != '\0')
    {
        hash ^= (size_t)(unsigned char)path[index];
        /* FNV-1a requires modulo-size_t multiplication. The overflow builtin
         * defines that wrap explicitly, including under integer sanitizers. */
        wrapped = __builtin_mul_overflow(hash, PATH_HASH_PRIME, &product);
        (void)wrapped;
        hash = product;
        index++;
    }
    p101_single_result_ = hash;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool path_admission_cache_reserve(struct analysis_session *session, size_t needed)
{
    bool                         p101_single_result_;
    size_t                       capacity;
    struct path_admission_entry *entries;
    void                        *allocation;
    size_t                       index;

    capacity = session->path_admission_capacity;
    if(capacity > 0U && needed * 4U < capacity * 3U)
    {
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    if(capacity == 0U)
    {
        capacity = ANALYSIS_INITIAL_PATH_CAPACITY;
    }
    else
    {
        capacity *= 2U;
    }
    allocation = p101_calloc(session->env, session->err, capacity, sizeof(*entries));
    entries    = (struct path_admission_entry *)allocation;
    if(entries == NULL)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    for(index = 0U; index < session->path_admission_capacity; index++)
    {
        struct path_admission_entry entry;
        size_t                      slot;
        size_t                      hash;

        entry = session->path_admissions[index];
        if(entry.path == NULL)
        {
            continue;
        }
        hash = path_admission_hash(entry.path);
        slot = hash & (capacity - 1U);
        while(entries[slot].path != NULL)
        {
            slot = (slot + 1U) & (capacity - 1U);
        }
        entries[slot] = entry;
    }
    p101_free(session->env, session->path_admissions);
    session->path_admissions         = entries;
    session->path_admission_capacity = capacity;
    p101_single_result_              = true;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool path_is_admitted(struct analysis_session *session, const char *path)
{
    bool                         p101_single_result_;
    size_t                       hash;
    size_t                       slot;
    struct path_admission_entry *entry;
    int                          comparison;
    char                         actual[ANALYSIS_PATH_SIZE];
    const char                  *resolved;
    bool                         admitted;
    size_t                       index;
    char                        *path_copy;
    bool                         reserved;

    P101_TRACE_SCOPE(session->env);
    if(path == NULL || path[0] == '\0')
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    hash = path_admission_hash(path);
    if(session->path_admission_capacity > 0U)
    {
        slot  = hash & (session->path_admission_capacity - 1U);
        entry = &session->path_admissions[slot];
        while(entry->path != NULL)
        {
            comparison = p101_strcmp(session->env, entry->path, path);
            if(comparison == 0)
            {
                p101_single_result_ = entry->admitted;
                goto p101_single_exit_;
            }
            slot  = (slot + 1U) & (session->path_admission_capacity - 1U);
            entry = &session->path_admissions[slot];
        }
    }

    resolved = p101_realpath(session->env, session->err, path, actual);
    if(resolved == NULL)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    admitted = false;
    for(index = 0U; index < session->options->path_count; index++)
    {
        const char *root;
        size_t      length;

        root = session->options->paths[index];
        if(root == NULL)
        {
            continue;
        }
        length     = p101_strlen(session->env, root);
        comparison = p101_strncmp(session->env, actual, root, length);
        if(comparison == 0 && (actual[length] == '\0' || actual[length] == '/'))
        {
            admitted = true;
            break;
        }
    }
    reserved = path_admission_cache_reserve(session, session->path_admission_count + 1U);
    if(!reserved)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    path_copy = copy_text(session->env, session->err, path);
    if(path_copy == NULL)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    slot  = hash & (session->path_admission_capacity - 1U);
    entry = &session->path_admissions[slot];
    while(entry->path != NULL)
    {
        slot  = (slot + 1U) & (session->path_admission_capacity - 1U);
        entry = &session->path_admissions[slot];
    }
    entry->path     = path_copy;
    entry->admitted = admitted;
    session->path_admission_count++;
    p101_single_result_ = admitted;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void path_admission_cache_destroy(struct analysis_session *session)
{
    size_t index;

    for(index = 0U; index < session->path_admission_capacity; index++)
    {
        p101_free(session->env, session->path_admissions[index].path);
    }
    p101_free(session->env, session->path_admissions);
    session->path_admissions         = NULL;
    session->path_admission_count    = 0U;
    session->path_admission_capacity = 0U;
}

static bool emit_record(struct scan_context *context, const struct p101_c_analysis_record *record)
{
    bool p101_single_result_;
    bool keep_going;
    bool has_error;

    keep_going = context->observer(context->env, context->err, record, context->observer_context);
    has_error  = p101_error_has_error(context->err);
    if(!keep_going || has_error)
    {
        context->stopped    = true;
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    p101_single_result_ = true;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void cursor_location(const struct p101_env *env, struct p101_error *err, CXCursor cursor, char **path, size_t *line, size_t *column, size_t *offset)
{
    CXFile           file;
    CXString         name;
    unsigned         raw_line;
    unsigned         raw_column;
    unsigned         raw_offset;
    CXSourceLocation location;

    *path = NULL;
    /*
     * Attribute facts to the source that invoked a macro, not to the header
     * that defines it.  Wrapper instrumentation is intentionally expressed
     * through macros such as P101_TRACE and P101_*_FAULT_RETURN; using the
     * spelling location made those calls disappear when the admitted roots
     * excluded lib_env's headers.
     */
    location = clang_getCursorLocation(cursor);
    clang_getExpansionLocation(location, &file, &raw_line, &raw_column, &raw_offset);
    *line   = raw_line;
    *column = raw_column;
    *offset = raw_offset;
    if(file == NULL)
    {
        goto p101_single_exit_;
    }
    name  = clang_getFileName(file);
    *path = copy_cx_string(env, err, name);

p101_single_exit_:
    return;
}

static bool cursor_is_definition(CXCursor cursor)
{
    unsigned definition;

    definition = clang_isCursorDefinition(cursor);
    return definition != 0U;
}

static bool cursor_kind_is_function(enum CXCursorKind kind)
{
    return (kind == CXCursor_FunctionDecl || kind == CXCursor_CXXMethod || kind == CXCursor_Constructor || kind == CXCursor_Destructor) != 0;
}

static bool type_is_record_pointer(const struct p101_env *env, CXType type, const char *record_usr)
{
    bool        matches;
    CXType      canonical;
    CXType      pointee;
    CXCursor    declaration;
    CXString    usr_value;
    const char *usr;
    int         comparison;
    int         is_null;

    matches   = false;
    canonical = clang_getCanonicalType(type);
    if(canonical.kind != CXType_Pointer)
    {
        goto done;
    }
    pointee     = clang_getPointeeType(canonical);
    pointee     = clang_getCanonicalType(pointee);
    declaration = clang_getTypeDeclaration(pointee);
    is_null     = clang_Cursor_isNull(declaration);
    if(is_null != 0)
    {
        goto done;
    }
    usr_value  = clang_getCursorUSR(declaration);
    usr        = clang_getCString(usr_value);
    comparison = -1;
    if(usr != NULL)
    {
        comparison = p101_strcmp(env, usr, record_usr);
    }
    if(usr != NULL && comparison == 0)
    {
        matches = true;
    }
    clang_disposeString(usr_value);

done:
    return matches;
}

struct record_contract_context
{
    const struct p101_env *env;
    const char            *record_usr;
    unsigned               remaining_depth;
    bool                   found;
};

static bool type_contains_record_pointer(const struct p101_env *env, CXType type, const char *record_usr, unsigned remaining_depth);

static enum CXVisitorResult visit_record_contract_field(CXCursor cursor, CXClientData client_data)
{
    struct record_contract_context *context;
    CXType                          type;
    bool                            contains;
    enum CXVisitorResult            result;

    context  = (struct record_contract_context *)client_data;
    type     = clang_getCursorType(cursor);
    contains = type_contains_record_pointer(context->env, type, context->record_usr, context->remaining_depth);
    if(contains)
    {
        context->found = true;
        result         = CXVisit_Break;
        goto p101_single_exit_;
    }
    result = CXVisit_Continue;

p101_single_exit_:
    return result;
}

static bool type_contains_record_pointer(const struct p101_env *env, CXType type, const char *record_usr, unsigned remaining_depth)
{
    struct record_contract_context context;
    CXType                         aggregate;
    CXType                         canonical;
    CXType                         pointee;
    bool                           contains;
    unsigned                       visited;

    contains = type_is_record_pointer(env, type, record_usr);
    if(contains)
    {
        goto p101_single_exit_;
    }
    if(remaining_depth == 0U)
    {
        goto p101_single_exit_;
    }

    canonical = clang_getCanonicalType(type);
    aggregate = canonical;
    if(canonical.kind == CXType_Pointer)
    {
        pointee   = clang_getPointeeType(canonical);
        aggregate = clang_getCanonicalType(pointee);
    }
    if(aggregate.kind != CXType_Record)
    {
        goto p101_single_exit_;
    }

    context.env             = env;
    context.record_usr      = record_usr;
    context.remaining_depth = remaining_depth - 1U;
    context.found           = false;
    visited                 = clang_Type_visitFields(aggregate, visit_record_contract_field, &context);
    (void)visited;
    contains = context.found;

p101_single_exit_:
    return contains;
}

struct record_contract_use_context
{
    const struct p101_env *env;
    const char            *record_usr;
    bool                   found;
};

static enum CXChildVisitResult find_record_contract_use(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct record_contract_use_context *context;
    enum CXChildVisitResult             result;
    enum CXCursorKind                   kind;
    CXType                              type;
    bool                                contains;

    context  = (struct record_contract_use_context *)client_data;
    result   = CXChildVisit_Recurse;
    kind     = clang_getCursorKind(cursor);
    contains = false;
    if(kind == CXCursor_CStyleCastExpr)
    {
        type     = clang_getCursorType(cursor);
        contains = type_contains_record_pointer(context->env, type, context->record_usr, 4U);
    }
    if(contains)
    {
        context->found = true;
        result         = CXChildVisit_Break;
    }
    (void)parent;
    return result;
}

static int function_parameter_index(const struct p101_env *env, CXCursor cursor, const char *record_usr)
{
    int result;
    int count;

    result = -1;
    count  = clang_Cursor_getNumArguments(cursor);
    for(int index = 0; index < count && result < 0; index++)
    {
        CXCursor argument;
        CXType   type;
        bool     contains;

        argument = clang_Cursor_getArgument(cursor, (unsigned)index);
        type     = clang_getCursorType(argument);
        contains = type_is_record_pointer(env, type, record_usr);
        if(contains)
        {
            result = index;
        }
    }
    return result;
}

static bool function_has_record_contract(const struct p101_env *env, CXCursor cursor, const char *record_usr)
{
    struct record_contract_use_context context;
    int                                count;
    bool                               found;

    found = false;
    count = clang_Cursor_getNumArguments(cursor);
    for(int index = 0; index < count && !found; index++)
    {
        CXCursor argument;
        CXType   type;

        argument = clang_Cursor_getArgument(cursor, (unsigned)index);
        type     = clang_getCursorType(argument);
        found    = type_contains_record_pointer(env, type, record_usr, 2U);
    }
    if(!found)
    {
        context.env        = env;
        context.record_usr = record_usr;
        context.found      = false;
        clang_visitChildren(cursor, find_record_contract_use, &context);
        found = context.found;
    }
    return found;
}

static bool cursor_type_is_record_pointer(const struct p101_env *env, CXCursor cursor, const char *record_usr)
{
    CXType type;
    bool   result;

    type   = clang_getCursorType(cursor);
    result = type_is_record_pointer(env, type, record_usr);
    return result;
}

struct semantic_role_context
{
    const struct p101_env *env;
    const char            *role;
    bool                   found;
};

static enum CXChildVisitResult find_semantic_role(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct semantic_role_context *context;
    enum CXChildVisitResult       result;
    enum CXCursorKind             kind;

    context = (struct semantic_role_context *)client_data;
    result  = CXChildVisit_Continue;
    kind    = clang_getCursorKind(cursor);
    if(kind == CXCursor_AnnotateAttr)
    {
        CXString    spelling;
        const char *text;
        int         comparison;

        spelling   = clang_getCursorSpelling(cursor);
        text       = clang_getCString(spelling);
        comparison = -1;
        if(text != NULL)
        {
            comparison = p101_strcmp(context->env, text, context->role);
        }
        if(text != NULL && comparison == 0)
        {
            context->found = true;
            result         = CXChildVisit_Break;
        }
        clang_disposeString(spelling);
    }
    (void)parent;
    return result;
}

static bool function_has_semantic_role(const struct p101_env *env, CXCursor cursor, const char *role)
{
    struct semantic_role_context context;

    context.env   = env;
    context.role  = role;
    context.found = false;
    clang_visitChildren(cursor, find_semantic_role, &context);
    return context.found;
}

static bool function_result_must_be_checked(const struct p101_env *env, CXCursor cursor)
{
    return function_has_semantic_role(env, cursor, "p101:result:must-check");
}

static bool ancestry_contains_loop(const struct scan_context *context)
{
    const struct cursor_ancestry *item;
    bool                          found;

    found = false;
    item  = context->ancestry;
    while(item != NULL)
    {
        enum CXCursorKind kind;

        kind = clang_getCursorKind(item->cursor);
        if(kind == CXCursor_WhileStmt || kind == CXCursor_DoStmt || kind == CXCursor_ForStmt || kind == CXCursor_CXXForRangeStmt)
        {
            found = true;
            break;
        }
        item = item->parent;
    }
    return found;
}

struct emit_semantic_role_context
{
    struct scan_context                 *scan;
    const struct p101_c_analysis_record *record;
    const char                          *prefix;
    const char                          *caller;
    const char                          *caller_usr;
};

static enum CXChildVisitResult emit_semantic_role(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct emit_semantic_role_context *context;
    enum CXChildVisitResult            result;
    enum CXCursorKind                  kind;

    context = (struct emit_semantic_role_context *)client_data;
    kind    = clang_getCursorKind(cursor);
    if(kind == CXCursor_AnnotateAttr)
    {
        CXString    spelling;
        const char *role;
        char        note[ANALYSIS_NAME_SIZE];
        int         written;

        spelling = clang_getCursorSpelling(cursor);
        role     = clang_getCString(spelling);
        written  = -1;
        if(role != NULL)
        {
            written = p101_snprintf(context->scan->env, context->scan->err, note, sizeof(note), "%s%s", context->prefix, role);
        }
        if(written >= 0 && (size_t)written < sizeof(note))
        {
            emit_note_as(context->scan, context->record->path, context->record->line, context->record->column, context->record->start_offset, context->record->end_offset, context->record->is_header, note, context->caller, context->caller_usr);
        }
        if(written < 0 || (size_t)written >= sizeof(note))
        {
            bool no_error;

            no_error = p101_error_has_no_error(context->scan->err);
            if(role != NULL && no_error)
            {
                P101_ERROR_RAISE_USER(context->scan->err, "A semantic role annotation exceeds the supported fact size.", EOVERFLOW);
                context->scan->stopped = true;
            }
        }
        clang_disposeString(spelling);
    }
    (void)parent;
    result = CXChildVisit_Continue;
    if(context->scan->stopped)
    {
        result = CXChildVisit_Break;
    }
    return result;
}

static void emit_function_semantic_roles(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *function)
{
    struct emit_semantic_role_context role_context;

    role_context.scan       = context;
    role_context.record     = function;
    role_context.prefix     = "SEMANTIC_ROLE:";
    role_context.caller     = function->name;
    role_context.caller_usr = function->usr;
    clang_visitChildren(cursor, emit_semantic_role, &role_context);
}

static void emit_callee_semantic_roles(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *call)
{
    struct emit_semantic_role_context role_context;

    role_context.scan       = context;
    role_context.record     = call;
    role_context.prefix     = "CALLEE_SEMANTIC_ROLE:";
    role_context.caller     = call->caller;
    role_context.caller_usr = call->caller_usr;
    clang_visitChildren(cursor, emit_semantic_role, &role_context);
}

static void emit_type_semantic_roles(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *record)
{
    CXCursor                          declaration;
    struct emit_semantic_role_context role_context;
    CXType                            type;
    int                               is_null;

    type        = clang_getCursorType(cursor);
    declaration = clang_getTypeDeclaration(type);
    is_null     = clang_Cursor_isNull(declaration);
    if(is_null != 0)
    {
        goto p101_single_exit_;
    }
    role_context.scan       = context;
    role_context.record     = record;
    role_context.prefix     = "TYPE_SEMANTIC_ROLE:";
    role_context.caller     = context->current_function;
    role_context.caller_usr = context->current_function_usr;
    clang_visitChildren(declaration, emit_semantic_role, &role_context);

p101_single_exit_:
    return;
}

struct final_statement_context
{
    CXCursor body;
    CXCursor last_statement;
};

static enum CXChildVisitResult find_function_body(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct final_statement_context *context;
    enum CXCursorKind               kind;
    enum CXChildVisitResult         result;

    context = (struct final_statement_context *)client_data;
    kind    = clang_getCursorKind(cursor);
    if(kind == CXCursor_CompoundStmt)
    {
        context->body = cursor;
        result        = CXChildVisit_Break;
        goto p101_single_exit_;
    }
    (void)parent;
    result = CXChildVisit_Continue;

p101_single_exit_:
    return result;
}

static enum CXChildVisitResult remember_last_statement(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct final_statement_context *context;

    context                 = (struct final_statement_context *)client_data;
    context->last_statement = cursor;
    (void)parent;
    return CXChildVisit_Continue;
}

static size_t function_final_return_start(CXCursor cursor, CXCursor *label)
{
    struct final_statement_context context;
    size_t                         start;
    size_t                         end;
    int                            is_null;
    enum CXCursorKind              kind;

    context.body           = clang_getNullCursor();
    context.last_statement = clang_getNullCursor();
    clang_visitChildren(cursor, find_function_body, &context);
    is_null = clang_Cursor_isNull(context.body);
    if(is_null == 0)
    {
        clang_visitChildren(context.body, remember_last_statement, &context);
    }
    *label = clang_getNullCursor();
    kind   = clang_getCursorKind(context.last_statement);
    while(kind == CXCursor_LabelStmt)
    {
        CXCursor labeled_statement;

        labeled_statement      = context.last_statement;
        context.last_statement = clang_getNullCursor();
        is_null                = clang_Cursor_isNull(*label);
        if(is_null != 0)
        {
            *label = labeled_statement;
        }
        clang_visitChildren(labeled_statement, remember_last_statement, &context);
        kind = clang_getCursorKind(context.last_statement);
    }
    start = 0U;
    kind  = clang_getCursorKind(context.last_statement);
    if(kind == CXCursor_ReturnStmt)
    {
        cursor_extent_offsets(context.last_statement, &start, &end);
    }
    return start;
}

static bool function_is_error_state_query(const struct p101_env *env, CXCursor cursor)
{
    bool matches;

    matches = function_has_semantic_role(env, cursor, "p101:error-state-query");
    if(!matches)
    {
        matches = function_has_semantic_role(env, cursor, "p101:error-state-query:positive");
    }
    if(!matches)
    {
        matches = function_has_semantic_role(env, cursor, "p101:error-state-query:negative");
    }
    return matches;
}

struct semantic_role_lookup
{
    const struct p101_env *env;
    const char            *role;
    char                  *name;
    size_t                 name_size;
    char                   matched_usr[ANALYSIS_IDENTITY_SIZE];
    size_t                 matches;
};

static enum CXChildVisitResult find_semantic_role_function(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct semantic_role_lookup *lookup;
    enum CXCursorKind            kind;
    bool                         is_function;
    bool                         has_role;

    lookup      = (struct semantic_role_lookup *)client_data;
    kind        = clang_getCursorKind(cursor);
    is_function = cursor_kind_is_function(kind);
    has_role    = false;
    if(is_function)
    {
        has_role = function_has_semantic_role(lookup->env, cursor, lookup->role);
    }
    if(is_function && has_role)
    {
        CXString    spelling;
        CXString    usr_value;
        const char *name;
        const char *usr;
        int         comparison;

        spelling   = clang_getCursorSpelling(cursor);
        usr_value  = clang_getCursorUSR(cursor);
        name       = clang_getCString(spelling);
        usr        = clang_getCString(usr_value);
        comparison = 1;
        if(usr != NULL && usr[0] != '\0' && lookup->matched_usr[0] != '\0')
        {
            comparison = p101_strcmp(lookup->env, lookup->matched_usr, usr);
        }
        if(usr != NULL && usr[0] != '\0' && (lookup->matched_usr[0] == '\0' || comparison != 0))
        {
            lookup->matches++;
            if(lookup->matches == 1U && name != NULL)
            {
                p101_snprintf(lookup->env, P101_ERROR_OPTIONAL, lookup->name, lookup->name_size, "%s", name);
                p101_snprintf(lookup->env, P101_ERROR_OPTIONAL, lookup->matched_usr, sizeof(lookup->matched_usr), "%s", usr);
            }
        }
        clang_disposeString(usr_value);
        clang_disposeString(spelling);
    }
    (void)parent;
    return CXChildVisit_Recurse;
}

static bool semantic_role_function_name(const struct p101_env *env, CXTranslationUnit translation_unit, const char *role, char *name, size_t name_size)
{
    struct semantic_role_lookup lookup;
    CXCursor                    root;

    lookup.env            = env;
    lookup.role           = role;
    lookup.name           = name;
    lookup.name_size      = name_size;
    lookup.matched_usr[0] = '\0';
    lookup.matches        = 0U;
    name[0]               = '\0';
    root                  = clang_getTranslationUnitCursor(translation_unit);
    clang_visitChildren(root, find_semantic_role_function, &lookup);
    return (lookup.matches == 1U && name[0] != '\0') != 0;
}

struct argument_identity_context
{
    const struct p101_env *env;
    struct p101_error     *err;
    char                  *text;
    size_t                 text_size;
    size_t                 length;
    bool                   found;
};

static enum CXChildVisitResult collect_argument_identity(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    enum CXChildVisitResult           result;
    struct argument_identity_context *context;
    CXCursor                          referenced;
    enum CXCursorKind                 referenced_kind;
    enum CXCursorKind                 kind;
    int                               is_null;

    context         = (struct argument_identity_context *)client_data;
    result          = CXChildVisit_Recurse;
    referenced      = clang_getCursorReferenced(cursor);
    referenced_kind = clang_getCursorKind(referenced);
    kind            = clang_getCursorKind(cursor);
    is_null         = clang_Cursor_isNull(referenced);
    if((kind == CXCursor_DeclRefExpr || kind == CXCursor_MemberRefExpr) && is_null == 0 && (referenced_kind == CXCursor_ParmDecl || referenced_kind == CXCursor_VarDecl || referenced_kind == CXCursor_FieldDecl))
    {
        CXString    usr_value;
        const char *usr;

        usr_value = clang_getCursorUSR(referenced);
        usr       = clang_getCString(usr_value);
        if(usr != NULL && usr[0] != '\0')
        {
            int written;

            written = p101_snprintf(context->env, context->err, context->text + context->length, context->text_size - context->length, "%u:%s;", (unsigned)referenced_kind, usr);
            if(written < 0 || (size_t)written >= context->text_size - context->length)
            {
                context->text[0] = '\0';
                context->length  = 0U;
                result           = CXChildVisit_Break;
            }
            else
            {
                context->length += (size_t)written;
                context->found = true;
            }
        }
        clang_disposeString(usr_value);
    }
    (void)parent;
    return result;
}

static char *cursor_argument_identity(const struct p101_env *env, struct p101_error *err, CXCursor cursor, unsigned index)
{
    char                            *identity;
    CXCursor                         argument;
    char                             text[ANALYSIS_IDENTITY_SIZE];
    struct argument_identity_context context;
    int                              argument_count;
    enum CXChildVisitResult          visit_result;
    bool                             no_error;

    identity       = NULL;
    argument_count = clang_Cursor_getNumArguments(cursor);
    if(index >= (unsigned)argument_count)
    {
        goto done;
    }
    argument = clang_Cursor_getArgument(cursor, index);
    p101_memset(env, &context, 0, sizeof(context));
    context.env       = env;
    context.err       = err;
    context.text      = text;
    context.text_size = sizeof(text);
    text[0]           = '\0';
    {
        CXCursor visitor_cursor;
        CXCursor visitor_parent;

        visitor_cursor = argument;
        visitor_parent = clang_getNullCursor();
        visit_result   = collect_argument_identity(visitor_cursor, visitor_parent, &context);
    }
    if(visit_result == CXChildVisit_Recurse)
    {
        clang_visitChildren(argument, collect_argument_identity, &context);
    }
    no_error = p101_error_has_no_error(err);
    if(context.found && text[0] != '\0' && no_error)
    {
        identity = copy_text(env, err, text);
    }

done:
    return identity;
}

static char *call_operation_identity(const struct p101_env *env, struct p101_error *err, CXCursor call, CXCursor function)
{
    char *identity;
    int   argument_count;
    int   env_index;
    int   error_index;

    identity       = NULL;
    argument_count = clang_Cursor_getNumArguments(call);
    env_index      = function_parameter_index(env, function, P101_ENV_TYPE_USR);
    error_index    = function_parameter_index(env, function, P101_ERROR_TYPE_USR);
    for(int index = 0; index < argument_count; index++)
    {
        if(index == env_index || index == error_index)
        {
            continue;
        }
        identity = cursor_argument_identity(env, err, call, (unsigned)index);
        if(identity != NULL)
        {
            break;
        }
    }
    return identity;
}

static char *call_path_identity(const struct p101_env *env, struct p101_error *err, CXCursor call, CXCursor function)
{
    char *identity;
    int   argument_count;
    int   env_index;
    int   error_index;

    identity       = NULL;
    argument_count = clang_Cursor_getNumArguments(call);
    env_index      = function_parameter_index(env, function, P101_ENV_TYPE_USR);
    error_index    = function_parameter_index(env, function, P101_ERROR_TYPE_USR);
    for(int index = 0; index < argument_count; index++)
    {
        CXCursor argument;
        CXType   raw_type;
        CXType   type;
        CXType   raw_pointee;
        CXType   pointee;

        if(index == env_index || index == error_index)
        {
            continue;
        }
        argument = clang_Cursor_getArgument(call, (unsigned)index);
        raw_type = clang_getCursorType(argument);
        type     = clang_getCanonicalType(raw_type);
        if(type.kind != CXType_Pointer)
        {
            continue;
        }
        raw_pointee = clang_getPointeeType(type);
        pointee     = clang_getCanonicalType(raw_pointee);
        if(pointee.kind != CXType_Char_S && pointee.kind != CXType_Char_U && pointee.kind != CXType_SChar && pointee.kind != CXType_UChar)
        {
            continue;
        }
        identity = cursor_argument_identity(env, err, call, (unsigned)index);
        if(identity != NULL)
        {
            break;
        }
    }
    return identity;
}

static bool declaration_identity(const struct p101_env *env, struct p101_error *err, CXCursor declaration, char *identity, size_t identity_size)
{
    enum CXCursorKind kind;
    CXString          usr_value;
    const char       *usr;
    int               written;
    bool              found;

    kind      = clang_getCursorKind(declaration);
    usr_value = clang_getCursorUSR(declaration);
    usr       = clang_getCString(usr_value);
    found     = usr != NULL && usr[0] != '\0';
    if(found)
    {
        written = p101_snprintf(env, err, identity, identity_size, "%u:%s;", (unsigned)kind, usr);
        found   = written >= 0 && (size_t)written < identity_size;
    }
    clang_disposeString(usr_value);
    return found;
}

static bool expression_identity(struct scan_context *context, CXCursor expression, char *identity, size_t identity_size)
{
    struct argument_identity_context identity_context;
    enum CXChildVisitResult          visit_result;
    bool                             found;

    p101_memset(context->env, &identity_context, 0, sizeof(identity_context));
    identity_context.env       = context->env;
    identity_context.err       = context->err;
    identity_context.text      = identity;
    identity_context.text_size = identity_size;
    identity[0]                = '\0';
    visit_result               = collect_argument_identity(expression, clang_getNullCursor(), &identity_context);
    if(visit_result == CXChildVisit_Recurse)
    {
        clang_visitChildren(expression, collect_argument_identity, &identity_context);
    }
    found = identity_context.found && identity[0] != '\0';
    return found;
}

static bool call_result_identity(struct scan_context *context, CXCursor parent, char *identity, size_t identity_size)
{
    const struct cursor_ancestry *ancestor;
    enum CXCursorKind             kind;
    bool                          found;

    ancestor = context->ancestry;
    kind     = clang_getCursorKind(parent);
    found    = false;
    while(kind == CXCursor_UnexposedExpr || kind == CXCursor_CStyleCastExpr)
    {
        if(ancestor == NULL)
        {
            break;
        }
        parent   = ancestor->cursor;
        ancestor = ancestor->parent;
        kind     = clang_getCursorKind(parent);
    }
    if(kind == CXCursor_VarDecl)
    {
        found = declaration_identity(context->env, context->err, parent, identity, identity_size);
    }
    else if(kind == CXCursor_BinaryOperator && binary_parent_is_simple_assignment(parent))
    {
        struct binary_operands operands;

        operands.count = 0U;
        operands.left  = clang_getNullCursor();
        operands.right = clang_getNullCursor();
        clang_visitChildren(parent, capture_binary_operands, &operands);
        if(operands.count == 2U)
        {
            found = expression_identity(context, operands.left, identity, identity_size);
        }
    }
    return found;
}

static bool result_use_requires_checked_error(struct scan_context *context, CXCursor cursor)
{
    const struct cursor_ancestry *ancestor;
    bool                          consumed;

    (void)cursor;
    ancestor = context->ancestry;
    consumed = false;
    while(ancestor != NULL)
    {
        enum CXCursorKind kind;

        kind = clang_getCursorKind(ancestor->cursor);
        if(kind == CXCursor_CallExpr || kind == CXCursor_ReturnStmt)
        {
            consumed = true;
            break;
        }
        if(kind == CXCursor_IfStmt || kind == CXCursor_SwitchStmt || kind == CXCursor_WhileStmt || kind == CXCursor_DoStmt || kind == CXCursor_ForStmt || kind == CXCursor_ConditionalOperator || kind == CXCursor_CompoundStmt)
        {
            break;
        }
        ancestor = ancestor->parent;
    }
    return consumed;
}

static bool call_has_role_or_usr(const struct p101_env *env, CXCursor function, const char *role, const char *const identities[], size_t identity_count)
{
    bool        found;
    CXString    usr_value;
    const char *usr;

    found = function_has_semantic_role(env, function, role);
    if(found)
    {
        return true;
    }
    usr_value = clang_getCursorUSR(function);
    usr       = clang_getCString(usr_value);
    for(size_t index = 0U; usr != NULL && index < identity_count && !found; index++)
    {
        int comparison;

        comparison = p101_strcmp(env, usr, identities[index]);
        found      = comparison == 0;
    }
    clang_disposeString(usr_value);
    return found;
}

static bool cursor_integer_value(CXCursor cursor, int64_t *value)
{
    CXEvalResult     evaluation;
    CXEvalResultKind kind;
    bool             found;

    evaluation = clang_Cursor_Evaluate(cursor);
    found      = false;
    if(evaluation != NULL)
    {
        kind = clang_EvalResult_getKind(evaluation);
        if(kind == CXEval_Int)
        {
            *value = clang_EvalResult_getAsLongLong(evaluation);
            found  = true;
        }
        clang_EvalResult_dispose(evaluation);
    }
    return found;
}

struct automatic_storage_probe
{
    bool found;
};

static enum CXChildVisitResult probe_automatic_storage(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct automatic_storage_probe *probe;
    enum CXCursorKind               kind;

    (void)parent;
    probe = (struct automatic_storage_probe *)client_data;
    kind  = clang_getCursorKind(cursor);
    if(kind == CXCursor_DeclRefExpr)
    {
        CXCursor          declaration;
        enum CXCursorKind declaration_kind;

        declaration      = clang_getCursorReferenced(cursor);
        declaration_kind = clang_getCursorKind(declaration);
        if(declaration_kind == CXCursor_ParmDecl)
        {
            probe->found = true;
            return CXChildVisit_Break;
        }
        if(declaration_kind == CXCursor_VarDecl)
        {
            CXCursor             semantic_parent;
            enum CXCursorKind    parent_kind;
            enum CX_StorageClass storage;

            semantic_parent = clang_getCursorSemanticParent(declaration);
            parent_kind     = clang_getCursorKind(semantic_parent);
            storage         = clang_Cursor_getStorageClass(declaration);
            if(cursor_kind_is_function(parent_kind) && storage != CX_SC_Static)
            {
                probe->found = true;
                return CXChildVisit_Break;
            }
        }
    }
    return CXChildVisit_Recurse;
}

static bool argument_references_automatic_storage(CXCursor argument)
{
    struct automatic_storage_probe probe;
    enum CXChildVisitResult        result;

    probe.found = false;
    result      = probe_automatic_storage(argument, clang_getNullCursor(), &probe);
    if(result == CXChildVisit_Recurse)
    {
        clang_visitChildren(argument, probe_automatic_storage, &probe);
    }
    return probe.found;
}

static bool cursor_is_signal_safe_shared_object(const struct p101_env *env, CXCursor cursor)
{
    CXType      type;
    CXType      canonical;
    CXType      element;
    CXCursor    declaration;
    CXString    usr_value;
    const char *usr;
    bool        safe;
    unsigned    volatile_qualified;

    type      = clang_getCursorType(cursor);
    canonical = clang_getCanonicalType(type);
    /*
     * POSIX admits non-modifiable objects and lock-free atomics.  Const is
     * visible in the target AST.  Lock freedom is not a property of the C
     * type alone, so atomic objects need an explicit target-reviewed role.
     */
    safe    = clang_isConstQualifiedType(type) != 0U;
    element = clang_getArrayElementType(type);
    if(!safe && element.kind != CXType_Invalid)
    {
        safe = clang_isConstQualifiedType(element) != 0U;
    }
    if(!safe && canonical.kind == CXType_Atomic)
    {
        safe = function_has_semantic_role(env, cursor, "p101:signal:lock-free-atomic");
    }
    volatile_qualified = clang_isVolatileQualifiedType(type);
    declaration        = clang_getTypeDeclaration(type);
    usr_value          = clang_getCursorUSR(declaration);
    usr                = clang_getCString(usr_value);
    if(!safe && volatile_qualified != 0U && usr != NULL)
    {
        int comparison;

        comparison = p101_strcmp(env, usr, "c:@T@sig_atomic_t");
        safe       = comparison == 0;
    }
    clang_disposeString(usr_value);
    return safe;
}

static bool cursor_references_shared_object(CXCursor cursor, CXCursor *declaration)
{
    enum CXCursorKind kind;
    bool              shared;

    shared       = false;
    *declaration = clang_getNullCursor();
    kind         = clang_getCursorKind(cursor);
    if(kind == CXCursor_DeclRefExpr)
    {
        enum CXCursorKind declaration_kind;

        *declaration     = clang_getCursorReferenced(cursor);
        declaration_kind = clang_getCursorKind(*declaration);
        if(declaration_kind == CXCursor_VarDecl)
        {
            CXCursor             semantic_parent;
            enum CXCursorKind    parent_kind;
            enum CX_StorageClass storage;

            semantic_parent = clang_getCursorSemanticParent(*declaration);
            parent_kind     = clang_getCursorKind(semantic_parent);
            storage         = clang_Cursor_getStorageClass(*declaration);
            shared          = !cursor_kind_is_function(parent_kind) || storage == CX_SC_Static;
        }
    }
    return shared;
}

static bool identity_is_environment_borrow(const struct scan_context *context, const char *identity, size_t offset)
{
    bool found;

    found = false;
    for(size_t index = 0U; index < context->environment_borrow_count && !found; index++)
    {
        int comparison;

        comparison = p101_strcmp(context->env, context->environment_borrows[index].identity, identity);
        found      = comparison == 0 && context->environment_borrows[index].invalidated && offset > context->environment_borrows[index].invalidated_after;
    }
    return found;
}

static void observe_semantic_reference(struct scan_context *context, CXCursor cursor, const char *path, size_t line, size_t column, size_t start, size_t end, bool is_header)
{
    CXCursor declaration;
    bool     shared;

    shared = cursor_references_shared_object(cursor, &declaration);
    if(shared)
    {
        bool signal_safe;

        signal_safe = cursor_is_signal_safe_shared_object(context->env, declaration);
        if(!signal_safe)
        {
            emit_note(context, path, line, column, start, end, is_header, "SIGNAL_SHARED_OBJECT_ACCESS");
        }
    }
    if(clang_getCursorKind(cursor) == CXCursor_DeclRefExpr)
    {
        char identity[ANALYSIS_IDENTITY_SIZE];
        bool has_identity;

        has_identity = declaration_identity(context->env, context->err, clang_getCursorReferenced(cursor), identity, sizeof(identity));
        if(has_identity && identity_is_environment_borrow(context, identity, start))
        {
            emit_note(context, path, line, column, start, end, is_header, "ENV_BORROWED_POINTER_INVALIDATED");
        }
    }
}

static void remember_environment_borrow(struct scan_context *context, CXCursor parent)
{
    char identity[ANALYSIS_IDENTITY_SIZE];
    bool found;

    found = call_result_identity(context, parent, identity, sizeof(identity));
    if(found)
    {
        size_t index;

        index = context->environment_borrow_count;
        for(size_t item = 0U; item < context->environment_borrow_count; item++)
        {
            int comparison;

            comparison = p101_strcmp(context->env, context->environment_borrows[item].identity, identity);
            if(comparison == 0)
            {
                index = item;
                break;
            }
        }
        if(index == context->environment_borrow_count && index < SEMANTIC_IDENTITY_CAPACITY)
        {
            context->environment_borrow_count++;
        }
        if(index < SEMANTIC_IDENTITY_CAPACITY)
        {
            int operation_status;

            operation_status = p101_snprintf(context->env, context->err, context->environment_borrows[index].identity, sizeof(context->environment_borrows[index].identity), "%s", identity);
            (void)operation_status;
            context->environment_borrows[index].invalidated       = false;
            context->environment_borrows[index].invalidated_after = 0U;
        }
    }
}

static void invalidate_environment_borrows(struct scan_context *context, size_t end)
{
    for(size_t index = 0U; index < context->environment_borrow_count; index++)
    {
        context->environment_borrows[index].invalidated       = true;
        context->environment_borrows[index].invalidated_after = end;
    }
}

static void emit_secure_semantic_call_notes(struct scan_context *context, CXCursor cursor, CXCursor parent, CXCursor referenced, const struct p101_c_analysis_record *record, const char *path, size_t line, size_t column)
{
    static const char *const allocators[]               = {"c:@F@malloc", "c:@F@calloc", "c:@F@realloc", "c:@F@aligned_alloc", "c:@F@reallocarray"};
    static const char *const product_allocators[]       = {"c:@F@calloc", "c:@F@reallocarray"};
    static const char *const restricted_copies[]        = {"c:@F@memcpy", "c:@F@strcpy", "c:@F@strncpy", "c:@F@strcat", "c:@F@strncat"};
    static const char *const thread_creators[]          = {"c:@F@pthread_create", "c:@F@thrd_create"};
    static const char *const environment_getters[]      = {"c:@F@getenv", "c:@F@localeconv", "c:@F@setlocale", "c:@F@strerror"};
    static const char *const environment_invalidators[] = {"c:@F@setenv", "c:@F@unsetenv", "c:@F@putenv", "c:@F@clearenv", "c:@F@localeconv", "c:@F@setlocale", "c:@F@strerror"};
    static const char *const path_checks[]              = {"c:@F@access", "c:@F@faccessat", "c:@F@stat", "c:@F@lstat"};
    static const char *const path_uses[]                = {"c:@F@open", "c:@F@openat", "c:@F@fopen", "c:@F@unlink", "c:@F@rename", "c:@F@chmod", "c:@F@chown", "c:@F@truncate"};
    int                      argument_count;
    bool                     classification;

    argument_count = clang_Cursor_getNumArguments(cursor);
    classification = call_has_role_or_usr(context->env, referenced, "p101:allocation", allocators, sizeof(allocators) / sizeof(allocators[0]));
    if(classification && argument_count > 0)
    {
        bool product_size;
        bool zero_size;
        int  first_size_index;

        product_size     = call_has_role_or_usr(context->env, referenced, "p101:allocation:product-size", product_allocators, sizeof(product_allocators) / sizeof(product_allocators[0]));
        first_size_index = argument_count - 1;
        if(product_size && argument_count >= 2)
        {
            first_size_index = argument_count - 2;
        }
        zero_size = false;
        for(int index = first_size_index; index < argument_count; index++)
        {
            CXCursor size_argument;
            int64_t  value;
            bool     known;

            size_argument = clang_Cursor_getArgument(cursor, (unsigned)index);
            known         = cursor_integer_value(size_argument, &value);
            if(known && value == 0)
            {
                zero_size = true;
            }
        }
        if(zero_size)
        {
            emit_note(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "ZERO_SIZE_ALLOCATION");
        }
    }
    classification = call_has_role_or_usr(context->env, referenced, "p101:memory:restricted-copy", restricted_copies, sizeof(restricted_copies) / sizeof(restricted_copies[0]));
    if(classification && argument_count >= 3)
    {
        char    *destination;
        char    *source;
        CXCursor size_argument;
        int64_t  size_value;
        bool     size_known;

        destination   = cursor_argument_identity(context->env, context->err, cursor, (unsigned)(argument_count - 3));
        source        = cursor_argument_identity(context->env, context->err, cursor, (unsigned)(argument_count - 2));
        size_argument = clang_Cursor_getArgument(cursor, (unsigned)(argument_count - 1));
        size_known    = cursor_integer_value(size_argument, &size_value);
        int same_identity;

        same_identity = 0;
        if(destination != NULL && source != NULL)
        {
            same_identity = p101_strcmp(context->env, destination, source) == 0;
        }
        if(same_identity != 0 && (!size_known || size_value > 0))
        {
            emit_note(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "OVERLAPPING_RESTRICTED_COPY");
        }
        p101_free(context->env, source);
        p101_free(context->env, destination);
    }
    classification = call_has_role_or_usr(context->env, referenced, "p101:thread:create", thread_creators, sizeof(thread_creators) / sizeof(thread_creators[0]));
    if(classification && argument_count > 0)
    {
        CXCursor argument;
        bool     automatic;

        argument  = clang_Cursor_getArgument(cursor, (unsigned)(argument_count - 1));
        automatic = argument_references_automatic_storage(argument);
        if(automatic)
        {
            emit_note(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "THREAD_AUTOMATIC_STORAGE_ESCAPE");
        }
    }
    classification = call_has_role_or_usr(context->env, referenced, "p101:environment:invalidates-borrowed", environment_invalidators, sizeof(environment_invalidators) / sizeof(environment_invalidators[0]));
    if(classification)
    {
        invalidate_environment_borrows(context, record->end_offset);
    }
    classification = call_has_role_or_usr(context->env, referenced, "p101:environment:borrowed-result", environment_getters, sizeof(environment_getters) / sizeof(environment_getters[0]));
    if(classification)
    {
        remember_environment_borrow(context, parent);
    }
    classification = call_has_role_or_usr(context->env, referenced, "p101:filesystem:path-check", path_checks, sizeof(path_checks) / sizeof(path_checks[0]));
    if(classification)
    {
        char *identity;

        identity = call_path_identity(context->env, context->err, cursor, referenced);
        if(identity != NULL)
        {
            int operation_status;

            operation_status = p101_snprintf(context->env, context->err, context->checked_path_identity, sizeof(context->checked_path_identity), "%s", identity);
            (void)operation_status;
        }
        p101_free(context->env, identity);
    }
    classification = call_has_role_or_usr(context->env, referenced, "p101:filesystem:path-use", path_uses, sizeof(path_uses) / sizeof(path_uses[0]));
    if(classification && context->checked_path_identity[0] != '\0')
    {
        char *identity;

        identity = call_path_identity(context->env, context->err, cursor, referenced);
        int comparison;

        comparison = 1;
        if(identity != NULL)
        {
            comparison = p101_strcmp(context->env, identity, context->checked_path_identity);
        }
        if(comparison == 0)
        {
            emit_note(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "PATH_TOCTOU");
        }
        p101_free(context->env, identity);
    }
    if(record->usr != NULL && context->current_function_usr != NULL && !context->current_recursion_bounded)
    {
        int comparison;

        comparison = p101_strcmp(context->env, record->usr, context->current_function_usr);
        if(comparison == 0)
        {
            emit_note(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "RECURSIVE_CALL");
        }
    }
}

static bool call_discards_error(CXCursor cursor, unsigned argument_index)
{
    bool     discarded;
    int      argument_count;
    CXCursor argument;

    discarded      = false;
    argument_count = clang_Cursor_getNumArguments(cursor);
    if(argument_index >= (unsigned)argument_count)
    {
        goto done;
    }
    argument  = clang_Cursor_getArgument(cursor, argument_index);
    discarded = cursor_is_null_pointer_constant(argument);
    if(discarded)
    {
        goto done;
    }

done:
    return discarded;
}

struct null_pointer_child
{
    CXCursor cursor;
    size_t   count;
};

static enum CXChildVisitResult capture_null_pointer_child(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct null_pointer_child *child;
    enum CXCursorKind          kind;
    unsigned                   is_expression;

    child         = (struct null_pointer_child *)client_data;
    kind          = clang_getCursorKind(cursor);
    is_expression = clang_isExpression(kind);
    if(is_expression == 0U)
    {
        goto done;
    }
    if(child->count == 0U)
    {
        child->cursor = cursor;
    }
    child->count++;

done:
    (void)parent;
    return CXChildVisit_Continue;
}

static bool cursor_is_null_pointer_constant(CXCursor cursor)
{
    bool is_null;

    is_null = false;
    for(size_t depth = 0U; depth < NULL_POINTER_CAST_DEPTH; depth++)
    {
        enum CXCursorKind         kind;
        CXEvalResult              evaluation;
        struct null_pointer_child child;

        kind = clang_getCursorKind(cursor);
        if(kind == CXCursor_CXXNullPtrLiteralExpr || kind == CXCursor_GNUNullExpr)
        {
            is_null = true;
            goto done;
        }
        evaluation = clang_Cursor_Evaluate(cursor);
        if(evaluation != NULL)
        {
            CXEvalResultKind evaluation_kind;

            evaluation_kind = clang_EvalResult_getKind(evaluation);
            if(evaluation_kind == CXEval_Int)
            {
                long long evaluation_value;

                evaluation_value = clang_EvalResult_getAsLongLong(evaluation);
                if(evaluation_value == 0)
                {
                    is_null = true;
                }
            }
            clang_EvalResult_dispose(evaluation);
        }
        if(is_null)
        {
            goto done;
        }
        if(kind != CXCursor_UnexposedExpr && kind != CXCursor_ParenExpr && kind != CXCursor_CStyleCastExpr)
        {
            goto done;
        }
        child.cursor = clang_getNullCursor();
        child.count  = 0U;
        clang_visitChildren(cursor, capture_null_pointer_child, &child);
        if(child.count != 1U)
        {
            goto done;
        }
        cursor = child.cursor;
    }

done:
    return is_null;
}

struct cursor_probe
{
    CXCursor cursor;
    bool     found;
};

static enum CXChildVisitResult capture_first_cursor(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct cursor_probe *probe;

    (void)parent;
    probe         = (struct cursor_probe *)client_data;
    probe->cursor = cursor;
    probe->found  = true;
    return CXChildVisit_Break;
}

static enum CXChildVisitResult find_referenced_callee(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct cursor_probe    *probe;
    enum CXChildVisitResult result;
    enum CXCursorKind       kind;

    (void)parent;
    probe  = (struct cursor_probe *)client_data;
    result = CXChildVisit_Recurse;
    kind   = clang_getCursorKind(cursor);
    if(kind == CXCursor_DeclRefExpr || kind == CXCursor_MemberRefExpr)
    {
        CXCursor referenced;
        int      is_null;

        referenced = clang_getCursorReferenced(cursor);
        is_null    = clang_Cursor_isNull(referenced);
        if(is_null == 0)
        {
            probe->cursor = referenced;
            probe->found  = true;
            result        = CXChildVisit_Break;
        }
    }
    return result;
}

static CXCursor call_referenced_cursor(CXCursor cursor)
{
    CXCursor            referenced;
    int                 is_null;
    struct cursor_probe callee;

    referenced = clang_getCursorReferenced(cursor);
    is_null    = clang_Cursor_isNull(referenced);
    if(is_null != 0)
    {
        callee.cursor = clang_getNullCursor();
        callee.found  = false;
        clang_visitChildren(cursor, capture_first_cursor, &callee);
        if(callee.found)
        {
            struct cursor_probe declaration;

            declaration.cursor = clang_getNullCursor();
            declaration.found  = false;
            clang_visitChildren(callee.cursor, find_referenced_callee, &declaration);
            if(declaration.found)
            {
                referenced = declaration.cursor;
            }
        }
    }
    return referenced;
}

struct optional_error_context
{
    const struct p101_env *env;
    bool                   found;
};

static enum CXChildVisitResult find_optional_error_reference(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct optional_error_context *context;
    enum CXChildVisitResult        result;
    enum CXCursorKind              kind;

    context = (struct optional_error_context *)client_data;
    result  = CXChildVisit_Recurse;
    kind    = clang_getCursorKind(cursor);
    if(kind == CXCursor_CallExpr || kind == CXCursor_DeclRefExpr)
    {
        CXCursor referenced;
        int      is_null;
        bool     has_role;

        referenced = clang_getCursorReferenced(cursor);
        is_null    = clang_Cursor_isNull(referenced);
        has_role   = false;
        if(is_null == 0)
        {
            has_role = function_has_semantic_role(context->env, referenced, "p101:optional-error");
        }
        if(is_null == 0 && has_role)
        {
            context->found = true;
            result         = CXChildVisit_Break;
        }
    }
    (void)parent;
    return result;
}

static bool call_uses_optional_error(const struct p101_env *env, CXCursor cursor, unsigned argument_index)
{
    struct optional_error_context context;
    CXCursor                      argument;
    int                           argument_count;
    CXCursor                      visitor_cursor;
    CXCursor                      visitor_parent;
    enum CXChildVisitResult       visit_result;

    context.env    = env;
    context.found  = false;
    argument_count = clang_Cursor_getNumArguments(cursor);
    if(argument_index >= (unsigned)argument_count)
    {
        goto done;
    }
    argument       = clang_Cursor_getArgument(cursor, argument_index);
    visitor_cursor = argument;
    visitor_parent = clang_getNullCursor();
    visit_result   = find_optional_error_reference(visitor_cursor, visitor_parent, &context);
    (void)visit_result;
    if(!context.found)
    {
        clang_visitChildren(argument, find_optional_error_reference, &context);
    }

done:
    return context.found;
}

static void emit_note(struct scan_context *context, const char *path, size_t line, size_t column, size_t start, size_t end, bool is_header, const char *name)
{
    emit_note_as(context, path, line, column, start, end, is_header, name, context->current_function, context->current_function_usr);
}

static void emit_note_as(struct scan_context *context, const char *path, size_t line, size_t column, size_t start, size_t end, bool is_header, const char *name, const char *caller, const char *caller_usr)
{
    struct p101_c_analysis_record record;
    bool                          emitted;

    p101_memset(context->env, &record, 0, sizeof(record));
    record.kind         = P101_C_ANALYSIS_NOTE;
    record.path         = path;
    record.line         = line;
    record.column       = column;
    record.start_offset = start;
    record.end_offset   = end;
    record.name         = name;
    record.caller       = caller;
    record.caller_usr   = caller_usr;
    record.is_header    = is_header;
    emitted             = emit_record(context, &record);
    (void)emitted;
}

static void cursor_extent_offsets(CXCursor cursor, size_t *start, size_t *end)
{
    CXSourceRange    range;
    unsigned         start_offset;
    unsigned         end_offset;
    CXSourceLocation location;

    range    = clang_getCursorExtent(cursor);
    location = clang_getRangeStart(range);
    clang_getExpansionLocation(location, NULL, NULL, NULL, &start_offset);
    location = clang_getRangeEnd(range);
    clang_getExpansionLocation(location, NULL, NULL, NULL, &end_offset);
    *start = start_offset;
    *end   = end_offset;
}

static bool call_is_generated_by_macro(CXCursor cursor)
{
    CXSourceLocation location;
    CXFile           spelling_file;
    CXFile           expansion_file;
    unsigned         spelling_offset;
    unsigned         expansion_offset;
    bool             generated;
    int              files_equal;

    location         = clang_getCursorLocation(cursor);
    spelling_file    = NULL;
    expansion_file   = NULL;
    spelling_offset  = 0U;
    expansion_offset = 0U;
    generated        = false;
    clang_getSpellingLocation(location, &spelling_file, NULL, NULL, &spelling_offset);
    clang_getExpansionLocation(location, &expansion_file, NULL, NULL, &expansion_offset);
    files_equal = 1;
    if(spelling_file != NULL && expansion_file != NULL)
    {
        files_equal = clang_File_isEqual(spelling_file, expansion_file);
    }
    if(spelling_file != NULL && expansion_file != NULL && (files_equal == 0 || spelling_offset != expansion_offset))
    {
        generated = true;
    }
    return generated;
}

/*
 * A call cursor created from a function-like macro can inherit the expansion
 * location for both its spelling and expansion locations.  In that case the
 * location comparison above cannot establish the cursor's provenance.  Ask
 * the translation unit which source construct owns the written range: a macro
 * expansion means the call is compiler-produced implementation detail, not a
 * call expression written by the student.
 */
static bool call_is_covered_by_macro_expansion(const struct scan_context *context, CXCursor cursor)
{
    CXSourceRange    range;
    CXSourceLocation location;
    CXFile           file;
    unsigned         start;
    unsigned         end;
    bool             covered;

    range    = clang_getCursorExtent(cursor);
    location = clang_getRangeStart(range);
    file     = NULL;
    start    = 0U;
    end      = 0U;
    clang_getExpansionLocation(location, &file, NULL, NULL, &start);
    location = clang_getRangeEnd(range);
    clang_getExpansionLocation(location, NULL, NULL, NULL, &end);
    covered = false;
    for(size_t index = 0U; index < context->macro_expansion_count; index++)
    {
        const struct macro_expansion_range *expansion;
        int                                 same_file;

        expansion = &context->macro_expansions[index];
        same_file = 0;
        if(file != NULL && expansion->file != NULL)
        {
            same_file = clang_File_isEqual(file, expansion->file);
        }
        if(same_file != 0 && start == expansion->start && end == expansion->end)
        {
            covered = true;
            break;
        }
    }
    return covered;
}

static enum CXChildVisitResult collect_macro_expansion(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct scan_context    *context;
    enum CXCursorKind       kind;
    enum CXChildVisitResult result;

    context = (struct scan_context *)client_data;
    kind    = clang_getCursorKind(cursor);
    if(kind == CXCursor_MacroExpansion)
    {
        CXSourceRange    source_range;
        CXSourceLocation source_start;
        int              in_system_header;

        source_range     = clang_getCursorExtent(cursor);
        source_start     = clang_getRangeStart(source_range);
        in_system_header = clang_Location_isInSystemHeader(source_start);
        if(in_system_header == 0 && context->macro_expansion_count == context->macro_expansion_capacity)
        {
            size_t                        capacity;
            struct macro_expansion_range *resized;

            capacity = context->macro_expansion_capacity == 0U ? ANALYSIS_INITIAL_MACRO_CAPACITY : context->macro_expansion_capacity * 2U;
            if(capacity < context->macro_expansion_capacity || capacity > SIZE_MAX / sizeof(*resized))
            {
                P101_ERROR_RAISE_USER(context->err, "Too many macro expansions in the translation unit.", EOVERFLOW);
                context->stopped = true;
            }
            else
            {
                size_t bytes;
                void  *allocation;

                bytes      = capacity * sizeof(*resized);
                allocation = p101_realloc(context->env, context->err, context->macro_expansions, bytes);
                resized    = (struct macro_expansion_range *)allocation;
                if(resized == NULL)
                {
                    context->stopped = true;
                }
                else
                {
                    context->macro_expansions         = resized;
                    context->macro_expansion_capacity = capacity;
                }
            }
        }
        if(in_system_header == 0 && !context->stopped)
        {
            struct macro_expansion_range *expansion;
            CXSourceRange                 range;
            CXSourceLocation              location;

            expansion        = &context->macro_expansions[context->macro_expansion_count++];
            range            = clang_getCursorExtent(cursor);
            location         = clang_getRangeStart(range);
            expansion->file  = NULL;
            expansion->start = 0U;
            expansion->end   = 0U;
            clang_getExpansionLocation(location, &expansion->file, NULL, NULL, &expansion->start);
            location = clang_getRangeEnd(range);
            clang_getExpansionLocation(location, NULL, NULL, NULL, &expansion->end);
        }
    }
    (void)parent;
    result = CXChildVisit_Continue;
    if(context->stopped)
    {
        result = CXChildVisit_Break;
    }
    return result;
}

/*
 * Some platform headers expose an object-like macro whose expansion contains
 * a call (notably errno).  libclang does not consistently report distinct
 * spelling and expansion locations for that hidden call on every platform.
 * The isolation contract governs calls present in the editable source, so a
 * call extent with no written invocation parenthesis is macro-generated even
 * when the location API cannot prove it.
 */
static bool call_has_written_invocation(struct scan_context *context, const char *path, size_t start, size_t end)
{
    char       *source_text;
    const char *opening_parenthesis;
    bool        written;

    source_text = source_range_text(context->env, context->err, context->translation_unit, path, start, end);
    written     = true;
    if(source_text != NULL)
    {
        opening_parenthesis = p101_strchr(context->env, source_text, '(');
        written             = opening_parenthesis != NULL;
    }
    p101_free(context->env, source_text);
    return written;
}

/*
 * The caller has already established that the parent cursor is a
 * BinaryOperator. Ask libclang for the operator itself instead of scanning
 * tokens: a token scan cannot tell "a = helper(b)" from
 * "(a = helper(b)) == helper(c)", where the parent operator is "==".
 */
static bool binary_parent_is_simple_assignment(CXCursor parent)
{
    enum CXBinaryOperatorKind operator_kind;
    bool                      assignment;

    operator_kind = clang_getCursorBinaryOperatorKind(parent);
    assignment    = operator_kind == CXBinaryOperator_Assign;
    return assignment;
}

static bool call_is_isolated(struct scan_context *context, CXCursor cursor, CXCursor parent)
{
    const struct cursor_ancestry *ancestor;
    enum CXCursorKind             parent_kind;
    enum CXCursorKind             ancestor_kind;
    bool                          isolated;

    (void)cursor;
    (void)parent;
    ancestor = context->ancestry;
    if(ancestor == NULL)
    {
        ancestor_kind = CXCursor_InvalidFile;
    }
    else
    {
        ancestor_kind = clang_getCursorKind(ancestor->cursor);
    }
    while(ancestor != NULL && (ancestor_kind == CXCursor_UnexposedExpr || ancestor_kind == CXCursor_LabelStmt || ancestor_kind == CXCursor_CaseStmt || ancestor_kind == CXCursor_DefaultStmt))
    {
        ancestor = ancestor->parent;
        if(ancestor == NULL)
        {
            ancestor_kind = CXCursor_InvalidFile;
        }
        else
        {
            ancestor_kind = clang_getCursorKind(ancestor->cursor);
        }
    }
    parent_kind = ancestor_kind;
    isolated    = false;
    if(parent_kind == CXCursor_CompoundStmt || parent_kind == CXCursor_VarDecl)
    {
        isolated = true;
    }
    else if(parent_kind == CXCursor_BinaryOperator)
    {
        isolated = binary_parent_is_simple_assignment(ancestor->cursor);
    }
    return isolated;
}

static char *enum_cursor_name(const struct p101_env *env, struct p101_error *err, CXCursor cursor, CXCursor parent)
{
    char             *name;
    CXString          spelling;
    enum CXCursorKind parent_kind;

    P101_TRACE_SCOPE(env);
    spelling    = clang_getCursorSpelling(cursor);
    name        = copy_cx_string(env, err, spelling);
    parent_kind = clang_getCursorKind(parent);
    if(name != NULL && parent_kind == CXCursor_TypedefDecl)
    {
        p101_free(env, name);
        spelling = clang_getCursorSpelling(parent);
        name     = copy_cx_string(env, err, spelling);
    }
    else
    {
        unsigned anonymous;

        /*
         * Ask libclang whether the declaration is anonymous instead of
         * prefix-matching the "enum (unnamed at ...)" rendering that
         * libclang uses for diagnostics.
         */
        anonymous = clang_Cursor_isAnonymous(cursor);
        if(name != NULL && anonymous != 0U)
        {
            name[0] = '\0';
        }
    }
    return name;
}

static char *copy_cursor_spelling(const struct p101_env *env, struct p101_error *err, CXCursor cursor)
{
    CXString spelling;
    char    *text;

    spelling = clang_getCursorSpelling(cursor);
    text     = copy_cx_string(env, err, spelling);
    return text;
}

static char *copy_cursor_usr(const struct p101_env *env, struct p101_error *err, CXCursor cursor)
{
    CXString usr;
    char    *text;

    usr  = clang_getCursorUSR(cursor);
    text = copy_cx_string(env, err, usr);
    return text;
}

static char *copy_cursor_type_spelling(const struct p101_env *env, struct p101_error *err, CXCursor cursor)
{
    CXType   type;
    CXString spelling;
    char    *text;

    type     = clang_getCursorType(cursor);
    spelling = clang_getTypeSpelling(type);
    text     = copy_cx_string(env, err, spelling);
    return text;
}

static char *copy_cursor_canonical_type_spelling(const struct p101_env *env, struct p101_error *err, CXCursor cursor)
{
    CXType   canonical_type;
    CXType   type;
    CXString spelling;
    char    *text;

    type           = clang_getCursorType(cursor);
    canonical_type = clang_getCanonicalType(type);
    spelling       = clang_getTypeSpelling(canonical_type);
    text           = copy_cx_string(env, err, spelling);
    return text;
}

static char *copy_cursor_result_type_spelling(const struct p101_env *env, struct p101_error *err, CXCursor cursor)
{
    CXType   type;
    CXString spelling;
    char    *text;

    type     = clang_getCursorResultType(cursor);
    spelling = clang_getTypeSpelling(type);
    text     = copy_cx_string(env, err, spelling);
    return text;
}

static bool cursor_parameter_index(CXCursor function, CXCursor parameter, size_t *parameter_index)
{
    int  argument_count;
    bool found;

    argument_count = clang_Cursor_getNumArguments(function);
    found          = false;
    for(int index = 0; index < argument_count && !found; index++)
    {
        CXCursor argument;
        unsigned equal;

        argument = clang_Cursor_getArgument(function, (unsigned)index);
        equal    = clang_equalCursors(argument, parameter);
        if(equal != 0U)
        {
            *parameter_index = (size_t)index;
            found            = true;
        }
    }
    return found;
}

static void emit_cursor_record(struct scan_context *context, CXCursor cursor, CXCursor parent)
{
    enum CXCursorKind             cursor_kind;
    struct p101_c_analysis_record record;
    char                         *path;
    char                         *name;
    char                         *type;
    char                         *canonical_type;
    char                         *return_type;
    char                         *usr;
    size_t                        line;
    size_t                        column;
    bool                          admitted;
    bool                          emitted;

    cursor_kind = clang_getCursorKind(cursor);
    p101_memset(context->env, &record, 0, sizeof(record));
    path           = NULL;
    name           = NULL;
    type           = NULL;
    canonical_type = NULL;
    return_type    = NULL;
    usr            = NULL;
    cursor_location(context->env, context->err, cursor, &path, &line, &column, &record.start_offset);
    admitted = false;
    if(path != NULL)
    {
        admitted = path_is_admitted(context->session, path);
    }
    if(path == NULL || !admitted)
    {
        goto p101_single_exit_;
    }

    record.path      = path;
    record.line      = line;
    record.column    = column;
    record.is_header = path_has_header_suffix(context->env, path);
    cursor_extent_offsets(cursor, &record.start_offset, &record.end_offset);

    if(cursor_kind == CXCursor_InclusionDirective)
    {
        bool  local_include;
        char *resolved;

        record.kind = P101_C_ANALYSIS_INCLUDE;
        name        = include_target_text(context->env, context->err, context->translation_unit, cursor, path, &local_include);
        record.name = name;
        if(name == NULL)
        {
            context->stopped = p101_error_has_error(context->err);
        }
        else
        {
            resolved = include_resolved_path(context->env, context->err, cursor);
            if(resolved == NULL)
            {
                context->stopped = true;
            }
            else
            {
                /*
                 * Admission of the resolved file, not the include delimiter,
                 * decides locality: a quoted include can still reach a system
                 * header, and an angled include can reach a project header
                 * through -I. The delimiter only survives as the fallback for
                 * a header the search paths could not resolve.
                 */
                if(resolved[0] != '\0')
                {
                    local_include = path_is_admitted(context->session, resolved);
                }
                record.resolved_include = resolved;
                record.is_local_include = local_include;
                emitted                 = emit_record(context, &record);
                (void)emitted;
                p101_free(context->env, resolved);
            }
        }
    }
    else
    {
        bool is_function;

        is_function = cursor_kind_is_function(cursor_kind);
        if(is_function)
        {
            unsigned             variadic;
            enum CX_StorageClass storage_class;

            record.kind = P101_C_ANALYSIS_FUNCTION;
            name        = copy_cursor_spelling(context->env, context->err, cursor);
            type        = copy_cursor_type_spelling(context->env, context->err, cursor);
            return_type = copy_cursor_result_type_spelling(context->env, context->err, cursor);
            usr         = copy_cursor_usr(context->env, context->err, cursor);
            if(name == NULL || type == NULL || return_type == NULL || usr == NULL)
            {
                context->stopped = true;
            }
            record.name          = name;
            record.type          = type;
            record.return_type   = return_type;
            record.usr           = usr;
            record.is_definition = cursor_is_definition(cursor);
            storage_class        = clang_Cursor_getStorageClass(cursor);
            record.is_static     = storage_class == CX_SC_Static;
            record.is_public     = true;
            if(record.is_static)
            {
                record.is_public = false;
            }
            variadic                    = clang_Cursor_isVariadic(cursor);
            record.is_variadic          = variadic != 0U;
            record.has_env_parameter    = function_has_record_contract(context->env, cursor, P101_ENV_TYPE_USR);
            record.has_error_parameter  = function_has_record_contract(context->env, cursor, P101_ERROR_TYPE_USR);
            record.is_error_state_query = function_is_error_state_query(context->env, cursor);
            if(!context->stopped)
            {
                emitted = emit_record(context, &record);
                (void)emitted;
                emit_function_semantic_roles(context, cursor, &record);
            }
            if(record.has_env_parameter && !context->stopped)
            {
                emit_note_as(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ENV_CONTRACT", record.name, record.usr);
            }
            if(record.has_error_parameter && !context->stopped)
            {
                emit_note_as(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_CONTRACT", record.name, record.usr);
            }
            if(record.is_definition && !context->stopped)
            {
                emit_signature_notes(context, cursor, &record, path, line, column);
            }
        }
        else if(cursor_kind == CXCursor_CallExpr)
        {
            CXCursor referenced;
            char    *error_argument_identity;
            bool     is_error_check;
            bool     discarded_error;
            int      referenced_is_null;

            record.kind             = P101_C_ANALYSIS_CALL;
            record.caller           = context->current_function;
            record.caller_usr       = context->current_function_usr;
            referenced              = call_referenced_cursor(cursor);
            error_argument_identity = NULL;
            is_error_check          = false;
            discarded_error         = false;
            referenced_is_null      = clang_Cursor_isNull(referenced);
            if(referenced_is_null != 0)
            {
                name               = copy_cursor_spelling(context->env, context->err, cursor);
                record.is_indirect = true;
            }
            else
            {
                CXCursor          type_declaration;
                enum CXCursorKind referenced_kind;
                bool              referenced_is_function;
                CXType            referenced_type;
                int               type_is_null;

                name                   = copy_cursor_spelling(context->env, context->err, referenced);
                record.is_indirect     = true;
                referenced_kind        = clang_getCursorKind(referenced);
                referenced_is_function = cursor_kind_is_function(referenced_kind);
                if(referenced_is_function)
                {
                    record.is_indirect = false;
                }
                type             = copy_cursor_type_spelling(context->env, context->err, referenced);
                referenced_type  = clang_getCursorType(referenced);
                type_declaration = clang_getTypeDeclaration(referenced_type);
                type_is_null     = clang_Cursor_isNull(type_declaration);
                if(record.is_indirect && type_is_null == 0)
                {
                    /*
                     * An indirect operation is identified by its declared
                     * function-pointer type, not by the local variable or field
                     * spelling used at this call site.
                     */
                    usr = copy_cursor_usr(context->env, context->err, type_declaration);
                }
                else
                {
                    usr = copy_cursor_usr(context->env, context->err, referenced);
                }
            }
            record.name = name;
            record.type = type;
            record.usr  = usr;
            if(name == NULL || (referenced_is_null == 0 && (type == NULL || usr == NULL)))
            {
                context->stopped = true;
            }
            if(referenced_is_null == 0)
            {
                int env_index;
                int error_index;

                env_index                   = function_parameter_index(context->env, referenced, P101_ENV_TYPE_USR);
                error_index                 = function_parameter_index(context->env, referenced, P101_ERROR_TYPE_USR);
                record.has_env_parameter    = env_index >= 0;
                record.has_error_parameter  = error_index >= 0;
                record.is_error_state_query = function_is_error_state_query(context->env, referenced);
            }
            if(record.has_error_parameter)
            {
                int error_index;

                error_index                    = function_parameter_index(context->env, referenced, P101_ERROR_TYPE_USR);
                error_argument_identity        = cursor_argument_identity(context->env, context->err, cursor, (unsigned)error_index);
                record.error_argument_identity = error_argument_identity;
            }
            if(!context->stopped)
            {
                emitted = emit_record(context, &record);
                (void)emitted;
            }
            if(!context->stopped)
            {
                bool generated;
                bool isolated;

                generated = call_is_generated_by_macro(cursor);
                if(!generated)
                {
                    generated = call_is_covered_by_macro_expansion(context, cursor);
                }
                isolated = call_is_isolated(context, cursor, parent);
                if(!generated && !isolated)
                {
                    bool written;

                    written = call_has_written_invocation(context, path, record.start_offset, record.end_offset);
                    if(written)
                    {
                        emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "CALL_NOT_ISOLATED");
                    }
                }
            }
            if(!context->stopped && referenced_is_null == 0)
            {
                emit_allocation_notes(context, cursor, &record, path, line, column);
                emit_handler_notes(context, cursor, path, line, column, record.is_header);
                emit_secure_semantic_call_notes(context, cursor, parent, referenced, &record, path, line, column);
            }
            if(!context->stopped)
            {
                enum CXCursorKind parent_kind;
                CXType            parent_type;
                bool              result_discarded;

                parent_kind      = clang_getCursorKind(parent);
                result_discarded = parent_kind == CXCursor_CompoundStmt;
                if(parent_kind == CXCursor_CStyleCastExpr)
                {
                    parent_type      = clang_getCursorType(parent);
                    result_discarded = parent_type.kind == CXType_Void;
                }
                if(result_discarded)
                {
                    emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "CALL_RESULT_DISCARDED");
                    if(referenced_is_null == 0 && function_result_must_be_checked(context->env, referenced))
                    {
                        emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "MUST_CHECK_RESULT_DISCARDED");
                    }
                    if(referenced_is_null == 0 && function_has_semantic_role(context->env, referenced, "p101:result:partial"))
                    {
                        emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "PARTIAL_RESULT_DISCARDED");
                    }
                }
            }
            if(!context->stopped && referenced_is_null == 0 && function_has_semantic_role(context->env, referenced, "p101:progress:resolved"))
            {
                context->uncertain_progress_usr[0]      = '\0';
                context->uncertain_progress_identity[0] = '\0';
            }
            if(!context->stopped && referenced_is_null == 0 && function_has_semantic_role(context->env, referenced, "p101:progress:uncertain"))
            {
                char *operation_identity;
                int   same_call;
                int   same_operation;

                operation_identity = call_operation_identity(context->env, context->err, cursor, referenced);
                same_call          = context->uncertain_progress_usr[0] == '\0' ? 1 : p101_strcmp(context->env, context->uncertain_progress_usr, record.usr);
                same_operation     = 1;
                if(operation_identity != NULL && context->uncertain_progress_identity[0] != '\0')
                {
                    same_operation = p101_strcmp(context->env, context->uncertain_progress_identity, operation_identity);
                }
                if(same_call == 0 && same_operation == 0)
                {
                    emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "UNCERTAIN_PROGRESS_RETRIED");
                }
                p101_snprintf(context->env, context->err, context->uncertain_progress_usr, sizeof(context->uncertain_progress_usr), "%s", record.usr);
                context->uncertain_progress_identity[0] = '\0';
                if(operation_identity != NULL)
                {
                    p101_snprintf(context->env, context->err, context->uncertain_progress_identity, sizeof(context->uncertain_progress_identity), "%s", operation_identity);
                }
                p101_free(context->env, operation_identity);
            }
            if(!context->stopped && referenced_is_null == 0 && function_has_semantic_role(context->env, referenced, "p101:sync:condition-wait") && !ancestry_contains_loop(context))
            {
                emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "CONDITION_WAIT_OUTSIDE_LOOP");
            }
            if(!context->stopped && referenced_is_null == 0 && context->post_fork_child_function && !function_has_semantic_role(context->env, referenced, "p101:process:post-fork-safe"))
            {
                emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "POST_FORK_UNSAFE_CALL");
            }
            if(!context->stopped && referenced_is_null == 0)
            {
                emit_callee_semantic_roles(context, referenced, &record);
            }
            if(!context->stopped && record.is_error_state_query)
            {
                char *checked_error_identity;
                int   error_index;
                int   comparison;

                is_error_check = true;
                emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_CHECK");
                error_index            = function_parameter_index(context->env, referenced, P101_ERROR_TYPE_USR);
                checked_error_identity = cursor_argument_identity(context->env, context->err, cursor, (unsigned)error_index);
                comparison             = 1;
                if(checked_error_identity != NULL)
                {
                    comparison = p101_strcmp(context->env, context->pending_error_identity, checked_error_identity);
                }
                if(checked_error_identity != NULL && comparison == 0)
                {
                    context->pending_error_identity[0] = '\0';
                }
                comparison = 1;
                if(checked_error_identity != NULL)
                {
                    comparison = p101_strcmp(context->env, context->pending_result_error_identity, checked_error_identity);
                }
                if(checked_error_identity != NULL && comparison == 0)
                {
                    context->pending_result_identity[0]       = '\0';
                    context->pending_result_error_identity[0] = '\0';
                    context->pending_result_end               = 0U;
                    context->pending_result_reported          = false;
                }
                if(checked_error_identity != NULL)
                {
                    p101_snprintf(context->env, context->err, context->checked_error_identity, sizeof(context->checked_error_identity), "%s", checked_error_identity);
                }
                p101_free(context->env, checked_error_identity);
            }
            if(!context->stopped && record.has_error_parameter)
            {
                int  error_index;
                bool optional_error;

                error_index     = function_parameter_index(context->env, referenced, P101_ERROR_TYPE_USR);
                discarded_error = call_discards_error(cursor, (unsigned)error_index);
                if(discarded_error)
                {
                    emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_DISCARD");
                }
                optional_error = call_uses_optional_error(context->env, cursor, (unsigned)error_index);
                if(optional_error)
                {
                    emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_OPTIONAL");
                }
                if(!optional_error && referenced_is_null == 0 && function_has_semantic_role(context->env, referenced, "p101:cleanup:fallible") && error_argument_identity != NULL && context->checked_error_identity[0] != '\0')
                {
                    int same_error;

                    same_error = p101_strcmp(context->env, context->checked_error_identity, error_argument_identity);
                    if(same_error == 0)
                    {
                        emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_CLEANUP_SHADOW");
                    }
                }
            }
            if(!context->stopped && context->inside_return)
            {
                emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_PROPAGATED");
            }
            if(!context->stopped && !is_error_check && !discarded_error && context->conditional_depth == 0U && record.has_error_parameter && error_argument_identity != NULL)
            {
                int comparison;

                comparison = 1;
                if(context->pending_error_identity[0] != '\0')
                {
                    comparison = p101_strcmp(context->env, context->pending_error_identity, error_argument_identity);
                }
                if(context->pending_error_identity[0] != '\0' && comparison == 0)
                {
                    emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_UNCHECKED_CHAIN");
                }
                p101_snprintf(context->env, context->err, context->pending_error_identity, sizeof(context->pending_error_identity), "%s", error_argument_identity);
                context->pending_result_identity[0] = '\0';
                if(call_result_identity(context, parent, context->pending_result_identity, sizeof(context->pending_result_identity)))
                {
                    p101_snprintf(context->env, context->err, context->pending_result_error_identity, sizeof(context->pending_result_error_identity), "%s", error_argument_identity);
                    context->pending_result_end      = record.end_offset;
                    context->pending_result_reported = false;
                }
            }
            emit_mutation_record(context, cursor, parent, path, line, column);
            p101_free(context->env, error_argument_identity);
        }
        else if(cursor_kind == CXCursor_ReturnStmt)
        {
            emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "FUNCTION_RETURN");
            if(record.start_offset != context->final_return_start)
            {
                emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "FUNCTION_EARLY_RETURN");
            }
        }
        else if(cursor_kind == CXCursor_MemberRefExpr)
        {
            emit_field_reach_note(context, cursor, path, line, column, record.is_header);
        }
        else if(cursor_kind == CXCursor_EnumDecl)
        {
            record.kind      = P101_C_ANALYSIS_ENUM;
            record.is_public = record.is_header;
            name             = enum_cursor_name(context->env, context->err, cursor, parent);
            usr              = copy_cursor_usr(context->env, context->err, cursor);
            record.name      = name;
            record.usr       = usr;
            if(name == NULL || usr == NULL)
            {
                context->stopped = true;
            }
            else if(name[0] != '\0')
            {
                emitted = emit_record(context, &record);
                (void)emitted;
            }
        }
        else if(cursor_kind == CXCursor_EnumConstantDecl)
        {
            record.kind       = P101_C_ANALYSIS_ENUMERATOR;
            record.is_public  = record.is_header;
            name              = copy_cursor_spelling(context->env, context->err, cursor);
            usr               = copy_cursor_usr(context->env, context->err, cursor);
            record.name       = name;
            record.usr        = usr;
            record.type       = context->current_enum;
            record.caller_usr = context->current_enum_usr;
            if(name == NULL || usr == NULL)
            {
                context->stopped = true;
            }
            else if(context->current_enum[0] != '\0')
            {
                emitted = emit_record(context, &record);
                (void)emitted;
                if(record.is_header)
                {
                    char      value_note[ANALYSIS_NAME_SIZE];
                    long long enum_value;
                    int       value_status;

                    enum_value   = clang_getEnumConstantDeclValue(cursor);
                    value_status = p101_snprintf(context->env, context->err, value_note, sizeof(value_note), "API_ENUMERATOR_VALUE:%lld", enum_value);
                    if(value_status >= 0 && (size_t)value_status < sizeof(value_note))
                    {
                        emit_note_as(context, path, line, column, record.start_offset, record.end_offset, true, value_note, record.name, record.usr);
                    }
                    else
                    {
                        context->stopped = true;
                    }
                }
            }
        }
        else if(cursor_kind == CXCursor_TypedefDecl || cursor_kind == CXCursor_StructDecl || cursor_kind == CXCursor_UnionDecl)
        {
            record.kind = P101_C_ANALYSIS_TYPE;
            name        = copy_cursor_spelling(context->env, context->err, cursor);
            usr         = copy_cursor_usr(context->env, context->err, cursor);
            record.name = name;
            record.usr  = usr;
            if(name == NULL || usr == NULL)
            {
                context->stopped = true;
            }
            else if(name[0] != '\0')
            {
                emitted = emit_record(context, &record);
                (void)emitted;
                if(record.is_header && cursor_is_definition(cursor) && (cursor_kind == CXCursor_StructDecl || cursor_kind == CXCursor_UnionDecl))
                {
                    CXType    layout_type;
                    long long byte_size;
                    long long byte_alignment;
                    char      layout_note[ANALYSIS_NAME_SIZE];
                    int       layout_status;

                    layout_type    = clang_getCursorType(cursor);
                    byte_size      = clang_Type_getSizeOf(layout_type);
                    byte_alignment = clang_Type_getAlignOf(layout_type);
                    layout_status  = p101_snprintf(context->env, context->err, layout_note, sizeof(layout_note), "API_TYPE_LAYOUT:%lld:%lld", byte_size, byte_alignment);
                    if(layout_status >= 0 && (size_t)layout_status < sizeof(layout_note))
                    {
                        emit_note_as(context, path, line, column, record.start_offset, record.end_offset, true, layout_note, record.name, record.usr);
                    }
                    else
                    {
                        context->stopped = true;
                    }
                }
            }
        }
        else if(cursor_kind == CXCursor_MacroDefinition)
        {
            record.kind          = P101_C_ANALYSIS_MACRO;
            record.is_definition = true;
            name                 = copy_cursor_spelling(context->env, context->err, cursor);
            record.name          = name;
            record.caller_usr    = context->current_function_usr;
            if(name == NULL)
            {
                context->stopped = true;
            }
            else
            {
                emitted = emit_record(context, &record);
                (void)emitted;
                emit_macro_hygiene_notes(context, cursor, &record, path, line, column);
                if(record.is_header && clang_Cursor_isMacroFunctionLike(cursor) == 0U)
                {
                    char *definition;

                    definition = source_range_text(context->env, context->err, context->translation_unit, path, record.start_offset, record.end_offset);
                    if(definition != NULL)
                    {
                        const char *replacement;
                        size_t      name_length;

                        replacement = definition;
                        name_length = p101_strlen(context->env, record.name);
                        if(p101_strncmp(context->env, replacement, record.name, name_length) == 0)
                        {
                            char macro_note[ANALYSIS_NAME_SIZE];
                            char macro_usr[ANALYSIS_IDENTITY_SIZE];
                            int  note_status;
                            int  usr_status;

                            replacement += name_length;
                            while(*replacement == ' ' || *replacement == '\t')
                            {
                                replacement++;
                            }
                            if(replacement[0] != '\0')
                            {
                                note_status = p101_snprintf(context->env, context->err, macro_note, sizeof(macro_note), "API_MACRO_VALUE:%s", replacement);
                                usr_status  = p101_snprintf(context->env, context->err, macro_usr, sizeof(macro_usr), "macro:%s:%s", path, record.name);
                                if(note_status >= 0 && (size_t)note_status < sizeof(macro_note) && usr_status >= 0 && (size_t)usr_status < sizeof(macro_usr))
                                {
                                    emit_note_as(context, path, line, column, record.start_offset, record.end_offset, true, macro_note, record.name, macro_usr);
                                }
                            }
                        }
                        p101_free(context->env, definition);
                    }
                }
            }
        }
        else if(cursor_kind == CXCursor_MacroExpansion)
        {
            name = copy_cursor_spelling(context->env, context->err, cursor);
            if(name == NULL)
            {
                context->stopped = true;
            }
            else
            {
                record.kind          = P101_C_ANALYSIS_MACRO;
                record.name          = name;
                record.caller        = context->current_function;
                record.caller_usr    = context->current_function_usr;
                record.is_definition = false;
                emitted              = emit_record(context, &record);
                (void)emitted;
            }
        }
        else if(cursor_kind == CXCursor_DeclRefExpr)
        {
            CXCursor          referenced;
            enum CXCursorKind referenced_kind;
            bool              references_function;

            referenced          = clang_getCursorReferenced(cursor);
            referenced_kind     = clang_getCursorKind(referenced);
            references_function = cursor_kind_is_function(referenced_kind);
            observe_semantic_reference(context, cursor, path, line, column, record.start_offset, record.end_offset, record.is_header);
            if(references_function)
            {
                usr = copy_cursor_usr(context->env, context->err, referenced);
                if(usr == NULL)
                {
                    context->stopped = true;
                }
                else
                {
                    char reference_note[ANALYSIS_IDENTITY_SIZE + sizeof("FUNCTION_REFERENCE:")];
                    int  written;

                    written = p101_snprintf(context->env, context->err, reference_note, sizeof(reference_note), "FUNCTION_REFERENCE:%s", usr);
                    if(written < 0 || (size_t)written >= sizeof(reference_note))
                    {
                        bool has_no_error;

                        has_no_error = p101_error_has_no_error(context->err);
                        if(has_no_error)
                        {
                            P101_ERROR_RAISE_USER(context->err, "A referenced function identity exceeds the supported fact size.", EOVERFLOW);
                        }
                        context->stopped = true;
                    }
                    else
                    {
                        emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, reference_note);
                    }
                }
            }
            else if(context->pending_result_identity[0] != '\0' && !context->pending_result_reported && record.start_offset > context->pending_result_end)
            {
                char identity[ANALYSIS_IDENTITY_SIZE];
                bool found;

                found = declaration_identity(context->env, context->err, referenced, identity, sizeof(identity));
                if(found)
                {
                    int  comparison;
                    bool consumed;

                    comparison = p101_strcmp(context->env, identity, context->pending_result_identity);
                    consumed   = result_use_requires_checked_error(context, cursor);
                    if(comparison == 0 && consumed)
                    {
                        emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_OUTPUT_UNCHECKED");
                        context->pending_result_reported = true;
                    }
                }
            }
        }
        else if(cursor_kind == CXCursor_ParmDecl)
        {
            enum CXCursorKind parent_kind;
            CXCursor          function_cursor;
            CXCursor          parameter_cursor;
            bool              parent_is_function;

            parent_kind        = clang_getCursorKind(parent);
            parent_is_function = cursor_kind_is_function(parent_kind);
            if(parent_is_function)
            {
                bool indexed;

                function_cursor  = parent;
                parameter_cursor = cursor;
                indexed          = cursor_parameter_index(function_cursor, parameter_cursor, &record.parameter_index);
                if(indexed)
                {
                    record.kind           = P101_C_ANALYSIS_PARAMETER;
                    name                  = copy_cursor_spelling(context->env, context->err, cursor);
                    type                  = copy_cursor_type_spelling(context->env, context->err, cursor);
                    canonical_type        = copy_cursor_canonical_type_spelling(context->env, context->err, cursor);
                    usr                   = copy_cursor_usr(context->env, context->err, parent);
                    record.name           = name;
                    record.type           = type;
                    record.canonical_type = canonical_type;
                    record.caller_usr     = usr;
                    if(name == NULL || type == NULL || canonical_type == NULL || usr == NULL)
                    {
                        context->stopped = true;
                    }
                    else
                    {
                        emitted = emit_record(context, &record);
                        (void)emitted;
                    }
                    if(!context->stopped)
                    {
                        bool is_env_pointer;
                        bool is_error_pointer;

                        emit_type_semantic_roles(context, cursor, &record);
                        is_env_pointer = cursor_type_is_record_pointer(context->env, cursor, P101_ENV_TYPE_USR);
                        if(is_env_pointer)
                        {
                            emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ENV_USE");
                        }
                        is_error_pointer = cursor_type_is_record_pointer(context->env, cursor, P101_ERROR_TYPE_USR);
                        if(!context->stopped && is_error_pointer)
                        {
                            emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_USE");
                        }
                    }
                }
            }
        }
        else if(cursor_kind == CXCursor_VarDecl || cursor_kind == CXCursor_MemberRefExpr)
        {
            bool is_env_pointer;
            bool is_error_pointer;

            emit_type_semantic_roles(context, cursor, &record);
            is_env_pointer = cursor_type_is_record_pointer(context->env, cursor, P101_ENV_TYPE_USR);
            if(is_env_pointer)
            {
                emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ENV_USE");
            }
            is_error_pointer = cursor_type_is_record_pointer(context->env, cursor, P101_ERROR_TYPE_USR);
            if(!context->stopped && is_error_pointer)
            {
                emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "ERROR_USE");
            }
        }
        else if(cursor_kind == CXCursor_BinaryOperator)
        {
            if(context->pending_result_identity[0] != '\0' && record.start_offset > context->pending_result_end && binary_parent_is_simple_assignment(cursor))
            {
                struct binary_operands operands;

                operands.count = 0U;
                operands.left  = clang_getNullCursor();
                operands.right = clang_getNullCursor();
                clang_visitChildren(cursor, capture_binary_operands, &operands);
                if(operands.count == 2U)
                {
                    char identity[ANALYSIS_IDENTITY_SIZE];
                    bool found;

                    found = expression_identity(context, operands.left, identity, sizeof(identity));
                    if(found)
                    {
                        int comparison;

                        comparison = p101_strcmp(context->env, identity, context->pending_result_identity);
                        if(comparison == 0)
                        {
                            context->pending_result_identity[0]       = '\0';
                            context->pending_result_error_identity[0] = '\0';
                            context->pending_result_end               = 0U;
                            context->pending_result_reported          = false;
                        }
                    }
                }
            }
            emit_mutation_record(context, cursor, parent, path, line, column);
        }
    }

p101_single_exit_:
    p101_free(context->env, canonical_type);
    p101_free(context->env, return_type);
    p101_free(context->env, type);
    p101_free(context->env, usr);
    p101_free(context->env, name);
    p101_free(context->env, path);
}

static enum CXChildVisitResult visit_cursor(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    enum CXChildVisitResult       p101_single_result_;
    struct scan_context          *context;
    enum CXCursorKind             kind;
    const char                   *saved_function;
    const char                   *saved_function_usr;
    char                         *function_name;
    char                         *function_usr;
    bool                          saved_inside_return;
    bool                          saved_post_fork_child_function;
    bool                          saved_current_recursion_bounded;
    char                          saved_uncertain_progress_usr[ANALYSIS_IDENTITY_SIZE];
    char                          saved_uncertain_progress_identity[ANALYSIS_IDENTITY_SIZE];
    size_t                        saved_final_return_start;
    CXCursor                      saved_final_return_label;
    unsigned                      saved_conditional_depth;
    char                          saved_pending_error_identity[ANALYSIS_IDENTITY_SIZE];
    char                          saved_pending_result_identity[ANALYSIS_IDENTITY_SIZE];
    char                          saved_pending_result_error_identity[ANALYSIS_IDENTITY_SIZE];
    size_t                        saved_pending_result_end;
    bool                          saved_pending_result_reported;
    char                          saved_checked_error_identity[ANALYSIS_IDENTITY_SIZE];
    char                          saved_enum[ANALYSIS_NAME_SIZE];
    char                          saved_enum_usr[ANALYSIS_IDENTITY_SIZE];
    bool                          function_scope;
    bool                          conditional_scope;
    bool                          saved_conditional_has_return;
    bool                          is_function;
    bool                          is_definition;
    bool                          goto_targets_final_return;
    int                           final_label_is_null;
    const struct cursor_ancestry *saved_ancestry;
    struct cursor_ancestry        ancestry;

    context                         = (struct scan_context *)client_data;
    saved_function                  = context->current_function;
    saved_function_usr              = context->current_function_usr;
    saved_inside_return             = context->inside_return;
    saved_post_fork_child_function  = context->post_fork_child_function;
    saved_current_recursion_bounded = context->current_recursion_bounded;
    p101_snprintf(context->env, context->err, saved_uncertain_progress_usr, sizeof(saved_uncertain_progress_usr), "%s", context->uncertain_progress_usr);
    p101_snprintf(context->env, context->err, saved_uncertain_progress_identity, sizeof(saved_uncertain_progress_identity), "%s", context->uncertain_progress_identity);
    saved_final_return_start     = context->final_return_start;
    saved_final_return_label     = context->final_return_label;
    saved_conditional_depth      = context->conditional_depth;
    saved_conditional_has_return = context->conditional_has_return;
    p101_snprintf(context->env, context->err, saved_pending_error_identity, sizeof(saved_pending_error_identity), "%s", context->pending_error_identity);
    p101_snprintf(context->env, context->err, saved_pending_result_identity, sizeof(saved_pending_result_identity), "%s", context->pending_result_identity);
    p101_snprintf(context->env, context->err, saved_pending_result_error_identity, sizeof(saved_pending_result_error_identity), "%s", context->pending_result_error_identity);
    saved_pending_result_end      = context->pending_result_end;
    saved_pending_result_reported = context->pending_result_reported;
    p101_snprintf(context->env, context->err, saved_checked_error_identity, sizeof(saved_checked_error_identity), "%s", context->checked_error_identity);
    p101_snprintf(context->env, context->err, saved_enum, sizeof(saved_enum), "%s", context->current_enum);
    p101_snprintf(context->env, context->err, saved_enum_usr, sizeof(saved_enum_usr), "%s", context->current_enum_usr);
    function_scope    = false;
    conditional_scope = false;
    function_name     = NULL;
    function_usr      = NULL;
    emit_cursor_record(context, cursor, parent);
    if(context->stopped)
    {
        p101_single_result_ = CXChildVisit_Break;
        goto p101_single_exit_;
    }

    kind = clang_getCursorKind(cursor);
    if(kind == CXCursor_BinaryOperator)
    {
        remember_signal_action_binding(context, cursor);
    }
    if(kind == CXCursor_ReturnStmt)
    {
        context->inside_return = true;
        if(context->conditional_depth > 0U)
        {
            context->conditional_has_return = true;
        }
    }
    final_label_is_null = clang_Cursor_isNull(context->final_return_label);
    if(kind == CXCursor_GotoStmt && context->conditional_depth > 0U && final_label_is_null == 0)
    {
        CXCursor target;
        CXCursor definition;
        unsigned target_matches;
        unsigned definition_matches;

        target                    = clang_getCursorReferenced(cursor);
        definition                = clang_getCursorDefinition(target);
        target_matches            = clang_equalCursors(target, context->final_return_label);
        definition_matches        = clang_equalCursors(definition, context->final_return_label);
        goto_targets_final_return = false;
        if(target_matches != 0U || definition_matches != 0U)
        {
            goto_targets_final_return = true;
        }
        if(goto_targets_final_return)
        {
            context->conditional_has_return = true;
        }
    }
    if(kind == CXCursor_IfStmt || kind == CXCursor_SwitchStmt || kind == CXCursor_ConditionalOperator || kind == CXCursor_WhileStmt || kind == CXCursor_DoStmt || kind == CXCursor_ForStmt || kind == CXCursor_CXXForRangeStmt)
    {
        conditional_scope = true;
        context->conditional_depth++;
        context->conditional_has_return           = false;
        context->pending_error_identity[0]        = '\0';
        context->pending_result_identity[0]       = '\0';
        context->pending_result_error_identity[0] = '\0';
        context->pending_result_end               = 0U;
        context->pending_result_reported          = false;
        context->checked_error_identity[0]        = '\0';
    }
    is_function   = cursor_kind_is_function(kind);
    is_definition = cursor_is_definition(cursor);
    if(is_function && is_definition)
    {
        CXString spelling;
        CXString usr;

        function_scope                          = true;
        spelling                                = clang_getCursorSpelling(cursor);
        function_name                           = copy_cx_string(context->env, context->err, spelling);
        usr                                     = clang_getCursorUSR(cursor);
        function_usr                            = copy_cx_string(context->env, context->err, usr);
        context->current_function               = function_name;
        context->current_function_usr           = function_usr;
        context->post_fork_child_function       = function_has_semantic_role(context->env, cursor, "p101:process:post-fork-child");
        context->current_recursion_bounded      = function_has_semantic_role(context->env, cursor, "p101:recursion:bounded");
        context->uncertain_progress_usr[0]      = '\0';
        context->uncertain_progress_identity[0] = '\0';
        context->final_return_start             = function_final_return_start(cursor, &context->final_return_label);
        context->pending_error_identity[0]      = '\0';
        context->checked_error_identity[0]      = '\0';
        context->environment_borrow_count       = 0U;
        context->checked_path_identity[0]       = '\0';
        context->signal_action_binding_count    = 0U;
    }
    if(kind == CXCursor_EnumDecl)
    {
        char       *enum_name;
        CXString    enum_usr_value;
        const char *enum_usr;

        enum_name      = enum_cursor_name(context->env, context->err, cursor, parent);
        enum_usr_value = clang_getCursorUSR(cursor);
        enum_usr       = clang_getCString(enum_usr_value);
        if(enum_name == NULL)
        {
            context->stopped = true;
        }
        else
        {
            const char *enum_usr_text;

            enum_usr_text = "";
            if(enum_usr != NULL)
            {
                enum_usr_text = enum_usr;
            }
            p101_snprintf(context->env, context->err, context->current_enum, sizeof(context->current_enum), "%s", enum_name);
            p101_snprintf(context->env, context->err, context->current_enum_usr, sizeof(context->current_enum_usr), "%s", enum_usr_text);
        }
        clang_disposeString(enum_usr_value);
        p101_free(context->env, enum_name);
    }
    if(context->stopped)
    {
        p101_free(context->env, function_usr);
        p101_free(context->env, function_name);
        p101_single_result_ = CXChildVisit_Break;
        goto p101_single_exit_;
    }
    saved_ancestry    = context->ancestry;
    ancestry.cursor   = cursor;
    ancestry.parent   = saved_ancestry;
    context->ancestry = &ancestry;
    clang_visitChildren(cursor, visit_cursor, context);
    context->ancestry                  = saved_ancestry;
    context->current_function          = saved_function;
    context->current_function_usr      = saved_function_usr;
    context->post_fork_child_function  = saved_post_fork_child_function;
    context->current_recursion_bounded = saved_current_recursion_bounded;
    context->inside_return             = saved_inside_return;
    context->final_return_start        = saved_final_return_start;
    context->final_return_label        = saved_final_return_label;
    context->conditional_depth         = saved_conditional_depth;
    p101_snprintf(context->env, context->err, context->current_enum, sizeof(context->current_enum), "%s", saved_enum);
    p101_snprintf(context->env, context->err, context->current_enum_usr, sizeof(context->current_enum_usr), "%s", saved_enum_usr);
    if(function_scope)
    {
        p101_snprintf(context->env, context->err, context->uncertain_progress_usr, sizeof(context->uncertain_progress_usr), "%s", saved_uncertain_progress_usr);
        p101_snprintf(context->env, context->err, context->uncertain_progress_identity, sizeof(context->uncertain_progress_identity), "%s", saved_uncertain_progress_identity);
        p101_snprintf(context->env, context->err, context->pending_error_identity, sizeof(context->pending_error_identity), "%s", saved_pending_error_identity);
        p101_snprintf(context->env, context->err, context->pending_result_identity, sizeof(context->pending_result_identity), "%s", saved_pending_result_identity);
        p101_snprintf(context->env, context->err, context->pending_result_error_identity, sizeof(context->pending_result_error_identity), "%s", saved_pending_result_error_identity);
        context->pending_result_end      = saved_pending_result_end;
        context->pending_result_reported = saved_pending_result_reported;
        p101_snprintf(context->env, context->err, context->checked_error_identity, sizeof(context->checked_error_identity), "%s", saved_checked_error_identity);
        context->conditional_has_return = saved_conditional_has_return;
    }
    else if(conditional_scope)
    {
        int comparison;

        comparison = 1;
        if(context->conditional_has_return && saved_pending_error_identity[0] != '\0')
        {
            comparison = p101_strcmp(context->env, saved_pending_error_identity, context->checked_error_identity);
        }
        if(context->conditional_has_return && saved_pending_error_identity[0] != '\0' && comparison == 0)
        {
            context->pending_error_identity[0] = '\0';
        }
        else
        {
            p101_snprintf(context->env, context->err, context->pending_error_identity, sizeof(context->pending_error_identity), "%s", saved_pending_error_identity);
        }
        context->conditional_has_return = saved_conditional_has_return;
    }
    p101_free(context->env, function_usr);
    p101_free(context->env, function_name);
    if(context->stopped)
    {
        p101_single_result_ = CXChildVisit_Break;
        goto p101_single_exit_;
    }
    p101_single_result_ = CXChildVisit_Continue;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void visit_inclusion(CXFile included_file, CXSourceLocation *inclusion_stack, unsigned include_length, CXClientData client_data)
{
    struct inclusion_context     *inclusion;
    struct scan_context          *context;
    struct p101_c_analysis_record record;
    CXString                      name;
    char                         *path;
    bool                          admitted;
    bool                          emitted;

    inclusion = (struct inclusion_context *)client_data;
    context   = inclusion->scan;
    if(context->stopped || included_file == NULL)
    {
        goto p101_single_exit_;
    }
    name     = clang_getFileName(included_file);
    path     = copy_cx_string(context->env, context->err, name);
    admitted = false;
    if(path != NULL)
    {
        admitted = path_is_admitted(context->session, path);
    }
    if(path == NULL || !admitted)
    {
        p101_free(context->env, path);
        goto p101_single_exit_;
    }

    p101_memset(context->env, &record, 0, sizeof(record));
    record.kind      = P101_C_ANALYSIS_FILE;
    record.path      = path;
    record.is_header = path_has_header_suffix(context->env, path);
    emitted          = emit_record(context, &record);
    (void)emitted;

    (void)inclusion_stack;
    (void)include_length;
    p101_free(context->env, path);

p101_single_exit_:
    return;
}

static char *include_target_text(const struct p101_env *env, struct p101_error *err, CXTranslationUnit translation_unit, CXCursor cursor, const char *path, bool *is_local)
{
    char            *p101_single_result_;
    CXSourceRange    range;
    CXFile           file;
    unsigned         line;
    unsigned         column;
    unsigned         start;
    unsigned         end;
    char            *text;
    const char      *quote;
    const char      *angle;
    const char      *opening;
    const char      *closing;
    char             closing_character;
    size_t           length;
    CXSourceLocation range_start;
    CXSourceLocation range_end;

    P101_TRACE_SCOPE(env);
    *is_local   = false;
    range       = clang_getCursorExtent(cursor);
    range_start = clang_getRangeStart(range);
    clang_getSpellingLocation(range_start, &file, &line, &column, &start);
    range_end = clang_getRangeEnd(range);
    clang_getSpellingLocation(range_end, &file, &line, &column, &end);
    if(file == NULL || end < start)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    text = source_range_text(env, err, translation_unit, path, start, end);
    if(text == NULL)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }

    quote   = p101_strchr(env, text, '"');
    angle   = p101_strchr(env, text, '<');
    opening = quote;
    if(opening == NULL || (angle != NULL && angle < opening))
    {
        opening = angle;
    }
    if(opening == NULL)
    {
        p101_free(env, text);
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    *is_local         = *opening == '"';
    closing_character = '>';
    if(*is_local)
    {
        closing_character = '"';
    }
    closing = p101_strchr(env, opening + 1, closing_character);
    if(closing == NULL)
    {
        p101_free(env, text);
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    length = (size_t)(closing - (opening + 1));
    p101_memmove(env, text, opening + 1, length);
    text[length]        = '\0';
    p101_single_result_ = text;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

/*
 * Report where an inclusion directive actually landed. libclang resolves the
 * directive against the same search paths the compiler used, so the answer is
 * the ground truth that the include spelling only approximates. An
 * unresolvable header (one the search paths do not contain) yields an empty
 * path, never NULL; NULL means the copy itself failed.
 */
static char *include_resolved_path(const struct p101_env *env, struct p101_error *err, CXCursor cursor)
{
    CXFile included;
    char  *text;

    P101_TRACE_SCOPE(env);
    included = clang_getIncludedFile(cursor);
    if(included == NULL)
    {
        text = copy_text(env, err, "");
    }
    else
    {
        CXString name;

        name = clang_getFileName(included);
        text = copy_cx_string(env, err, name);
    }
    return text;
}

static char *source_range_text(const struct p101_env *env, struct p101_error *err, CXTranslationUnit translation_unit, const char *path, size_t start, size_t end)
{
    char       *p101_single_result_;
    CXFile      file;
    const char *contents;
    size_t      contents_size;
    char       *text;
    size_t      length;
    void       *allocation;

    P101_TRACE_SCOPE(env);
    /*
     * libclang can report an inverted spelling range for calls synthesized
     * from macro expansions. Such a cursor has no safely editable source
     * range, so it is not a mutation candidate; it is not an analysis error.
     */
    if(end < start)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    /*
     * Read from the buffer libclang already parsed rather than from disk.
     * Re-reading the file would race against edits made since the parse and
     * would silently drop records when the file moved or shrank.
     */
    file = clang_getFile(translation_unit, path);
    if(file == NULL)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    contents_size = 0U;
    contents      = clang_getFileContents(translation_unit, file, &contents_size);
    if(contents == NULL || start > contents_size || end > contents_size)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    length     = end - start;
    allocation = p101_malloc(env, err, length + 1U);
    text       = (char *)allocation;
    if(text == NULL)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    /* The libclang buffer is not NUL-terminated, so copy and terminate. */
    p101_memmove(env, text, contents + start, length);
    text[length]        = '\0';
    p101_single_result_ = text;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static enum CXChildVisitResult capture_binary_operands(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct binary_operands *operands;
    enum CXChildVisitResult result;

    (void)parent;
    operands = (struct binary_operands *)client_data;
    result   = CXChildVisit_Break;
    if(operands->count == 0U)
    {
        operands->left  = cursor;
        operands->count = 1U;
        result          = CXChildVisit_Continue;
    }
    else if(operands->count == 1U)
    {
        operands->right = cursor;
        operands->count = 2U;
    }
    return result;
}

/*
 * Emit at most one mutation candidate for the operator that this cursor
 * itself denotes. Tokenizing the whole cursor extent would walk both operand
 * subtrees and produce one record per matching token, so a nested expression
 * such as "a == b && c == d" produced duplicated and spurious candidates,
 * including a unary minus mistaken for a binary subtraction.
 */
static void mutation_from_binary(struct scan_context *context, CXCursor cursor, const char *path, size_t line, size_t column)
{
    static const char *const originals[]    = {"==", "!=", "<", "<=", ">", ">=", "&&", "||", "+", "-"};
    static const char *const replacements[] = {"!=", "==", "<=", "<", ">=", ">", "||", "&&", "-", "+"};

    static const enum p101_c_mutation_kind kinds[] = {
        P101_C_MUTATION_COMPARISON_BOUNDARY,
        P101_C_MUTATION_COMPARISON_BOUNDARY,
        P101_C_MUTATION_COMPARISON_BOUNDARY,
        P101_C_MUTATION_COMPARISON_BOUNDARY,
        P101_C_MUTATION_COMPARISON_BOUNDARY,
        P101_C_MUTATION_COMPARISON_BOUNDARY,
        P101_C_MUTATION_LOGICAL_CONNECTIVE,
        P101_C_MUTATION_LOGICAL_CONNECTIVE,
        P101_C_MUTATION_ARITHMETIC_OPERATOR,
        P101_C_MUTATION_ARITHMETIC_OPERATOR,
    };

    static const enum CXBinaryOperatorKind operators[] = {
        CXBinaryOperator_EQ,
        CXBinaryOperator_NE,
        CXBinaryOperator_LT,
        CXBinaryOperator_LE,
        CXBinaryOperator_GT,
        CXBinaryOperator_GE,
        CXBinaryOperator_LAnd,
        CXBinaryOperator_LOr,
        CXBinaryOperator_Add,
        CXBinaryOperator_Sub,
    };

    struct binary_operands    operands;
    enum CXBinaryOperatorKind operator_kind;
    size_t                    operator_index;
    size_t                    operator_count;
    bool                      operator_found;
    CXToken                  *tokens;
    unsigned                  token_count;
    unsigned                  token_index;
    bool                      emitted_record;
    CXSourceRange             left_range;
    CXSourceRange             right_range;
    CXSourceRange             operator_range;
    CXSourceLocation          gap_start;
    CXSourceLocation          gap_end;

    if(context->stopped)
    {
        goto p101_single_exit_;
    }
    operator_kind  = clang_getCursorBinaryOperatorKind(cursor);
    operator_count = sizeof(operators) / sizeof(operators[0]);
    operator_found = false;
    operator_index = 0U;
    for(size_t index = 0U; index < operator_count; index++)
    {
        if(operators[index] == operator_kind)
        {
            operator_index = index;
            operator_found = true;
            break;
        }
    }
    if(!operator_found)
    {
        goto p101_single_exit_;
    }
    operands.count = 0U;
    operands.left  = clang_getNullCursor();
    operands.right = clang_getNullCursor();
    clang_visitChildren(cursor, capture_binary_operands, &operands);
    if(operands.count < 2U)
    {
        goto p101_single_exit_;
    }
    left_range     = clang_getCursorExtent(operands.left);
    right_range    = clang_getCursorExtent(operands.right);
    gap_start      = clang_getRangeEnd(left_range);
    gap_end        = clang_getRangeStart(right_range);
    operator_range = clang_getRange(gap_start, gap_end);
    tokens         = NULL;
    token_count    = 0U;
    emitted_record = false;
    clang_tokenize(context->translation_unit, operator_range, &tokens, &token_count);
    for(token_index = 0U; token_index < token_count && !emitted_record; token_index++)
    {
        CXString    spelling;
        const char *token_text;
        int         comparison;

        spelling   = clang_getTokenSpelling(context->translation_unit, tokens[token_index]);
        token_text = clang_getCString(spelling);
        comparison = 1;
        if(token_text != NULL)
        {
            comparison = p101_strcmp(context->env, token_text, originals[operator_index]);
        }
        if(token_text != NULL && comparison == 0)
        {
            struct p101_c_analysis_record record;
            CXSourceRange                 range;
            CXFile                        file;
            unsigned                      start_line;
            unsigned                      start_column;
            unsigned                      start_offset;
            unsigned                      end_line;
            unsigned                      end_column;
            unsigned                      end_offset;
            CXSourceLocation              range_start;
            CXSourceLocation              range_end;
            bool                          emitted;

            range       = clang_getTokenExtent(context->translation_unit, tokens[token_index]);
            range_start = clang_getRangeStart(range);
            clang_getSpellingLocation(range_start, &file, &start_line, &start_column, &start_offset);
            range_end = clang_getRangeEnd(range);
            clang_getSpellingLocation(range_end, &file, &end_line, &end_column, &end_offset);
            p101_memset(context->env, &record, 0, sizeof(record));
            record.kind         = P101_C_ANALYSIS_MUTATION;
            record.path         = path;
            record.line         = line;
            record.column       = column;
            record.start_offset = start_offset;
            record.end_offset   = end_offset;
            record.name         = originals[operator_index];
            record.replacement  = replacements[operator_index];
            record.mutation     = kinds[operator_index];
            emitted             = emit_record(context, &record);
            (void)emitted;
            emitted_record = true;
        }
        clang_disposeString(spelling);
    }
    clang_disposeTokens(context->translation_unit, tokens, token_count);
    goto p101_single_exit_;

p101_single_exit_:
    return;
}

static void mutation_from_call(struct scan_context *context, CXCursor cursor, CXCursor parent, const char *path, size_t line, size_t column)
{
    CXCursor          referenced;
    char             *name;
    char              predicate_replacement[ANALYSIS_NAME_SIZE];
    bool              has_predicate_replacement;
    int               referenced_is_null;
    CXString          referenced_spelling;
    bool              has_positive_role;
    bool              has_negative_role;
    CXSourceRange     cursor_range;
    enum CXCursorKind parent_kind;

    referenced         = clang_getCursorReferenced(cursor);
    referenced_is_null = clang_Cursor_isNull(referenced);
    if(referenced_is_null != 0)
    {
        goto p101_single_exit_;
    }
    referenced_spelling = clang_getCursorSpelling(referenced);
    name                = copy_cx_string(context->env, context->err, referenced_spelling);
    if(name == NULL)
    {
        context->stopped = true;
        goto p101_single_exit_;
    }
    has_predicate_replacement = false;
    has_positive_role         = function_has_semantic_role(context->env, referenced, "p101:error-state-query:positive");
    if(has_positive_role)
    {
        has_predicate_replacement = semantic_role_function_name(context->env, context->translation_unit, "p101:error-state-query:negative", predicate_replacement, sizeof(predicate_replacement));
    }
    else
    {
        has_negative_role = function_has_semantic_role(context->env, referenced, "p101:error-state-query:negative");
        if(has_negative_role)
        {
            has_predicate_replacement = semantic_role_function_name(context->env, context->translation_unit, "p101:error-state-query:positive", predicate_replacement, sizeof(predicate_replacement));
        }
    }
    if(has_predicate_replacement)
    {
        CXToken         *tokens;
        unsigned         token_count;
        unsigned         token_index;
        unsigned         callee_offset;
        bool             emitted_record;
        CXSourceLocation cursor_start;

        tokens         = NULL;
        token_count    = 0U;
        callee_offset  = 0U;
        emitted_record = false;
        cursor_range   = clang_getCursorExtent(cursor);
        cursor_start   = clang_getRangeStart(cursor_range);
        clang_getSpellingLocation(cursor_start, NULL, NULL, NULL, &callee_offset);
        clang_tokenize(context->translation_unit, cursor_range, &tokens, &token_count);
        /*
         * The callee token precedes the '(' and every argument token, so the
         * first token at or after the extent start that spells the callee is
         * the callee itself. Stopping there keeps a nested call to the same
         * function from producing a duplicate candidate.
         */
        for(token_index = 0U; token_index < token_count && !emitted_record; token_index++)
        {
            CXString         spelling;
            const char      *token_text;
            int              comparison;
            unsigned         token_offset;
            CXSourceRange    token_range;
            CXSourceLocation token_start;

            token_range  = clang_getTokenExtent(context->translation_unit, tokens[token_index]);
            token_start  = clang_getRangeStart(token_range);
            token_offset = 0U;
            clang_getSpellingLocation(token_start, NULL, NULL, NULL, &token_offset);
            spelling   = clang_getTokenSpelling(context->translation_unit, tokens[token_index]);
            token_text = clang_getCString(spelling);
            comparison = 1;
            if(token_offset >= callee_offset && token_text != NULL)
            {
                comparison = p101_strcmp(context->env, token_text, name);
            }
            if(token_offset >= callee_offset && token_text != NULL && comparison == 0)
            {
                struct p101_c_analysis_record record;
                CXSourceRange                 range;
                CXFile                        file;
                unsigned                      start_line;
                unsigned                      start_column;
                unsigned                      start_offset;
                unsigned                      end_line;
                unsigned                      end_column;
                unsigned                      end_offset;
                CXSourceLocation              range_start;
                CXSourceLocation              range_end;
                bool                          emitted;

                range       = clang_getTokenExtent(context->translation_unit, tokens[token_index]);
                range_start = clang_getRangeStart(range);
                clang_getSpellingLocation(range_start, &file, &start_line, &start_column, &start_offset);
                range_end = clang_getRangeEnd(range);
                clang_getSpellingLocation(range_end, &file, &end_line, &end_column, &end_offset);
                p101_memset(context->env, &record, 0, sizeof(record));
                record.kind         = P101_C_ANALYSIS_MUTATION;
                record.path         = path;
                record.line         = line;
                record.column       = column;
                record.start_offset = start_offset;
                record.end_offset   = end_offset;
                record.name         = name;
                record.replacement  = predicate_replacement;
                record.mutation     = P101_C_MUTATION_ERROR_PREDICATE;
                emitted             = emit_record(context, &record);
                (void)emitted;
                emitted_record = true;
            }
            clang_disposeString(spelling);
        }
        clang_disposeTokens(context->translation_unit, tokens, token_count);
        p101_free(context->env, name);
        goto p101_single_exit_;
    }

    parent_kind = clang_getCursorKind(parent);
    if(parent_kind == CXCursor_CompoundStmt)
    {
        struct p101_c_analysis_record record;
        CXSourceRange                 range;
        CXFile                        file;
        unsigned                      start_line;
        unsigned                      start_column;
        unsigned                      start_offset;
        unsigned                      end_line;
        unsigned                      end_column;
        unsigned                      end_offset;
        char                         *original;
        CXSourceLocation              range_start;
        CXSourceLocation              range_end;

        range       = clang_getCursorExtent(cursor);
        range_start = clang_getRangeStart(range);
        clang_getSpellingLocation(range_start, &file, &start_line, &start_column, &start_offset);
        range_end = clang_getRangeEnd(range);
        clang_getSpellingLocation(range_end, &file, &end_line, &end_column, &end_offset);
        original = source_range_text(context->env, context->err, context->translation_unit, path, start_offset, end_offset);
        if(original != NULL)
        {
            bool emitted;

            p101_memset(context->env, &record, 0, sizeof(record));
            record.kind         = P101_C_ANALYSIS_MUTATION;
            record.path         = path;
            record.line         = line;
            record.column       = column;
            record.start_offset = start_offset;
            record.end_offset   = end_offset;
            record.name         = original;
            record.replacement  = "(void)0";
            record.mutation     = P101_C_MUTATION_SKIP_CALL;
            emitted             = emit_record(context, &record);
            (void)emitted;
            p101_free(context->env, original);
        }
    }
    p101_free(context->env, name);

p101_single_exit_:
    return;
}

static void emit_mutation_record(struct scan_context *context, CXCursor cursor, CXCursor parent, const char *path, size_t line, size_t column)
{
    enum CXCursorKind kind;

    kind = clang_getCursorKind(cursor);
    if(kind == CXCursor_BinaryOperator)
    {
        mutation_from_binary(context, cursor, path, line, column);
    }
    else if(kind == CXCursor_CallExpr)
    {
        mutation_from_call(context, cursor, parent, path, line, column);
    }
}

static bool argument_equals_any(const struct p101_env *env, const char *argument, const char *const values[], size_t value_count)
{
    bool   p101_single_result_;
    size_t index;

    p101_single_result_ = false;
    for(index = 0U; index < value_count; index++)
    {
        int comparison;

        comparison = p101_strcmp(env, argument, values[index]);
        if(comparison == 0)
        {
            p101_single_result_ = true;
            break;
        }
    }
    return p101_single_result_;
}

static bool command_argument_takes_ignored_value(const struct p101_env *env, const char *argument)
{
    bool                     p101_single_result_;
    static const char *const values[] = {"-o", "-MF", "-MT", "-MQ"};

    P101_TRACE_SCOPE(env);
    p101_single_result_ = argument_equals_any(env, argument, values, sizeof(values) / sizeof(values[0]));
    return p101_single_result_;
}

static bool command_argument_takes_semantic_value(const struct p101_env *env, const char *argument)
{
    bool                     p101_single_result_;
    static const char *const values[] = {"-D", "-U", "-I", "-F", "-include", "-imacros", "-isystem", "-iquote", "-idirafter", "-iframework", "-x", "-target", "--target", "-arch", "-isysroot", "--sysroot", "--gcc-toolchain"};

    P101_TRACE_SCOPE(env);
    p101_single_result_ = argument_equals_any(env, argument, values, sizeof(values) / sizeof(values[0]));
    return p101_single_result_;
}

static bool argument_has_prefix(const struct p101_env *env, const char *argument, const char *prefix)
{
    bool   p101_single_result_;
    size_t prefix_length;
    int    comparison;

    P101_TRACE_SCOPE(env);
    prefix_length       = p101_strlen(env, prefix);
    comparison          = p101_strncmp(env, argument, prefix, prefix_length);
    p101_single_result_ = comparison == 0;
    return p101_single_result_;
}

static bool command_argument_is_semantic(const struct p101_env *env, const char *argument)
{
    bool                     p101_single_result_;
    static const char *const exact_arguments[] = {"-ansi",           "-nostdinc",          "-nostdinc++",  "-nobuiltininc", "-pthread",  "-ObjC",         "-ObjC++",       "-fblocks",      "-fno-blocks",
                                                  "-fms-extensions", "-fno-ms-extensions", "-fdeclspec",   "-fno-declspec", "-fchar8_t", "-fno-char8_t",  "-fshort-wchar", "-fshort-enums", "-funsigned-char",
                                                  "-fsigned-char",   "-ffreestanding",     "-fno-builtin", "-fopenmp",      "-fmodules", "-fcxx-modules", "-m32",          "-m64"};
    static const char *const prefixes[]        = {"-D",
                                                  "-U",
                                                  "-I",
                                                  "-F",
                                                  "-include",
                                                  "-imacros",
                                                  "-isystem",
                                                  "-iquote",
                                                  "-idirafter",
                                                  "-iframework",
                                                  "-iprefix",
                                                  "-iwithprefix",
                                                  "-std=",
                                                  "--std=",
                                                  "-stdlib=",
                                                  "--target=",
                                                  "-isysroot=",
                                                  "--sysroot=",
                                                  "--gcc-toolchain=",
                                                  "-resource-dir=",
                                                  "-fmodule-map-file=",
                                                  "-fmodule-file=",
                                                  "-fmodules-cache-path=",
                                                  "-fopenmp="};
    size_t                   index;

    P101_TRACE_SCOPE(env);
    for(index = 0U; index < sizeof(exact_arguments) / sizeof(exact_arguments[0]); index++)
    {
        int comparison;

        comparison = p101_strcmp(env, argument, exact_arguments[index]);
        if(comparison == 0)
        {
            p101_single_result_ = true;
            goto p101_single_exit_;
        }
    }
    for(index = 0U; index < sizeof(prefixes) / sizeof(prefixes[0]); index++)
    {
        bool has_prefix;

        has_prefix = argument_has_prefix(env, argument, prefixes[index]);
        if(has_prefix)
        {
            p101_single_result_ = true;
            goto p101_single_exit_;
        }
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool command_argument_is_output(const struct p101_env *env, const char *argument)
{
    bool p101_single_result_;
    int  objc_comparison;
    int  dependency_comparison;
    int  target_comparison;
    int  quoted_target_comparison;

    P101_TRACE_SCOPE(env);
    objc_comparison          = p101_strcmp(env, argument, "-ObjC");
    dependency_comparison    = p101_strncmp(env, argument, "-MF", sizeof("-MF") - 1U);
    target_comparison        = p101_strncmp(env, argument, "-MT", sizeof("-MT") - 1U);
    quoted_target_comparison = p101_strncmp(env, argument, "-MQ", sizeof("-MQ") - 1U);
    if((argument[0] == '-' && argument[1] == 'o' && objc_comparison != 0) || dependency_comparison == 0 || target_comparison == 0 || quoted_target_comparison == 0)
    {
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool command_argument_is_sysroot(const struct p101_env *env, const char *argument)
{
    bool p101_single_result_;
    int  isysroot_comparison;
    int  sysroot_comparison;
    int  isysroot_prefix_comparison;
    int  sysroot_prefix_comparison;

    P101_TRACE_SCOPE(env);
    isysroot_comparison        = p101_strcmp(env, argument, "-isysroot");
    sysroot_comparison         = p101_strcmp(env, argument, "--sysroot");
    isysroot_prefix_comparison = p101_strncmp(env, argument, "-isysroot=", sizeof("-isysroot=") - 1U);
    sysroot_prefix_comparison  = p101_strncmp(env, argument, "--sysroot=", sizeof("--sysroot=") - 1U);
    if(isysroot_comparison == 0 || sysroot_comparison == 0 || isysroot_prefix_comparison == 0 || sysroot_prefix_comparison == 0)
    {
        p101_single_result_ = true;
        goto p101_single_exit_;
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool scan_source(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, struct analysis_session *session, p101_c_analysis_observer observer, void *observer_context, const char *source, const char *directory,
                        const char *const arguments[], size_t argument_count)
{
    bool              p101_single_result_;
    CXIndex           index;
    CXTranslationUnit translation_unit;
    enum CXErrorCode  parse_status;
    const char       *parse_arguments[ANALYSIS_MAX_ARGUMENTS];
#ifdef P101_LIBCLANG_RESOURCE_DIR
    char resource_argument[ANALYSIS_PATH_SIZE];
#endif
    size_t                   parse_argument_count;
    size_t                   argument_index;
    struct scan_context      context;
    struct inclusion_context inclusion;
    char                     previous_directory[ANALYSIS_PATH_SIZE];
    bool                     changed_directory;
    bool                     has_sysroot;
    bool                     result;
    unsigned                 translation_unit_options;
    bool                     has_error;
    bool                     has_no_error;
    int                      operation_status;
    unsigned                 visit_status;

    P101_TRACE_SCOPE(env);
    parse_argument_count = 0U;
    has_sysroot          = false;
    for(argument_index = 0U; argument_index < argument_count && parse_argument_count < ANALYSIS_MAX_ARGUMENTS; argument_index++)
    {
        const char *argument;
        int         compile_comparison;
        int         source_comparison;
        bool        takes_ignored_value;
        bool        is_output;
        bool        takes_semantic_value;
        bool        is_semantic;
        bool        is_sysroot;

        argument           = arguments[argument_index];
        compile_comparison = p101_strcmp(env, argument, "-c");
        source_comparison  = p101_strcmp(env, argument, source);
        if(argument_index == 0U || compile_comparison == 0 || source_comparison == 0)
        {
            continue;
        }
        takes_ignored_value = command_argument_takes_ignored_value(env, argument);
        if(takes_ignored_value)
        {
            argument_index++;
            continue;
        }
        is_output = command_argument_is_output(env, argument);
        if(is_output)
        {
            continue;
        }
        takes_semantic_value = command_argument_takes_semantic_value(env, argument);
        if(takes_semantic_value)
        {
            if(argument_index + 1U < argument_count && parse_argument_count + 2U <= ANALYSIS_MAX_ARGUMENTS)
            {
                is_sysroot = command_argument_is_sysroot(env, argument);
                if(is_sysroot)
                {
                    has_sysroot = true;
                }
                parse_arguments[parse_argument_count++] = argument;
                parse_arguments[parse_argument_count++] = arguments[++argument_index];
            }
            continue;
        }
        is_semantic = command_argument_is_semantic(env, argument);
        if(!is_semantic)
        {
            continue;
        }
        is_sysroot = command_argument_is_sysroot(env, argument);
        if(is_sysroot)
        {
            has_sysroot = true;
        }
        parse_arguments[parse_argument_count++] = argument;
    }
    for(argument_index = 0U; argument_index < options->extra_argument_count && parse_argument_count < ANALYSIS_MAX_ARGUMENTS; argument_index++)
    {
        parse_arguments[parse_argument_count++] = options->extra_arguments[argument_index];
    }
#ifdef P101_LIBCLANG_RESOURCE_DIR
    if(parse_argument_count < ANALYSIS_MAX_ARGUMENTS)
    {
        p101_snprintf(env, err, resource_argument, sizeof(resource_argument), "-resource-dir=%s", P101_LIBCLANG_RESOURCE_DIR);
        has_error = p101_error_has_error(err);
        if(has_error)
        {
            p101_single_result_ = false;
            goto p101_single_exit_;
        }
        parse_arguments[parse_argument_count++] = resource_argument;
    }
#endif
#ifdef P101_LIBCLANG_SYSROOT
    if(!has_sysroot && parse_argument_count + 2U <= ANALYSIS_MAX_ARGUMENTS)
    {
        parse_arguments[parse_argument_count++] = "-isysroot";
        parse_arguments[parse_argument_count++] = P101_LIBCLANG_SYSROOT;
    }
#else
    (void)has_sysroot;
#endif

    changed_directory = false;
    if(directory != NULL && directory[0] != '\0')
    {
        const char *current_directory;

        current_directory = p101_getcwd(env, err, previous_directory, sizeof(previous_directory));
        if(current_directory != NULL)
        {
            operation_status = p101_chdir(env, err, directory);
            if(operation_status == 0)
            {
                changed_directory = true;
            }
        }
    }
    has_error = p101_error_has_error(err);
    if(has_error)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }

    index                    = clang_createIndex(0, 0);
    translation_unit_options = CXTranslationUnit_KeepGoing;
    if(options->detailed_preprocessing)
    {
        translation_unit_options |= CXTranslationUnit_DetailedPreprocessingRecord;
    }
    parse_status = clang_parseTranslationUnit2(index, source, parse_arguments, (int)parse_argument_count, NULL, 0U, translation_unit_options, &translation_unit);
    if(parse_status != CXError_Success || translation_unit == NULL)
    {
        struct p101_c_analysis_record record;

        p101_memset(env, &record, 0, sizeof(record));
        record.kind = P101_C_ANALYSIS_DIAGNOSTIC;
        record.path = source;
        record.name = "Clang could not parse the translation unit";
        p101_memset(env, &context, 0, sizeof(context));
        context.env              = env;
        context.err              = err;
        context.options          = options;
        context.session          = session;
        context.observer         = observer;
        context.observer_context = observer_context;
        result                   = emit_record(&context, &record);
        (void)result;
        clang_disposeIndex(index);
        if(changed_directory)
        {
            operation_status = p101_chdir(env, err, previous_directory);
            (void)operation_status;
        }
        has_no_error = p101_error_has_no_error(err);
        if(options->keep_going && has_no_error)
        {
            p101_single_result_ = true;
            goto p101_single_exit_;
        }
        p101_single_result_ = false;
        goto p101_single_exit_;
    }

    p101_memset(env, &context, 0, sizeof(context));
    context.env              = env;
    context.err              = err;
    context.options          = options;
    context.session          = session;
    context.observer         = observer;
    context.observer_context = observer_context;
    context.translation_unit = translation_unit;
    {
        unsigned diagnostic_count;

        diagnostic_count = clang_getNumDiagnostics(translation_unit);
        for(unsigned diagnostic_index = 0U; diagnostic_index < diagnostic_count && !context.stopped; diagnostic_index++)
        {
            CXDiagnostic              diagnostic;
            enum CXDiagnosticSeverity severity;

            diagnostic = clang_getDiagnostic(translation_unit, diagnostic_index);
            severity   = clang_getDiagnosticSeverity(diagnostic);
            if(severity == CXDiagnostic_Error || severity == CXDiagnostic_Fatal)
            {
                struct p101_c_analysis_record record;
                CXSourceLocation              location;
                CXFile                        file;
                CXString                      diagnostic_text;
                CXString                      diagnostic_path;
                const char                   *path;
                unsigned                      line;
                unsigned                      column;
                bool                          emitted;

                p101_memset(env, &record, 0, sizeof(record));
                location = clang_getDiagnosticLocation(diagnostic);
                file     = NULL;
                line     = 0U;
                column   = 0U;
                clang_getSpellingLocation(location, &file, &line, &column, NULL);
                diagnostic_path = clang_getFileName(file);
                path            = clang_getCString(diagnostic_path);
                diagnostic_text = clang_getDiagnosticSpelling(diagnostic);
                record.kind     = P101_C_ANALYSIS_DIAGNOSTIC;
                record.path     = source;
                if(path != NULL && path[0] != '\0')
                {
                    record.path = path;
                }
                record.name   = clang_getCString(diagnostic_text);
                record.line   = line;
                record.column = column;
                emitted       = emit_record(&context, &record);
                (void)emitted;
                clang_disposeString(diagnostic_text);
                clang_disposeString(diagnostic_path);
            }
            clang_disposeDiagnostic(diagnostic);
        }
    }
    inclusion.scan = &context;
    if(!context.stopped)
    {
        clang_getInclusions(translation_unit, visit_inclusion, &inclusion);
    }
    if(!context.stopped)
    {
        CXCursor translation_unit_cursor;

        translation_unit_cursor = clang_getTranslationUnitCursor(translation_unit);
        if(options->detailed_preprocessing)
        {
            visit_status = clang_visitChildren(translation_unit_cursor, collect_macro_expansion, &context);
            (void)visit_status;
        }
        if(!context.stopped)
        {
            visit_status = clang_visitChildren(translation_unit_cursor, visit_cursor, &context);
            (void)visit_status;
        }
    }
    result       = false;
    has_no_error = p101_error_has_no_error(err);
    if(!context.stopped && has_no_error)
    {
        result = true;
    }
    p101_free(env, context.macro_expansions);
    clang_disposeTranslationUnit(translation_unit);
    clang_disposeIndex(index);
    if(changed_directory)
    {
        operation_status = p101_chdir(env, err, previous_directory);
        (void)operation_status;
    }
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void emit_signature_notes(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *record, const char *path, size_t line, size_t column)
{
    int  env_index;
    int  error_index;
    bool misordered;

    {
        CXType declared_result;
        CXType result_type;
        bool   makes_env;

        declared_result = clang_getCursorResultType(cursor);
        result_type     = clang_getCanonicalType(declared_result);
        makes_env       = type_is_record_pointer(context->env, result_type, P101_ENV_TYPE_USR);
        if(makes_env)
        {
            /*
             * Constructors and duplicators OF the env receive it as data, not
             * as the tracing context, so the ordering contract does not apply.
             */
            env_index   = -1;
            error_index = -1;
        }
        else
        {
            env_index   = function_parameter_index(context->env, cursor, P101_ENV_TYPE_USR);
            error_index = function_parameter_index(context->env, cursor, P101_ERROR_TYPE_USR);
        }
    }
    misordered = false;
    if(env_index > 0)
    {
        misordered = true;
    }
    else
    {
        int expected_error_index;

        expected_error_index = 0;
        if(env_index == 0)
        {
            expected_error_index = 1;
        }
        if(error_index >= 0 && error_index != expected_error_index)
        {
            misordered = true;
        }
    }
    if(misordered)
    {
        emit_note_as(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "SIGNATURE_ENV_ORDER", record->name, record->usr);
    }
}

static bool callee_usr_is_allocator(const struct p101_env *env, const char *usr)
{
    static const char *const allocators[] = {"c:@F@malloc", "c:@F@calloc", "c:@F@realloc", "c:@F@aligned_alloc", "c:@F@reallocarray", "c:@F@p101_malloc", "c:@F@p101_calloc", "c:@F@p101_realloc", "c:@F@p101_reallocarray"};
    bool                     ret_val;

    ret_val = false;
    for(size_t index = 0U; index < sizeof(allocators) / sizeof(allocators[0]) && !ret_val; index++)
    {
        int comparison;

        comparison = p101_strcmp(env, usr, allocators[index]);
        if(comparison == 0)
        {
            ret_val = true;
        }
    }

    return ret_val;
}

struct sizeof_probe
{
    CXTranslationUnit translation_unit;
    bool              found;
};

static enum CXChildVisitResult probe_sizeof_expression_child(CXCursor candidate, CXCursor parent, CXClientData client_data)
{
    struct sizeof_probe *probe;
    enum CXCursorKind    kind;
    unsigned             is_expression;

    (void)parent;
    probe         = (struct sizeof_probe *)client_data;
    kind          = clang_getCursorKind(candidate);
    is_expression = clang_isExpression(kind);
    if(is_expression != 0U)
    {
        probe->found = true;
    }

    return CXChildVisit_Continue;
}

static enum CXChildVisitResult probe_sizeof_type(CXCursor candidate, CXCursor parent, CXClientData client_data)
{
    struct sizeof_probe *probe;
    enum CXCursorKind    kind;

    (void)parent;
    probe = (struct sizeof_probe *)client_data;
    kind  = clang_getCursorKind(candidate);
    if(kind == CXCursor_UnaryExpr)
    {
        CXToken      *tokens;
        CXSourceRange extent;
        unsigned      token_count;
        bool          is_sizeof;

        tokens      = NULL;
        token_count = 0U;
        is_sizeof   = false;
        extent      = clang_getCursorExtent(candidate);
        clang_tokenize(probe->translation_unit, extent, &tokens, &token_count);
        if(token_count > 0U)
        {
            CXString    spelling;
            const char *text;

            spelling = clang_getTokenSpelling(probe->translation_unit, tokens[0]);
            text     = clang_getCString(spelling);
            if(text != NULL && text[0] == 's' && text[1] == 'i' && text[2] == 'z')
            {
                is_sizeof = true;
            }
            clang_disposeString(spelling);
        }
        clang_disposeTokens(probe->translation_unit, tokens, token_count);
        if(is_sizeof)
        {
            struct sizeof_probe child_probe;

            child_probe.translation_unit = probe->translation_unit;
            child_probe.found            = false;
            clang_visitChildren(candidate, probe_sizeof_expression_child, &child_probe);
            if(!child_probe.found)
            {
                probe->found = true;
            }
        }
    }

    return CXChildVisit_Recurse;
}

static void emit_allocation_notes(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *record, const char *path, size_t line, size_t column)
{
    bool is_allocator;

    if(record->usr == NULL)
    {
        goto done;
    }
    is_allocator = callee_usr_is_allocator(context->env, record->usr);
    if(is_allocator)
    {
        struct sizeof_probe probe;
        int                 argument_count;

        probe.translation_unit = context->translation_unit;
        probe.found            = false;
        argument_count         = clang_Cursor_getNumArguments(cursor);
        for(int index = 0; index < argument_count && !probe.found; index++)
        {
            CXCursor                argument;
            enum CXChildVisitResult visit_result;

            argument     = clang_Cursor_getArgument(cursor, (unsigned)index);
            visit_result = probe_sizeof_type(argument, cursor, &probe);
            (void)visit_result;
            if(!probe.found)
            {
                clang_visitChildren(argument, probe_sizeof_type, &probe);
            }
        }
        if(probe.found)
        {
            emit_note_as(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "ALLOC_SIZEOF_TYPE", record->name, record->usr);
        }
    }

done:
    return;
}

static bool callee_usr_registers_handler(const struct p101_env *env, const char *usr)
{
    static const char *const registrars[] = {"c:@F@signal", "c:@F@bsd_signal", "c:@F@sigset", "c:@F@atexit", "c:@F@at_quick_exit", "c:@F@pthread_atfork", "c:@F@p101_signal", "c:@F@p101_atexit"};
    bool                     ret_val;

    ret_val = false;
    for(size_t index = 0U; index < sizeof(registrars) / sizeof(registrars[0]) && !ret_val; index++)
    {
        int comparison;

        comparison = p101_strcmp(env, usr, registrars[index]);
        if(comparison == 0)
        {
            ret_val = true;
        }
    }

    return ret_val;
}

struct function_reference_capture
{
    CXCursor function;
    bool     found;
};

static enum CXChildVisitResult capture_function_reference(CXCursor candidate, CXCursor parent, CXClientData client_data)
{
    struct function_reference_capture *capture;
    enum CXChildVisitResult            result;

    (void)parent;
    capture = (struct function_reference_capture *)client_data;
    result  = CXChildVisit_Recurse;
    if(clang_getCursorKind(candidate) == CXCursor_DeclRefExpr)
    {
        CXCursor referenced;

        referenced = clang_getCursorReferenced(candidate);
        if(cursor_kind_is_function(clang_getCursorKind(referenced)))
        {
            capture->function = referenced;
            capture->found    = true;
            result            = CXChildVisit_Break;
        }
    }
    return result;
}

static bool cursor_has_function_pointer_type(CXCursor cursor)
{
    CXType type;
    CXType pointee;
    bool   matches;

    matches = false;
    type    = clang_getCanonicalType(clang_getCursorType(cursor));
    if(type.kind == CXType_Pointer)
    {
        pointee = clang_getCanonicalType(clang_getPointeeType(type));
        matches = pointee.kind == CXType_FunctionProto || pointee.kind == CXType_FunctionNoProto;
    }
    return matches;
}

static enum CXChildVisitResult probe_function_pointer_member(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    bool                   *found;
    enum CXChildVisitResult result;

    (void)parent;
    found  = (bool *)client_data;
    *found = cursor_has_function_pointer_type(cursor);
    result = *found ? CXChildVisit_Break : CXChildVisit_Recurse;
    return result;
}

static void remember_signal_action_binding(struct scan_context *context, CXCursor cursor)
{
    struct binary_operands            operands;
    struct function_reference_capture capture;
    char                              owner_identity[ANALYSIS_IDENTITY_SIZE];
    bool                              function_member;
    bool                              has_owner;

    if(!binary_parent_is_simple_assignment(cursor))
    {
        goto done;
    }
    operands.count = 0U;
    operands.left  = clang_getNullCursor();
    operands.right = clang_getNullCursor();
    clang_visitChildren(cursor, capture_binary_operands, &operands);
    if(operands.count != 2U)
    {
        goto done;
    }
    function_member = false;
    if(probe_function_pointer_member(operands.left, cursor, &function_member) == CXChildVisit_Recurse)
    {
        clang_visitChildren(operands.left, probe_function_pointer_member, &function_member);
    }
    if(!function_member)
    {
        goto done;
    }
    has_owner = expression_identity(context, operands.left, owner_identity, sizeof(owner_identity));
    if(!has_owner)
    {
        goto done;
    }
    {
        size_t identity_length;
        size_t component_start;

        identity_length = p101_strlen(context->env, owner_identity);
        component_start = 0U;
        for(size_t index = 0U; index + 1U < identity_length; index++)
        {
            if(owner_identity[index] == ';')
            {
                component_start = index + 1U;
            }
        }
        if(component_start > 0U)
        {
            p101_memmove(context->env, owner_identity, owner_identity + component_start, identity_length - component_start + 1U);
        }
    }
    capture.function = clang_getNullCursor();
    capture.found    = false;
    if(capture_function_reference(operands.right, cursor, &capture) == CXChildVisit_Recurse)
    {
        clang_visitChildren(operands.right, capture_function_reference, &capture);
    }
    if(capture.found)
    {
        size_t index;
        char  *handler_name;
        char  *handler_usr;

        index = context->signal_action_binding_count;
        for(size_t candidate = 0U; candidate < context->signal_action_binding_count; candidate++)
        {
            int comparison;

            comparison = p101_strcmp(context->env, context->signal_action_bindings[candidate].owner_identity, owner_identity);
            if(comparison == 0)
            {
                index = candidate;
                break;
            }
        }
        if(index == context->signal_action_binding_count && index < SEMANTIC_IDENTITY_CAPACITY)
        {
            context->signal_action_binding_count++;
        }
        if(index < SEMANTIC_IDENTITY_CAPACITY)
        {
            handler_name = copy_cursor_spelling(context->env, context->err, capture.function);
            handler_usr  = copy_cursor_usr(context->env, context->err, capture.function);
            if(handler_name != NULL && handler_usr != NULL)
            {
                p101_snprintf(context->env, context->err, context->signal_action_bindings[index].owner_identity, sizeof(context->signal_action_bindings[index].owner_identity), "%s", owner_identity);
                p101_snprintf(context->env, context->err, context->signal_action_bindings[index].handler_name, sizeof(context->signal_action_bindings[index].handler_name), "%s", handler_name);
                p101_snprintf(context->env, context->err, context->signal_action_bindings[index].handler_usr, sizeof(context->signal_action_bindings[index].handler_usr), "%s", handler_usr);
            }
            p101_free(context->env, handler_name);
            p101_free(context->env, handler_usr);
        }
    }

done:
    return;
}

static bool callee_usr_registers_signal_handler(const struct p101_env *env, const char *usr)
{
    static const char *const registrars[] = {"c:@F@signal", "c:@F@bsd_signal", "c:@F@sigset", "c:@F@sigaction", "c:@F@p101_signal", "c:@F@p101_sigaction"};
    bool                     ret_val;

    ret_val = false;
    for(size_t index = 0U; index < sizeof(registrars) / sizeof(registrars[0]) && !ret_val; index++)
    {
        int comparison;

        comparison = p101_strcmp(env, usr, registrars[index]);
        if(comparison == 0)
        {
            ret_val = true;
        }
    }

    return ret_val;
}

static enum CXChildVisitResult probe_handler_reference(CXCursor candidate, CXCursor parent, CXClientData client_data);

struct handler_probe
{
    struct scan_context *context;
    const char          *path;
    const char          *note_name;
    size_t               line;
    size_t               column;
    bool                 is_header;
};

static enum CXChildVisitResult probe_handler_reference(CXCursor candidate, CXCursor parent, CXClientData client_data)
{
    struct handler_probe *probe;
    enum CXCursorKind     kind;

    (void)parent;
    probe = (struct handler_probe *)client_data;
    kind  = clang_getCursorKind(candidate);
    if(kind == CXCursor_DeclRefExpr)
    {
        CXCursor          referenced;
        enum CXCursorKind referenced_kind;
        bool              references_function;

        referenced          = clang_getCursorReferenced(candidate);
        referenced_kind     = clang_getCursorKind(referenced);
        references_function = cursor_kind_is_function(referenced_kind);
        if(references_function)
        {
            char *handler_name;
            char *handler_usr;

            handler_name = copy_cursor_spelling(probe->context->env, probe->context->err, referenced);
            handler_usr  = copy_cursor_usr(probe->context->env, probe->context->err, referenced);
            if(handler_name != NULL && handler_usr != NULL)
            {
                emit_note_as(probe->context, probe->path, probe->line, probe->column, 0U, 0U, probe->is_header, probe->note_name, handler_name, handler_usr);
            }
            p101_free(probe->context->env, handler_name);
            p101_free(probe->context->env, handler_usr);
        }
    }

    return CXChildVisit_Recurse;
}

static void emit_handler_notes(struct scan_context *context, CXCursor cursor, const char *path, size_t line, size_t column, bool is_header)
{
    CXCursor referenced;
    int      referenced_is_null;

    referenced         = clang_getCursorReferenced(cursor);
    referenced_is_null = clang_Cursor_isNull(referenced);
    if(referenced_is_null == 0)
    {
        CXString    identity;
        const char *callee_usr;
        bool        registers;
        bool        registers_signal;

        identity         = clang_getCursorUSR(referenced);
        callee_usr       = clang_getCString(identity);
        registers        = false;
        registers_signal = false;
        if(callee_usr != NULL)
        {
            registers        = callee_usr_registers_handler(context->env, callee_usr);
            registers_signal = callee_usr_registers_signal_handler(context->env, callee_usr);
        }
        clang_disposeString(identity);
        if(registers)
        {
            struct handler_probe probe;
            int                  argument_count;

            probe.context   = context;
            probe.path      = path;
            probe.note_name = "HANDLER_REGISTERED";
            probe.line      = line;
            probe.column    = column;
            probe.is_header = is_header;
            argument_count  = clang_Cursor_getNumArguments(cursor);
            for(int index = 0; index < argument_count; index++)
            {
                CXCursor                argument;
                enum CXChildVisitResult visit_result;

                argument     = clang_Cursor_getArgument(cursor, (unsigned)index);
                visit_result = probe_handler_reference(argument, cursor, &probe);
                (void)visit_result;
                clang_visitChildren(argument, probe_handler_reference, &probe);
            }
        }
        if(registers_signal)
        {
            struct handler_probe probe;
            int                  argument_count;

            probe.context   = context;
            probe.path      = path;
            probe.note_name = "SIGNAL_HANDLER_REGISTERED";
            probe.line      = line;
            probe.column    = column;
            probe.is_header = is_header;
            argument_count  = clang_Cursor_getNumArguments(cursor);
            for(int index = 0; index < argument_count; index++)
            {
                CXCursor                argument;
                enum CXChildVisitResult visit_result;

                argument     = clang_Cursor_getArgument(cursor, (unsigned)index);
                visit_result = probe_handler_reference(argument, cursor, &probe);
                (void)visit_result;
                clang_visitChildren(argument, probe_handler_reference, &probe);
            }
            for(int argument_index = 0; argument_index < argument_count; argument_index++)
            {
                CXCursor argument;
                char     owner_identity[ANALYSIS_IDENTITY_SIZE];
                bool     has_owner;

                argument  = clang_Cursor_getArgument(cursor, (unsigned)argument_index);
                has_owner = expression_identity(context, argument, owner_identity, sizeof(owner_identity));
                for(size_t binding_index = 0U; has_owner && binding_index < context->signal_action_binding_count; binding_index++)
                {
                    int comparison;

                    comparison = p101_strcmp(context->env, owner_identity, context->signal_action_bindings[binding_index].owner_identity);
                    if(comparison == 0)
                    {
                        emit_note_as(context, path, line, column, 0U, 0U, is_header, "SIGNAL_HANDLER_REGISTERED", context->signal_action_bindings[binding_index].handler_name, context->signal_action_bindings[binding_index].handler_usr);
                        break;
                    }
                }
            }
        }
    }
}

static bool token_is_bare_operator(const struct p101_env *env, const char *spelling)
{
    static const char *const operators[] = {"+", "-", "*", "/", "%", "<<", ">>", "<", ">", "<=", ">=", "==", "!=", "&", "|", "^", "&&", "||", "?", ":", "=", "!", "~"};
    bool                     ret_val;

    ret_val = false;
    for(size_t index = 0U; index < sizeof(operators) / sizeof(operators[0]) && !ret_val; index++)
    {
        int comparison;

        comparison = p101_strcmp(env, spelling, operators[index]);
        if(comparison == 0)
        {
            ret_val = true;
        }
    }

    return ret_val;
}

static void emit_macro_hygiene_notes(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *record, const char *path, size_t line, size_t column)
{
    enum
    {
        MACRO_MAX_PARAMS       = 16,
        MACRO_MAX_PARAM_LENGTH = 64
    };

    CXToken      *tokens;
    CXSourceRange extent;
    unsigned      token_count;
    unsigned      function_like;

    function_like = clang_Cursor_isMacroFunctionLike(cursor);
    if(function_like == 0U)
    {
        goto done;
    }
    tokens      = NULL;
    token_count = 0U;
    extent      = clang_getCursorExtent(cursor);
    clang_tokenize(context->translation_unit, extent, &tokens, &token_count);
    if(token_count > 2U)
    {
        char     parameters[MACRO_MAX_PARAMS][MACRO_MAX_PARAM_LENGTH];
        size_t   parameter_count;
        unsigned body_start;
        unsigned semicolon_count;
        bool     analyzable;
        bool     argument_bare;
        bool     statement_bare;

        parameter_count = 0U;
        body_start      = 0U;
        analyzable      = true;
        argument_bare   = false;
        statement_bare  = false;
        semicolon_count = 0U;
        for(unsigned index = 2U; index < token_count && body_start == 0U && analyzable; index++)
        {
            CXString    spelling;
            const char *text;

            spelling = clang_getTokenSpelling(context->translation_unit, tokens[index]);
            text     = clang_getCString(spelling);
            if(text == NULL)
            {
                analyzable = false;
            }
            else if(text[0] == ')' && text[1] == '\0')
            {
                body_start = index + 1U;
            }
            else if(text[0] != ',' || text[1] != '\0')
            {
                /*
                 * The separator carries no name; every other token in the
                 * parameter list names one.
                 */
                size_t text_length;

                text_length = p101_strlen(context->env, text);
                if(parameter_count >= (size_t)MACRO_MAX_PARAMS || text_length >= (size_t)MACRO_MAX_PARAM_LENGTH)
                {
                    analyzable = false;
                }
                else
                {
                    p101_strncpy(context->env, parameters[parameter_count], text, (size_t)MACRO_MAX_PARAM_LENGTH - 1U);
                    parameters[parameter_count][MACRO_MAX_PARAM_LENGTH - 1U] = '\0';
                    parameter_count++;
                }
            }
            clang_disposeString(spelling);
        }
        if(analyzable && body_start > 0U && body_start < token_count)
        {
            for(unsigned index = body_start; index < token_count; index++)
            {
                CXString    spelling;
                const char *text;

                spelling = clang_getTokenSpelling(context->translation_unit, tokens[index]);
                text     = clang_getCString(spelling);
                if(text != NULL)
                {
                    bool is_parameter;

                    if(text[0] == ';' && text[1] == '\0')
                    {
                        semicolon_count++;
                    }
                    is_parameter = false;
                    for(size_t parameter = 0U; parameter < parameter_count && !is_parameter; parameter++)
                    {
                        int comparison;

                        comparison = p101_strcmp(context->env, text, parameters[parameter]);
                        if(comparison == 0)
                        {
                            is_parameter = true;
                        }
                    }
                    if(is_parameter)
                    {
                        bool previous_operator;
                        bool next_operator;

                        previous_operator = false;
                        next_operator     = false;
                        if(index > body_start)
                        {
                            CXString    previous_spelling;
                            const char *previous_text;

                            previous_spelling = clang_getTokenSpelling(context->translation_unit, tokens[index - 1U]);
                            previous_text     = clang_getCString(previous_spelling);
                            if(previous_text != NULL)
                            {
                                previous_operator = token_is_bare_operator(context->env, previous_text);
                            }
                            clang_disposeString(previous_spelling);
                        }
                        if(index + 1U < token_count)
                        {
                            CXString    next_spelling;
                            const char *next_text;

                            next_spelling = clang_getTokenSpelling(context->translation_unit, tokens[index + 1U]);
                            next_text     = clang_getCString(next_spelling);
                            if(next_text != NULL)
                            {
                                next_operator = token_is_bare_operator(context->env, next_text);
                            }
                            clang_disposeString(next_spelling);
                        }
                        if(previous_operator || next_operator)
                        {
                            argument_bare = true;
                        }
                    }
                }
                clang_disposeString(spelling);
            }
        }
        if(analyzable && body_start > 0U && semicolon_count >= 2U)
        {
            CXString    first_spelling;
            const char *first_text;
            bool        starts_with_do;

            first_spelling = clang_getTokenSpelling(context->translation_unit, tokens[body_start]);
            first_text     = clang_getCString(first_spelling);
            starts_with_do = false;
            if(first_text != NULL && first_text[0] == 'd' && first_text[1] == 'o' && first_text[2] == '\0')
            {
                starts_with_do = true;
            }
            clang_disposeString(first_spelling);
            if(!starts_with_do)
            {
                statement_bare = true;
            }
        }
        if(argument_bare)
        {
            emit_note_as(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "MACRO_ARGUMENT_BARE", record->name, "");
        }
        if(statement_bare)
        {
            emit_note_as(context, path, line, column, record->start_offset, record->end_offset, record->is_header, "MACRO_STATEMENT_BARE", record->name, "");
        }
    }
    clang_disposeTokens(context->translation_unit, tokens, token_count);

done:
    return;
}

static void emit_field_reach_note(struct scan_context *context, CXCursor cursor, const char *path, size_t line, size_t column, bool is_header)
{
    CXCursor          referenced;
    enum CXCursorKind referenced_kind;

    referenced      = clang_getCursorReferenced(cursor);
    referenced_kind = clang_getCursorKind(referenced);
    if(referenced_kind == CXCursor_FieldDecl)
    {
        CXCursor          owner;
        enum CXCursorKind owner_kind;

        owner      = clang_getCursorSemanticParent(referenced);
        owner_kind = clang_getCursorKind(owner);
        if(owner_kind == CXCursor_StructDecl || owner_kind == CXCursor_UnionDecl)
        {
            char  *owner_path;
            size_t owner_line;
            size_t owner_column;
            size_t owner_offset;

            owner_path = NULL;
            cursor_location(context->env, context->err, owner, &owner_path, &owner_line, &owner_column, &owner_offset);
            if(owner_path != NULL)
            {
                bool owner_admitted;
                int  same_file;

                owner_admitted = path_is_admitted(context->session, owner_path);
                same_file      = p101_strcmp(context->env, owner_path, path);
                if(owner_admitted && same_file != 0)
                {
                    char *field_name;
                    char *owner_usr;

                    field_name = copy_cursor_spelling(context->env, context->err, referenced);
                    owner_usr  = copy_cursor_usr(context->env, context->err, owner);
                    if(field_name != NULL && owner_usr != NULL)
                    {
                        emit_note_as(context, path, line, column, 0U, 0U, is_header, "FIELD_REACH", field_name, owner_usr);
                    }
                    p101_free(context->env, field_name);
                    p101_free(context->env, owner_usr);
                }
                p101_free(context->env, owner_path);
            }
        }
    }
}

static bool should_skip_directory(const struct p101_env *env, const char *name)
{
    bool                     p101_single_result_;
    static const char *const skipped[] = {".git", ".hg", ".svn", "__pycache__", "build", "coverage", "debug", "dist", "profile"};
    size_t                   index;

    P101_TRACE_SCOPE(env);
    for(index = 0U; index < sizeof(skipped) / sizeof(skipped[0]); index++)
    {
        int comparison;

        comparison = p101_strcmp(env, name, skipped[index]);
        if(comparison == 0)
        {
            p101_single_result_ = true;
            goto p101_single_exit_;
        }
    }
    {
        int build_comparison;
        int coverage_comparison;
        int debug_comparison;
        int profile_comparison;

        build_comparison    = p101_strncmp(env, name, "build-", sizeof("build-") - 1U);
        coverage_comparison = p101_strncmp(env, name, "coverage-", sizeof("coverage-") - 1U);
        debug_comparison    = p101_strncmp(env, name, "debug-", sizeof("debug-") - 1U);
        profile_comparison  = p101_strncmp(env, name, "profile-", sizeof("profile-") - 1U);
        if(build_comparison == 0 || coverage_comparison == 0 || debug_comparison == 0 || profile_comparison == 0)
        {
            p101_single_result_ = true;
            goto p101_single_exit_;
        }
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

// NOLINTNEXTLINE(misc-no-recursion) -- directory trees are recursively bounded by the filesystem.
static bool scan_directory(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, struct analysis_session *session, p101_c_analysis_observer observer, void *observer_context, const char *directory)
{
    bool           p101_single_result_;
    DIR           *stream;
    struct dirent *entry;
    bool           result;
    bool           has_no_error;

    P101_TRACE_SCOPE(env);
    result = true;
    stream = p101_opendir(env, err, directory);
    if(stream == NULL)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    entry        = p101_readdir(env, err, stream);
    has_no_error = p101_error_has_no_error(err);
    while(entry != NULL && has_no_error)
    {
        char        path[ANALYSIS_PATH_SIZE];
        struct stat status;
        int         current_comparison;
        int         parent_comparison;
        bool        skip_directory;
        bool        directory_entry;
        bool        regular_entry;
        bool        source_path;
        bool        header_path;
        bool        scan_result;
        bool        has_error;
        int         stat_status;

        current_comparison = p101_strcmp(env, entry->d_name, ".");
        parent_comparison  = p101_strcmp(env, entry->d_name, "..");
        skip_directory     = should_skip_directory(env, entry->d_name);
        if(current_comparison == 0 || parent_comparison == 0 || skip_directory)
        {
            entry        = p101_readdir(env, err, stream);
            has_no_error = p101_error_has_no_error(err);
            continue;
        }
        p101_snprintf(env, err, path, sizeof(path), "%s/%s", directory, entry->d_name);
        has_error = p101_error_has_error(err);
        if(has_error)
        {
            result = false;
            break;
        }
        stat_status = p101_stat(env, err, path, &status);
        if(stat_status != 0)
        {
            result = false;
            break;
        }
        directory_entry = S_ISDIR(status.st_mode);
        regular_entry   = S_ISREG(status.st_mode);
        source_path     = path_has_source_suffix(env, path);
        header_path     = path_has_header_suffix(env, path);
        if(directory_entry)
        {
            scan_result = scan_directory(env, err, options, session, observer, observer_context, path);
            if(!scan_result)
            {
                result = false;
                break;
            }
        }
        else if(regular_entry && (source_path || (options->include_headers_as_translation_units && header_path)))
        {
            const char *default_arguments[] = {"clang", "-D_POSIX_C_SOURCE=200809L", "-D_XOPEN_SOURCE=700"};
            size_t      default_argument_count;

            default_argument_count = sizeof(default_arguments) / sizeof(default_arguments[0]);
            scan_result            = scan_source(env, err, options, session, observer, observer_context, path, directory, default_arguments, default_argument_count);
            if(!scan_result)
            {
                result = false;
                break;
            }
        }
        entry        = p101_readdir(env, err, stream);
        has_no_error = p101_error_has_no_error(err);
    }
    has_no_error = p101_error_has_no_error(err);
    if(!has_no_error)
    {
        result = false;
    }
    {
        int  close_status;
        bool had_error_before_close;

        had_error_before_close = p101_error_has_error(err);
        close_status           = p101_closedir(env, err, stream);
        /*
         * A before-call fault leaves the stream owned by this function. Retry
         * once so the injected failure is reported without leaking that
         * ownership. When an earlier operation already failed, p101_closedir
         * closes the stream but preserves that first error by returning -1,
         * so that path must not be retried.
         */
        if(close_status != 0 && !had_error_before_close)
        {
            int cleanup_status;

            cleanup_status = p101_closedir(env, err, stream);
            (void)cleanup_status;
        }
        if(close_status != 0)
        {
            result = false;
        }
    }
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool scan_compile_database(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, struct analysis_session *session, p101_c_analysis_observer observer, void *observer_context)
{
    bool                        p101_single_result_;
    char                        database_directory[ANALYSIS_PATH_SIZE];
    const char                 *separator;
    CXCompilationDatabase_Error database_error;
    CXCompilationDatabase       database;
    CXCompileCommands           commands;
    unsigned                    command_count;
    unsigned                    command_index;
    bool                        result;
    size_t                      database_path_length;
    bool                        has_error;

    P101_TRACE_SCOPE(env);
    database_path_length = 0U;
    if(options->compile_database != NULL)
    {
        database_path_length = p101_strlen(env, options->compile_database);
    }
    if(options->compile_database == NULL || database_path_length >= sizeof(database_directory))
    {
        P101_ERROR_RAISE_USER(err, "The compilation-database path is too long.", 1);
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    p101_snprintf(env, err, database_directory, sizeof(database_directory), "%s", options->compile_database);
    has_error = p101_error_has_error(err);
    if(has_error)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    separator = p101_strrchr(env, database_directory, '/');
    if(separator == NULL)
    {
        p101_snprintf(env, err, database_directory, sizeof(database_directory), ".");
    }
    else if(separator == database_directory)
    {
        /*
         * "/compile_commands.json" lives in the root directory; truncating at
         * the separator would leave an empty, unopenable directory name.
         */
        p101_snprintf(env, err, database_directory, sizeof(database_directory), "/");
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
    result        = true;
    for(command_index = 0U; command_index < command_count; command_index++)
    {
        CXCompileCommand command;
        char            *source;
        char            *directory;
        char           **arguments;
        unsigned         argument_count;
        unsigned         argument_index;
        CXString         source_value;
        CXString         directory_value;
        bool             command_has_error;
        void            *allocation;

        command         = clang_CompileCommands_getCommand(commands, command_index);
        source_value    = clang_CompileCommand_getFilename(command);
        source          = copy_cx_string(env, err, source_value);
        directory_value = clang_CompileCommand_getDirectory(command);
        directory       = copy_cx_string(env, err, directory_value);
        argument_count  = clang_CompileCommand_getNumArgs(command);
        allocation      = p101_calloc(env, err, argument_count, sizeof(*arguments));
        arguments       = (char **)allocation;
        if(source == NULL || directory == NULL || arguments == NULL)
        {
            p101_free(env, (void *)arguments);
            p101_free(env, directory);
            p101_free(env, source);
            result = false;
            break;
        }
        for(argument_index = 0U; argument_index < argument_count; argument_index++)
        {
            CXString argument_value;

            argument_value            = clang_CompileCommand_getArg(command, argument_index);
            arguments[argument_index] = copy_cx_string(env, err, argument_value);
        }
        command_has_error = p101_error_has_error(err);
        if(command_has_error)
        {
            result = false;
        }
        else
        {
            bool admitted;
            bool source_path;

            admitted    = path_is_admitted(session, source);
            source_path = path_has_source_suffix(env, source);
            if(admitted && source_path)
            {
                const char *const *argument_view;

                argument_view = (const char *const *)arguments;
                result        = scan_source(env, err, options, session, observer, observer_context, source, directory, argument_view, argument_count);
            }
        }
        for(argument_index = 0U; argument_index < argument_count; argument_index++)
        {
            p101_free(env, arguments[argument_index]);
        }
        p101_free(env, (void *)arguments);
        p101_free(env, directory);
        p101_free(env, source);
        if(!result)
        {
            break;
        }
    }
    clang_CompileCommands_dispose(commands);
    clang_CompilationDatabase_dispose(database);
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

bool p101_c_analysis_scan(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *context)
{
    bool                           p101_single_result_;
    struct p101_c_analysis_options normalized;
    const char                   **normalized_paths;
    analysis_path                 *path_storage;
    bool                           result;
    size_t                         index;
    void                          *allocation;
    struct analysis_session        session;

    P101_TRACE_SCOPE(env);
    P101_WRAPPER_FAULT_SCOPE_RETURN(env, err, result, false);
    if(options == NULL || observer == NULL || options->paths == NULL || options->path_count == 0U)
    {
        P101_ERROR_RAISE_CHECK(err);
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    for(index = 0U; index < options->path_count; index++)
    {
        if(options->paths[index] == NULL)
        {
            P101_ERROR_RAISE_CHECK(err);
            p101_single_result_ = false;
            goto p101_single_exit_;
        }
    }

    allocation       = p101_calloc(env, err, options->path_count, sizeof(*normalized_paths));
    normalized_paths = (const char **)allocation;
    allocation       = p101_calloc(env, err, options->path_count, sizeof(*path_storage));
    path_storage     = (analysis_path *)allocation;
    if(normalized_paths == NULL || path_storage == NULL)
    {
        p101_free(env, path_storage);
        p101_free(env, (void *)normalized_paths);
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    normalized = *options;
    for(index = 0U; index < options->path_count; index++)
    {
        const char *resolved_path;

        /* P101_ERROR_OPTIONAL rationale: a missing path remains literal. */
        resolved_path = p101_realpath(env, P101_ERROR_OPTIONAL, options->paths[index], path_storage[index]);
        if(resolved_path != NULL)
        {
            normalized_paths[index] = path_storage[index];
        }
        else
        {
            normalized_paths[index] = options->paths[index];
        }
    }
    normalized.paths = normalized_paths;
    p101_memset(env, &session, 0, sizeof(session));
    session.env     = env;
    session.err     = err;
    session.options = &normalized;

    if(normalized.compile_database != NULL)
    {
        result = scan_compile_database(env, err, &normalized, &session, observer, context);
    }
    else
    {
        result = true;
        for(index = 0U; index < normalized.path_count && result; index++)
        {
            struct stat status;
            const char *path;
            int         status_result;

            path          = normalized.paths[index];
            status_result = p101_stat(env, err, path, &status);
            if(status_result != 0)
            {
                result = false;
            }
            else
            {
                bool directory_path;
                bool regular_path;
                bool source_path;
                bool header_path;

                directory_path = S_ISDIR(status.st_mode);
                regular_path   = S_ISREG(status.st_mode);
                source_path    = path_has_source_suffix(env, path);
                header_path    = path_has_header_suffix(env, path);
                if(directory_path)
                {
                    result = scan_directory(env, err, &normalized, &session, observer, context, path);
                }
                else if(regular_path && (source_path || header_path))
                {
                    const char *default_arguments[] = {"clang", "-D_POSIX_C_SOURCE=200809L", "-D_XOPEN_SOURCE=700"};
                    size_t      default_argument_count;

                    default_argument_count = sizeof(default_arguments) / sizeof(default_arguments[0]);
                    result                 = scan_source(env, err, &normalized, &session, observer, context, path, NULL, default_arguments, default_argument_count);
                }
            }
        }
    }
    path_admission_cache_destroy(&session);
    p101_free(env, path_storage);
    p101_free(env, (void *)normalized_paths);
    P101_WRAPPER_SCOPE_DONE();
    {
        bool has_no_error;

        has_no_error = p101_error_has_no_error(err);
        if(result && has_no_error)
        {
            p101_single_result_ = true;
            goto p101_single_exit_;
        }
    }
    p101_single_result_ = false;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

const char *p101_c_analysis_kind_name(enum p101_c_analysis_kind kind)
{
    const char              *p101_single_result_;
    static const char *const names[] = {"FILE", "INCLUDE", "FUNCTION", "PARAMETER", "CALL", "TYPE", "ENUM", "ENUMERATOR", "MACRO", "NOTE", "MUTATION", "DIAGNOSTIC"};

    if(kind < P101_C_ANALYSIS_FILE || kind > P101_C_ANALYSIS_DIAGNOSTIC)
    {
        p101_single_result_ = "UNKNOWN";
        goto p101_single_exit_;
    }
    p101_single_result_ = names[kind];
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

const char *p101_c_mutation_kind_name(enum p101_c_mutation_kind kind)
{
    const char              *p101_single_result_;
    static const char *const names[] = {"none", "comparison-boundary", "logical-connective", "arithmetic-operator", "error-predicate", "skip-call"};

    if(kind < P101_C_MUTATION_NONE || kind > P101_C_MUTATION_SKIP_CALL)
    {
        p101_single_result_ = "unknown";
        goto p101_single_exit_;
    }
    p101_single_result_ = names[kind];
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

bool p101_c_mutation_kind_from_name(const struct p101_env *env, const char *name, enum p101_c_mutation_kind *kind)
{
    bool p101_single_result_;
    int  value;

    P101_TRACE_SCOPE(env);
    p101_single_result_ = false;
    if(name == NULL || kind == NULL)
    {
        goto p101_single_exit_;
    }
    for(value = P101_C_MUTATION_NONE; value <= P101_C_MUTATION_SKIP_CALL; value++)
    {
        const char *candidate;
        int         comparison;

        candidate  = p101_c_mutation_kind_name((enum p101_c_mutation_kind)value);
        comparison = p101_strcmp(env, name, candidate);
        if(comparison == 0)
        {
            *kind               = (enum p101_c_mutation_kind)value;
            p101_single_result_ = true;
            break;
        }
    }
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}
