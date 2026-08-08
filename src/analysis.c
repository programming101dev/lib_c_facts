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
    ANALYSIS_PATH_SIZE      = 4096,
    ANALYSIS_NAME_SIZE      = 256,
    ANALYSIS_IDENTITY_SIZE  = 4096,
    ANALYSIS_MAX_ARGUMENTS  = 1024,
    NULL_POINTER_CAST_DEPTH = 8
};

static const char P101_ENV_TYPE_USR[]   = "c:@S@p101_env";
static const char P101_ERROR_TYPE_USR[] = "c:@S@p101_error";

typedef char analysis_path[ANALYSIS_PATH_SIZE];

struct cursor_ancestry
{
    CXCursor                      cursor;
    const struct cursor_ancestry *parent;
};

struct scan_context
{
    const struct p101_env                *env;
    struct p101_error                    *err;
    const struct p101_c_analysis_options *options;
    p101_c_analysis_observer              observer;
    void                                 *observer_context;
    CXTranslationUnit                     translation_unit;
    const char                           *current_function;
    const char                           *current_function_usr;
    char                                  current_enum[ANALYSIS_NAME_SIZE];
    char                                  current_enum_usr[ANALYSIS_IDENTITY_SIZE];
    char                                  pending_error_identity[ANALYSIS_IDENTITY_SIZE];
    char                                  checked_error_identity[ANALYSIS_IDENTITY_SIZE];
    unsigned                              conditional_depth;
    size_t                                final_return_start;
    CXCursor                              final_return_label;
    bool                                  conditional_has_return;
    bool                                  inside_return;
    bool                                  stopped;
    bool                                  had_parse_failure;
    const struct cursor_ancestry         *ancestry;
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

static bool path_is_admitted(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, const char *path);
static bool path_has_source_suffix(const struct p101_env *env, const char *path);
static bool path_has_header_suffix(const struct p101_env *env, const char *path);
static bool scan_source(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context, const char *source, const char *directory, const char *const arguments[],
                        size_t argument_count);
static bool scan_directory(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context, const char *directory);
static bool scan_compile_database(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context);
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
static bool                    semantic_role_function_name(const struct p101_env *env, CXTranslationUnit translation_unit, const char *role, char *name, size_t name_size);
static void                    emit_function_semantic_roles(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *function);
static void                    emit_callee_semantic_roles(struct scan_context *context, CXCursor cursor, const struct p101_c_analysis_record *call);
static bool                    function_is_error_state_query(const struct p101_env *env, CXCursor cursor);
static size_t                  function_final_return_start(CXCursor cursor, CXCursor *label);
static bool                    call_discards_error(CXCursor cursor, unsigned argument_index);
static bool                    cursor_is_null_pointer_constant(CXCursor cursor);
static bool                    call_uses_optional_error(const struct p101_env *env, CXCursor cursor, unsigned argument_index);
static bool                    call_is_generated_by_macro(CXCursor cursor);
static bool                    call_is_isolated(struct scan_context *context, CXCursor cursor, CXCursor parent);
static bool                    binary_parent_is_simple_assignment(CXCursor parent);
static char                   *cursor_argument_identity(const struct p101_env *env, struct p101_error *err, CXCursor cursor, unsigned index);
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

static bool path_is_admitted(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, const char *path)
{
    bool        p101_single_result_;
    size_t      index;
    char        actual[ANALYSIS_PATH_SIZE];
    const char *resolved;
    int         comparison;

    P101_TRACE_SCOPE(env);
    resolved = NULL;
    if(path != NULL && path[0] != '\0')
    {
        resolved = p101_realpath(env, err, path, actual);
    }
    if(resolved == NULL)
    {
        p101_single_result_ = false;
        goto p101_single_exit_;
    }
    for(index = 0; index < options->path_count; index++)
    {
        const char *root;
        size_t      length;

        root = options->paths[index];
        if(root == NULL)
        {
            continue;
        }
        length     = p101_strlen(env, root);
        comparison = p101_strncmp(env, actual, root, length);
        if(comparison == 0 && (actual[length] == '\0' || actual[length] == '/'))
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

struct optional_error_context
{
    const struct p101_env *env;
    bool                   found;
};

static enum CXChildVisitResult find_optional_error_call(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct optional_error_context *context;
    enum CXChildVisitResult        result;
    enum CXCursorKind              kind;

    context = (struct optional_error_context *)client_data;
    result  = CXChildVisit_Recurse;
    kind    = clang_getCursorKind(cursor);
    if(kind == CXCursor_CallExpr)
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
    visit_result   = find_optional_error_call(visitor_cursor, visitor_parent, &context);
    (void)visit_result;
    if(!context.found)
    {
        clang_visitChildren(argument, find_optional_error_call, &context);
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

static void emit_cursor_record(struct scan_context *context, CXCursor cursor, CXCursor parent)
{
    enum CXCursorKind             cursor_kind;
    struct p101_c_analysis_record record;
    char                         *path;
    char                         *name;
    char                         *type;
    char                         *return_type;
    char                         *usr;
    size_t                        line;
    size_t                        column;
    bool                          admitted;
    bool                          emitted;

    cursor_kind = clang_getCursorKind(cursor);
    p101_memset(context->env, &record, 0, sizeof(record));
    path        = NULL;
    name        = NULL;
    type        = NULL;
    return_type = NULL;
    usr         = NULL;
    cursor_location(context->env, context->err, cursor, &path, &line, &column, &record.start_offset);
    admitted = false;
    if(path != NULL)
    {
        admitted = path_is_admitted(context->env, context->err, context->options, path);
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
                    local_include = path_is_admitted(context->env, context->err, context->options, resolved);
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
            referenced              = clang_getCursorReferenced(cursor);
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
                isolated  = call_is_isolated(context, cursor, parent);
                if(!generated && !isolated)
                {
                    emit_note(context, path, line, column, record.start_offset, record.end_offset, record.is_header, "CALL_NOT_ISOLATED");
                }
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
                }
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
        }
        else if(cursor_kind == CXCursor_ParmDecl || cursor_kind == CXCursor_VarDecl || cursor_kind == CXCursor_MemberRefExpr)
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
            emit_mutation_record(context, cursor, parent, path, line, column);
        }
    }

p101_single_exit_:
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
    size_t                        saved_final_return_start;
    CXCursor                      saved_final_return_label;
    unsigned                      saved_conditional_depth;
    char                          saved_pending_error_identity[ANALYSIS_IDENTITY_SIZE];
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

    context                      = (struct scan_context *)client_data;
    saved_function               = context->current_function;
    saved_function_usr           = context->current_function_usr;
    saved_inside_return          = context->inside_return;
    saved_final_return_start     = context->final_return_start;
    saved_final_return_label     = context->final_return_label;
    saved_conditional_depth      = context->conditional_depth;
    saved_conditional_has_return = context->conditional_has_return;
    p101_snprintf(context->env, context->err, saved_pending_error_identity, sizeof(saved_pending_error_identity), "%s", context->pending_error_identity);
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
        context->conditional_has_return    = false;
        context->pending_error_identity[0] = '\0';
        context->checked_error_identity[0] = '\0';
    }
    is_function   = cursor_kind_is_function(kind);
    is_definition = cursor_is_definition(cursor);
    if(is_function && is_definition)
    {
        CXString spelling;
        CXString usr;

        function_scope                     = true;
        spelling                           = clang_getCursorSpelling(cursor);
        function_name                      = copy_cx_string(context->env, context->err, spelling);
        usr                                = clang_getCursorUSR(cursor);
        function_usr                       = copy_cx_string(context->env, context->err, usr);
        context->current_function          = function_name;
        context->current_function_usr      = function_usr;
        context->final_return_start        = function_final_return_start(cursor, &context->final_return_label);
        context->pending_error_identity[0] = '\0';
        context->checked_error_identity[0] = '\0';
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
    context->ancestry             = saved_ancestry;
    context->current_function     = saved_function;
    context->current_function_usr = saved_function_usr;
    context->inside_return        = saved_inside_return;
    context->final_return_start   = saved_final_return_start;
    context->final_return_label   = saved_final_return_label;
    context->conditional_depth    = saved_conditional_depth;
    p101_snprintf(context->env, context->err, context->current_enum, sizeof(context->current_enum), "%s", saved_enum);
    p101_snprintf(context->env, context->err, context->current_enum_usr, sizeof(context->current_enum_usr), "%s", saved_enum_usr);
    if(function_scope)
    {
        p101_snprintf(context->env, context->err, context->pending_error_identity, sizeof(context->pending_error_identity), "%s", saved_pending_error_identity);
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
        admitted = path_is_admitted(context->env, context->err, context->options, path);
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

static bool scan_source(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context, const char *source, const char *directory, const char *const arguments[],
                        size_t argument_count)
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
        visit_status            = clang_visitChildren(translation_unit_cursor, visit_cursor, &context);
        (void)visit_status;
    }
    result       = false;
    has_no_error = p101_error_has_no_error(err);
    if(!context.stopped && has_no_error)
    {
        result = true;
    }
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

static bool scan_directory(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context, const char *directory)    // NOLINT(misc-no-recursion)
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
            scan_result = scan_directory(env, err, options, observer, observer_context, path);
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
            scan_result            = scan_source(env, err, options, observer, observer_context, path, directory, default_arguments, default_argument_count);
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
        int close_status;

        close_status = p101_closedir(env, err, stream);
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

static bool scan_compile_database(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context)
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

            admitted    = path_is_admitted(env, err, options, source);
            source_path = path_has_source_suffix(env, source);
            if(admitted && source_path)
            {
                const char *const *argument_view;

                argument_view = (const char *const *)arguments;
                result        = scan_source(env, err, options, observer, observer_context, source, directory, argument_view, argument_count);
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

    if(normalized.compile_database != NULL)
    {
        result = scan_compile_database(env, err, &normalized, observer, context);
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
                    result = scan_directory(env, err, &normalized, observer, context, path);
                }
                else if(regular_path && (source_path || header_path))
                {
                    const char *default_arguments[] = {"clang", "-D_POSIX_C_SOURCE=200809L", "-D_XOPEN_SOURCE=700"};
                    size_t      default_argument_count;

                    default_argument_count = sizeof(default_arguments) / sizeof(default_arguments[0]);
                    result                 = scan_source(env, err, &normalized, observer, context, path, NULL, default_arguments, default_argument_count);
                }
            }
        }
    }
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
    static const char *const names[] = {"FILE", "INCLUDE", "FUNCTION", "CALL", "TYPE", "ENUM", "ENUMERATOR", "MACRO", "NOTE", "MUTATION", "DIAGNOSTIC"};

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
