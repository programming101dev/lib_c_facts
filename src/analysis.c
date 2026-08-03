#include "p101_c_facts/analysis.h"
#include <clang-c/CXCompilationDatabase.h>
#include <clang-c/Index.h>
#include <dirent.h>
#include <limits.h>
#include <p101_c/p101_stdio.h>
#include <p101_c/p101_stdlib.h>
#include <p101_c/p101_string.h>
#include <p101_filesystem/filesystem.h>
#include <stdint.h>
#include <sys/stat.h>

enum
{
    ANALYSIS_PATH_SIZE     = 4096,
    ANALYSIS_NAME_SIZE     = 256,
    ANALYSIS_MAX_ARGUMENTS = 1024,
    NULL_ARGUMENT_SIZE     = 64,
    ANNOTATION_WINDOW_SIZE = 512
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
    char                                  pending_error_argument[ANALYSIS_NAME_SIZE];
    char                                  checked_error_argument[ANALYSIS_NAME_SIZE];
    unsigned                              conditional_depth;
    bool                                  conditional_has_return;
    bool                                  inside_return;
    bool                                  stopped;
    bool                                  had_parse_failure;
};

struct inclusion_context
{
    struct scan_context *scan;
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
static void                    emit_mutation_record(struct scan_context *context, CXCursor cursor, CXCursor parent, const char *path, size_t line, size_t column);
static bool                    emit_record(struct scan_context *context, const struct p101_c_analysis_record *record);
static char                   *copy_cx_string(const struct p101_env *env, struct p101_error *err, CXString value);
static char                   *copy_text(const struct p101_env *env, struct p101_error *err, const char *text);
static char                   *source_range_text(const struct p101_env *env, struct p101_error *err, const char *path, size_t start, size_t end);
static char                   *include_target_text(const struct p101_env *env, struct p101_error *err, CXCursor cursor, const char *path, bool *is_local);
static void                    cursor_location(const struct p101_env *env, struct p101_error *err, CXCursor cursor, char **path, size_t *line, size_t *column, size_t *offset);
static bool                    cursor_is_definition(CXCursor cursor);
static int                     function_parameter_index(const struct p101_env *env, CXCursor cursor, const char *needle);
static bool                    cursor_type_contains(const struct p101_env *env, CXCursor cursor, const char *needle);
static bool                    call_discards_error(const struct p101_env *env, struct p101_error *err, CXCursor cursor, unsigned argument_index, const char *path);
static char                   *cursor_argument_text(const struct p101_env *env, struct p101_error *err, CXCursor cursor, unsigned index, const char *path);
static bool                    source_near_cursor_contains(const struct p101_env *env, struct p101_error *err, CXCursor cursor, const char *path, const char *needle);
static void                    emit_note(struct scan_context *context, const char *path, size_t line, size_t column, bool is_header, const char *name);
static void                    cursor_extent_offsets(CXCursor cursor, size_t *start, size_t *end);
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
    size_t length;

    P101_TRACE_SCOPE(env);
    if(text == NULL)
    {
        text = "";
    }
    length = p101_strlen(env, text);
    copy   = (char *)p101_malloc(env, err, length + 1U);
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
    size_t path_length;
    size_t suffix_length;

    P101_TRACE_SCOPE(env);
    path_length   = p101_strlen(env, path);
    suffix_length = p101_strlen(env, suffix);
    if(path_length < suffix_length)
    {
        return false;
    }
    return p101_strcmp(env, path + path_length - suffix_length, suffix) == 0;
}

static bool path_has_source_suffix(const struct p101_env *env, const char *path)
{
    P101_TRACE_SCOPE(env);
    if(has_suffix(env, path, ".c") || has_suffix(env, path, ".cc") || has_suffix(env, path, ".cpp") || has_suffix(env, path, ".cxx") || has_suffix(env, path, ".m") || has_suffix(env, path, ".mm"))
    {
        return true;
    }
    return false;
}

static bool path_has_header_suffix(const struct p101_env *env, const char *path)
{
    P101_TRACE_SCOPE(env);
    if(has_suffix(env, path, ".h") || has_suffix(env, path, ".hh") || has_suffix(env, path, ".hpp") || has_suffix(env, path, ".hxx"))
    {
        return true;
    }
    return false;
}

static bool path_is_admitted(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, const char *path)
{
    size_t index;
    char   actual[ANALYSIS_PATH_SIZE];

    P101_TRACE_SCOPE(env);
    if(path == NULL || path[0] == '\0' || p101_realpath(env, err, path, actual) == NULL)
    {
        return false;
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
        length = p101_strlen(env, root);
        if(p101_strncmp(env, actual, root, length) == 0 && (actual[length] == '\0' || actual[length] == '/'))
        {
            return true;
        }
    }
    return false;
}

static bool emit_record(struct scan_context *context, const struct p101_c_analysis_record *record)
{
    bool keep_going;

    keep_going = context->observer(context->env, context->err, record, context->observer_context);
    if(!keep_going || p101_error_has_error(context->err))
    {
        context->stopped = true;
        return false;
    }
    return true;
}

static void cursor_location(const struct p101_env *env, struct p101_error *err, CXCursor cursor, char **path, size_t *line, size_t *column, size_t *offset)
{
    CXFile   file;
    CXString name;
    unsigned raw_line;
    unsigned raw_column;
    unsigned raw_offset;

    *path = NULL;
    /*
     * Attribute facts to the source that invoked a macro, not to the header
     * that defines it.  Wrapper instrumentation is intentionally expressed
     * through macros such as P101_TRACE and P101_*_FAULT_RETURN; using the
     * spelling location made those calls disappear when the admitted roots
     * excluded lib_env's headers.
     */
    clang_getExpansionLocation(clang_getCursorLocation(cursor), &file, &raw_line, &raw_column, &raw_offset);
    *line   = raw_line;
    *column = raw_column;
    *offset = raw_offset;
    if(file == NULL)
    {
        return;
    }
    name  = clang_getFileName(file);
    *path = copy_cx_string(env, err, name);
}

static bool cursor_is_definition(CXCursor cursor)
{
    return clang_isCursorDefinition(cursor) != 0U;
}

static int function_parameter_index(const struct p101_env *env, CXCursor cursor, const char *needle)
{
    int index;
    int count;

    count = clang_Cursor_getNumArguments(cursor);
    for(index = 0; index < count; index++)
    {
        CXCursor    argument;
        CXString    spelling;
        const char *type_text;

        argument  = clang_Cursor_getArgument(cursor, (unsigned)index);
        spelling  = clang_getTypeSpelling(clang_getCursorType(argument));
        type_text = clang_getCString(spelling);
        if(type_text != NULL && p101_strstr(env, type_text, needle) != NULL)
        {
            clang_disposeString(spelling);
            return index;
        }
        clang_disposeString(spelling);
    }
    return -1;
}

static bool cursor_type_contains(const struct p101_env *env, CXCursor cursor, const char *needle)
{
    CXString    spelling;
    const char *type_text;
    bool        result;

    spelling  = clang_getTypeSpelling(clang_getCursorType(cursor));
    type_text = clang_getCString(spelling);
    result    = false;
    if(type_text != NULL && p101_strstr(env, type_text, needle) != NULL)
    {
        result = true;
    }
    clang_disposeString(spelling);
    return result;
}

static bool call_discards_error(const struct p101_env *env, struct p101_error *err, CXCursor cursor, unsigned argument_index, const char *path)
{
    CXCursor     argument;
    CXEvalResult evaluation;
    char        *text;
    char         normalized[NULL_ARGUMENT_SIZE];
    size_t       read_index;
    size_t       write_index;

    if(argument_index >= (unsigned)clang_Cursor_getNumArguments(cursor))
    {
        return false;
    }
    argument = clang_Cursor_getArgument(cursor, argument_index);
    if(clang_getCursorKind(argument) == CXCursor_IntegerLiteral || clang_getCursorKind(argument) == CXCursor_CXXNullPtrLiteralExpr)
    {
        return true;
    }
    evaluation = clang_Cursor_Evaluate(argument);
    if(evaluation != NULL)
    {
        CXEvalResultKind kind;

        kind = clang_EvalResult_getKind(evaluation);
        if(kind == CXEval_Int && clang_EvalResult_getAsLongLong(evaluation) == 0)
        {
            clang_EvalResult_dispose(evaluation);
            return true;
        }
        clang_EvalResult_dispose(evaluation);
    }
    text = cursor_argument_text(env, err, cursor, argument_index, path);
    if(text == NULL)
    {
        return false;
    }
    write_index = 0U;
    for(read_index = 0U; text[read_index] != '\0' && write_index + 1U < sizeof(normalized); read_index++)
    {
        char current;

        current = text[read_index];
        if(current != ' ' && current != '\t' && current != '\n' && current != '\r')
        {
            normalized[write_index++] = current;
        }
    }
    normalized[write_index] = '\0';
    p101_free(env, text);
    if(p101_strcmp(env, normalized, "NULL") == 0 || p101_strcmp(env, normalized, "nullptr") == 0 || p101_strcmp(env, normalized, "0") == 0 || p101_strcmp(env, normalized, "(void*)0") == 0 || p101_strcmp(env, normalized, "((void*)0)") == 0)
    {
        return true;
    }
    return false;
}

static char *cursor_argument_text(const struct p101_env *env, struct p101_error *err, CXCursor cursor, unsigned index, const char *path)
{
    CXCursor      argument;
    CXSourceRange range;
    CXFile        file;
    unsigned      line;
    unsigned      column;
    unsigned      start;
    unsigned      end;

    if(index >= (unsigned)clang_Cursor_getNumArguments(cursor))
    {
        return NULL;
    }
    argument = clang_Cursor_getArgument(cursor, index);
    range    = clang_getCursorExtent(argument);
    clang_getExpansionLocation(clang_getRangeStart(range), &file, &line, &column, &start);
    clang_getExpansionLocation(clang_getRangeEnd(range), &file, &line, &column, &end);
    if(file == NULL || end < start)
    {
        return NULL;
    }
    return source_range_text(env, err, path, start, end);
}

static bool source_near_cursor_contains(const struct p101_env *env, struct p101_error *err, CXCursor cursor, const char *path, const char *needle)
{
    CXSourceRange range;
    CXFile        file;
    unsigned      line;
    unsigned      column;
    unsigned      start;
    unsigned      end;
    size_t        window_start;
    size_t        window_end;
    char         *text;
    bool          found;
    struct stat   status;

    range = clang_getCursorExtent(cursor);
    clang_getExpansionLocation(clang_getRangeStart(range), &file, &line, &column, &start);
    clang_getExpansionLocation(clang_getRangeEnd(range), &file, &line, &column, &end);
    if(file == NULL || end < start)
    {
        return false;
    }
    if(p101_stat(env, err, path, &status) != 0 || status.st_size < 0)
    {
        return false;
    }
    window_start = start > ANNOTATION_WINDOW_SIZE ? start - ANNOTATION_WINDOW_SIZE : 0U;
    window_end   = (size_t)end + ANNOTATION_WINDOW_SIZE;
    if(window_end > (size_t)status.st_size)
    {
        window_end = (size_t)status.st_size;
    }
    text = source_range_text(env, err, path, window_start, window_end);
    if(text == NULL)
    {
        return false;
    }
    found = p101_strstr(env, text, needle) != NULL;
    p101_free(env, text);
    return found;
}

static void emit_note(struct scan_context *context, const char *path, size_t line, size_t column, bool is_header, const char *name)
{
    struct p101_c_analysis_record record;

    p101_memset(context->env, &record, 0, sizeof(record));
    record.kind      = P101_C_ANALYSIS_NOTE;
    record.path      = path;
    record.line      = line;
    record.column    = column;
    record.name      = name;
    record.caller    = context->current_function;
    record.is_header = is_header;
    (void)emit_record(context, &record);
}

static void cursor_extent_offsets(CXCursor cursor, size_t *start, size_t *end)
{
    CXSourceRange range;
    unsigned      start_offset;
    unsigned      end_offset;

    range = clang_getCursorExtent(cursor);
    clang_getExpansionLocation(clang_getRangeStart(range), NULL, NULL, NULL, &start_offset);
    clang_getExpansionLocation(clang_getRangeEnd(range), NULL, NULL, NULL, &end_offset);
    *start = start_offset;
    *end   = end_offset;
}

static void emit_cursor_record(struct scan_context *context, CXCursor cursor, CXCursor parent)
{
    enum CXCursorKind             cursor_kind;
    struct p101_c_analysis_record record;
    char                         *path;
    char                         *name;
    char                         *type;
    char                         *return_type;
    size_t                        line;
    size_t                        column;

    cursor_kind = clang_getCursorKind(cursor);
    p101_memset(context->env, &record, 0, sizeof(record));
    path        = NULL;
    name        = NULL;
    type        = NULL;
    return_type = NULL;
    cursor_location(context->env, context->err, cursor, &path, &line, &column, &record.start_offset);
    if(path == NULL || !path_is_admitted(context->env, context->err, context->options, path))
    {
        p101_free(context->env, path);
        return;
    }

    record.path      = path;
    record.line      = line;
    record.column    = column;
    record.is_header = path_has_header_suffix(context->env, path);
    cursor_extent_offsets(cursor, &record.start_offset, &record.end_offset);

    if(cursor_kind == CXCursor_InclusionDirective)
    {
        bool local_include;

        record.kind = P101_C_ANALYSIS_INCLUDE;
        name        = include_target_text(context->env, context->err, cursor, path, &local_include);
        record.name = name;
        if(name == NULL)
        {
            context->stopped = p101_error_has_error(context->err);
        }
        else
        {
            record.is_local_include = local_include;
            (void)emit_record(context, &record);
        }
    }
    else if(cursor_kind == CXCursor_FunctionDecl || cursor_kind == CXCursor_CXXMethod || cursor_kind == CXCursor_Constructor || cursor_kind == CXCursor_Destructor)
    {
        record.kind = P101_C_ANALYSIS_FUNCTION;
        name        = copy_cx_string(context->env, context->err, clang_getCursorSpelling(cursor));
        type        = copy_cx_string(context->env, context->err, clang_getTypeSpelling(clang_getCursorType(cursor)));
        return_type = copy_cx_string(context->env, context->err, clang_getTypeSpelling(clang_getCursorResultType(cursor)));
        if(name == NULL || type == NULL || return_type == NULL)
        {
            context->stopped = true;
        }
        record.name          = name;
        record.type          = type;
        record.return_type   = return_type;
        record.is_definition = cursor_is_definition(cursor);
        record.is_static     = clang_Cursor_getStorageClass(cursor) == CX_SC_Static;
        record.is_public     = true;
        if(record.is_static)
        {
            record.is_public = false;
        }
        record.is_variadic         = clang_Cursor_isVariadic(cursor) != 0U;
        record.has_env_parameter   = function_parameter_index(context->env, cursor, "p101_env") >= 0;
        record.has_error_parameter = function_parameter_index(context->env, cursor, "p101_error") >= 0;
        if(!context->stopped)
        {
            (void)emit_record(context, &record);
        }
        if(record.has_env_parameter && !context->stopped)
        {
            emit_note(context, path, line, column, record.is_header, "ENV_CONTRACT");
        }
        if(record.has_error_parameter && !context->stopped)
        {
            emit_note(context, path, line, column, record.is_header, "ERROR_CONTRACT");
        }
    }
    else if(cursor_kind == CXCursor_CallExpr)
    {
        CXCursor referenced;
        char    *error_argument;
        bool     is_error_check;
        bool     discarded_error;

        record.kind     = P101_C_ANALYSIS_CALL;
        record.caller   = context->current_function;
        referenced      = clang_getCursorReferenced(cursor);
        error_argument  = NULL;
        is_error_check  = false;
        discarded_error = false;
        if(clang_Cursor_isNull(referenced) != 0)
        {
            name               = copy_cx_string(context->env, context->err, clang_getCursorSpelling(cursor));
            record.is_indirect = true;
        }
        else
        {
            name               = copy_cx_string(context->env, context->err, clang_getCursorSpelling(referenced));
            record.is_indirect = clang_getCursorKind(referenced) != CXCursor_FunctionDecl;
            type               = copy_cx_string(context->env, context->err, clang_getTypeSpelling(clang_getCursorType(referenced)));
        }
        record.name = name;
        record.type = type;
        if(name == NULL || (clang_Cursor_isNull(referenced) == 0 && type == NULL))
        {
            context->stopped = true;
        }
        if(clang_Cursor_isNull(referenced) == 0)
        {
            int env_index;
            int error_index;

            env_index                  = function_parameter_index(context->env, referenced, "p101_env");
            error_index                = function_parameter_index(context->env, referenced, "p101_error");
            record.has_env_parameter   = env_index >= 0;
            record.has_error_parameter = error_index >= 0;
        }
        if(record.has_error_parameter)
        {
            int error_index;

            error_index           = function_parameter_index(context->env, referenced, "p101_error");
            error_argument        = cursor_argument_text(context->env, context->err, cursor, (unsigned)error_index, path);
            record.error_argument = error_argument;
        }
        if(!context->stopped)
        {
            (void)emit_record(context, &record);
        }
        if(!context->stopped && name != NULL && (p101_strncmp(context->env, name, "p101_error_has_", sizeof("p101_error_has_") - 1U) == 0 || p101_strncmp(context->env, name, "p101_error_is_", sizeof("p101_error_is_") - 1U) == 0))
        {
            char *checked_argument;

            is_error_check = true;
            emit_note(context, path, line, column, record.is_header, "ERROR_CHECK");
            checked_argument = cursor_argument_text(context->env, context->err, cursor, 0U, path);
            if(checked_argument != NULL && p101_strcmp(context->env, context->pending_error_argument, checked_argument) == 0)
            {
                context->pending_error_argument[0] = '\0';
            }
            if(checked_argument != NULL)
            {
                p101_snprintf(context->env, context->err, context->checked_error_argument, sizeof(context->checked_error_argument), "%s", checked_argument);
            }
            p101_free(context->env, checked_argument);
        }
        if(!context->stopped && record.has_error_parameter)
        {
            int error_index;

            error_index     = function_parameter_index(context->env, referenced, "p101_error");
            discarded_error = call_discards_error(context->env, context->err, cursor, (unsigned)error_index, path);
            if(discarded_error)
            {
                emit_note(context, path, line, column, record.is_header, "ERROR_DISCARD");
            }
            if(source_near_cursor_contains(context->env, context->err, cursor, path, "P101_ERROR_CONTRACT_ALLOW_NO_ERROR"))
            {
                emit_note(context, path, line, column, record.is_header, "ERROR_OPTIONAL");
            }
        }
        if(!context->stopped && context->inside_return)
        {
            emit_note(context, path, line, column, record.is_header, "ERROR_PROPAGATED");
        }
        if(!context->stopped && !is_error_check && !discarded_error && context->conditional_depth == 0U && record.has_error_parameter && error_argument != NULL)
        {
            if(context->pending_error_argument[0] != '\0' && p101_strcmp(context->env, context->pending_error_argument, error_argument) == 0)
            {
                emit_note(context, path, line, column, record.is_header, "ERROR_UNCHECKED_CHAIN");
            }
            p101_snprintf(context->env, context->err, context->pending_error_argument, sizeof(context->pending_error_argument), "%s", error_argument);
        }
        emit_mutation_record(context, cursor, parent, path, line, column);
        p101_free(context->env, error_argument);
    }
    else if(cursor_kind == CXCursor_TypedefDecl || cursor_kind == CXCursor_StructDecl || cursor_kind == CXCursor_UnionDecl || cursor_kind == CXCursor_EnumDecl)
    {
        record.kind = P101_C_ANALYSIS_TYPE;
        name        = copy_cx_string(context->env, context->err, clang_getCursorSpelling(cursor));
        record.name = name;
        if(name == NULL)
        {
            context->stopped = true;
        }
        else if(name[0] != '\0')
        {
            (void)emit_record(context, &record);
        }
    }
    else if(cursor_kind == CXCursor_MacroDefinition)
    {
        record.kind          = P101_C_ANALYSIS_MACRO;
        record.is_definition = true;
        name                 = copy_cx_string(context->env, context->err, clang_getCursorSpelling(cursor));
        record.name          = name;
        if(name == NULL)
        {
            context->stopped = true;
        }
        else
        {
            (void)emit_record(context, &record);
        }
    }
    else if(cursor_kind == CXCursor_MacroExpansion)
    {
        name = copy_cx_string(context->env, context->err, clang_getCursorSpelling(cursor));
        if(name == NULL)
        {
            context->stopped = true;
        }
        else
        {
            record.kind          = P101_C_ANALYSIS_MACRO;
            record.name          = name;
            record.is_definition = false;
            (void)emit_record(context, &record);
            if(!context->stopped && p101_strcmp(context->env, name, "P101_TRACE_SCOPE") == 0)
            {
                emit_note(context, path, line, column, record.is_header, "TRACE_USE");
            }
        }
    }
    else if(cursor_kind == CXCursor_ParmDecl || cursor_kind == CXCursor_VarDecl || cursor_kind == CXCursor_MemberRefExpr)
    {
        if(cursor_type_contains(context->env, cursor, "p101_env"))
        {
            emit_note(context, path, line, column, record.is_header, "ENV_USE");
        }
        if(!context->stopped && cursor_type_contains(context->env, cursor, "p101_error"))
        {
            emit_note(context, path, line, column, record.is_header, "ERROR_USE");
        }
    }
    else if(cursor_kind == CXCursor_BinaryOperator)
    {
        emit_mutation_record(context, cursor, parent, path, line, column);
    }

    p101_free(context->env, return_type);
    p101_free(context->env, type);
    p101_free(context->env, name);
    p101_free(context->env, path);
}

static enum CXChildVisitResult visit_cursor(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    struct scan_context *context;
    enum CXCursorKind    kind;
    const char          *saved_function;
    char                *function_name;
    bool                 saved_inside_return;
    unsigned             saved_conditional_depth;
    char                 saved_pending_error[ANALYSIS_NAME_SIZE];
    char                 saved_checked_error[ANALYSIS_NAME_SIZE];
    bool                 function_scope;
    bool                 conditional_scope;
    bool                 saved_conditional_has_return;

    context                      = (struct scan_context *)client_data;
    saved_function               = context->current_function;
    saved_inside_return          = context->inside_return;
    saved_conditional_depth      = context->conditional_depth;
    saved_conditional_has_return = context->conditional_has_return;
    p101_snprintf(context->env, context->err, saved_pending_error, sizeof(saved_pending_error), "%s", context->pending_error_argument);
    p101_snprintf(context->env, context->err, saved_checked_error, sizeof(saved_checked_error), "%s", context->checked_error_argument);
    function_scope    = false;
    conditional_scope = false;
    function_name     = NULL;
    emit_cursor_record(context, cursor, parent);
    if(context->stopped)
    {
        return CXChildVisit_Break;
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
    if(kind == CXCursor_IfStmt || kind == CXCursor_SwitchStmt || kind == CXCursor_ConditionalOperator || kind == CXCursor_WhileStmt || kind == CXCursor_DoStmt || kind == CXCursor_ForStmt || kind == CXCursor_CXXForRangeStmt)
    {
        conditional_scope = true;
        context->conditional_depth++;
        context->conditional_has_return    = false;
        context->pending_error_argument[0] = '\0';
        context->checked_error_argument[0] = '\0';
    }
    if((kind == CXCursor_FunctionDecl || kind == CXCursor_CXXMethod) && cursor_is_definition(cursor))
    {
        function_scope                     = true;
        function_name                      = copy_cx_string(context->env, context->err, clang_getCursorSpelling(cursor));
        context->current_function          = function_name;
        context->pending_error_argument[0] = '\0';
        context->checked_error_argument[0] = '\0';
    }
    clang_visitChildren(cursor, visit_cursor, context);
    context->current_function  = saved_function;
    context->inside_return     = saved_inside_return;
    context->conditional_depth = saved_conditional_depth;
    if(function_scope)
    {
        p101_snprintf(context->env, context->err, context->pending_error_argument, sizeof(context->pending_error_argument), "%s", saved_pending_error);
        p101_snprintf(context->env, context->err, context->checked_error_argument, sizeof(context->checked_error_argument), "%s", saved_checked_error);
        context->conditional_has_return = saved_conditional_has_return;
    }
    else if(conditional_scope)
    {
        if(context->conditional_has_return && saved_pending_error[0] != '\0' && p101_strcmp(context->env, saved_pending_error, context->checked_error_argument) == 0)
        {
            context->pending_error_argument[0] = '\0';
        }
        else
        {
            p101_snprintf(context->env, context->err, context->pending_error_argument, sizeof(context->pending_error_argument), "%s", saved_pending_error);
        }
        context->conditional_has_return = saved_conditional_has_return;
    }
    p101_free(context->env, function_name);
    if(context->stopped)
    {
        return CXChildVisit_Break;
    }
    return CXChildVisit_Continue;
}

static void visit_inclusion(CXFile included_file, CXSourceLocation *inclusion_stack, unsigned include_length, CXClientData client_data)
{
    struct inclusion_context     *inclusion;
    struct scan_context          *context;
    struct p101_c_analysis_record record;
    CXString                      name;
    char                         *path;

    inclusion = (struct inclusion_context *)client_data;
    context   = inclusion->scan;
    if(context->stopped || included_file == NULL)
    {
        return;
    }
    name = clang_getFileName(included_file);
    path = copy_cx_string(context->env, context->err, name);
    if(path == NULL || !path_is_admitted(context->env, context->err, context->options, path))
    {
        p101_free(context->env, path);
        return;
    }

    p101_memset(context->env, &record, 0, sizeof(record));
    record.kind      = P101_C_ANALYSIS_FILE;
    record.path      = path;
    record.is_header = path_has_header_suffix(context->env, path);
    (void)emit_record(context, &record);

    (void)inclusion_stack;
    (void)include_length;
    p101_free(context->env, path);
}

static char *include_target_text(const struct p101_env *env, struct p101_error *err, CXCursor cursor, const char *path, bool *is_local)
{
    CXSourceRange range;
    CXFile        file;
    unsigned      line;
    unsigned      column;
    unsigned      start;
    unsigned      end;
    char         *text;
    const char   *quote;
    const char   *angle;
    const char   *opening;
    const char   *closing;
    char          closing_character;
    size_t        length;

    P101_TRACE_SCOPE(env);
    *is_local = false;
    range     = clang_getCursorExtent(cursor);
    clang_getSpellingLocation(clang_getRangeStart(range), &file, &line, &column, &start);
    clang_getSpellingLocation(clang_getRangeEnd(range), &file, &line, &column, &end);
    if(file == NULL || end < start)
    {
        return NULL;
    }
    text = source_range_text(env, err, path, start, end);
    if(text == NULL)
    {
        return NULL;
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
        return NULL;
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
        return NULL;
    }
    length = (size_t)(closing - (opening + 1));
    p101_memmove(env, text, opening + 1, length);
    text[length] = '\0';
    return text;
}

static char *source_range_text(const struct p101_env *env, struct p101_error *err, const char *path, size_t start, size_t end)
{
    FILE  *stream;
    char  *text;
    size_t length;
    size_t read_count;

    P101_TRACE_SCOPE(env);
    /*
     * libclang can report an inverted spelling range for calls synthesized
     * from macro expansions. Such a cursor has no safely editable source
     * range, so it is not a mutation candidate; it is not an analysis error.
     */
    if(end < start)
    {
        return NULL;
    }
    if(end - start > SIZE_MAX - 1U)
    {
        P101_ERROR_RAISE_CHECK(err);
        return NULL;
    }
    length = end - start;
    text   = (char *)p101_malloc(env, err, length + 1U);
    if(text == NULL)
    {
        return NULL;
    }
    stream = p101_fopen(env, err, path, "rb");
    if(stream == NULL)
    {
        p101_free(env, text);
        return NULL;
    }
    if(p101_fseek(env, err, stream, (long)start, SEEK_SET) != 0)
    {
        /* P101_ERROR_CONTRACT_ALLOW_NO_ERROR: preserve the seek failure. */
        p101_fclose(env, NULL, stream);
        p101_free(env, text);
        return NULL;
    }
    read_count = p101_fread(env, err, text, 1U, length, stream);
    if(read_count != length || p101_error_has_error(err))
    {
        /* P101_ERROR_CONTRACT_ALLOW_NO_ERROR: preserve the read failure. */
        p101_fclose(env, NULL, stream);
        p101_free(env, text);
        return NULL;
    }
    p101_fclose(env, err, stream);
    if(p101_error_has_error(err))
    {
        p101_free(env, text);
        return NULL;
    }
    text[length] = '\0';
    return text;
}

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

    CXToken *tokens;
    unsigned token_count;
    unsigned index;

    tokens      = NULL;
    token_count = 0U;
    clang_tokenize(context->translation_unit, clang_getCursorExtent(cursor), &tokens, &token_count);
    for(index = 0U; index < token_count && !context->stopped; index++)
    {
        CXString    spelling;
        const char *token_text;
        size_t      replacement_index;

        spelling   = clang_getTokenSpelling(context->translation_unit, tokens[index]);
        token_text = clang_getCString(spelling);
        for(replacement_index = 0U; replacement_index < sizeof(originals) / sizeof(originals[0]); replacement_index++)
        {
            if(token_text != NULL && p101_strcmp(context->env, token_text, originals[replacement_index]) == 0)
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

                range = clang_getTokenExtent(context->translation_unit, tokens[index]);
                clang_getSpellingLocation(clang_getRangeStart(range), &file, &start_line, &start_column, &start_offset);
                clang_getSpellingLocation(clang_getRangeEnd(range), &file, &end_line, &end_column, &end_offset);
                p101_memset(context->env, &record, 0, sizeof(record));
                record.kind         = P101_C_ANALYSIS_MUTATION;
                record.path         = path;
                record.line         = line;
                record.column       = column;
                record.start_offset = start_offset;
                record.end_offset   = end_offset;
                record.name         = originals[replacement_index];
                record.replacement  = replacements[replacement_index];
                record.mutation     = kinds[replacement_index];
                (void)emit_record(context, &record);
                break;
            }
        }
        clang_disposeString(spelling);
    }
    clang_disposeTokens(context->translation_unit, tokens, token_count);
}

static bool mutation_cleanup_call(const struct p101_env *env, const char *name)
{
    static const char *const exact_names[] = {
        "p101_free",
        "p101_munmap",
        "p101_pthread_join",
        "p101_pthread_detach",
        "p101_error_reset",
    };
    static const char *const fragments[] = {
        "close",
        "destroy",
        "release",
        "unlock",
    };
    size_t index;

    if(p101_strncmp(env, name, "p101_", sizeof("p101_") - 1U) != 0)
    {
        return false;
    }
    for(index = 0U; index < sizeof(exact_names) / sizeof(exact_names[0]); index++)
    {
        if(p101_strcmp(env, name, exact_names[index]) == 0)
        {
            return true;
        }
    }
    for(index = 0U; index < sizeof(fragments) / sizeof(fragments[0]); index++)
    {
        if(p101_strstr(env, name, fragments[index]) != NULL)
        {
            return true;
        }
    }
    return false;
}

static void mutation_from_call(struct scan_context *context, CXCursor cursor, CXCursor parent, const char *path, size_t line, size_t column)
{
    static const char *const predicate_names[]        = {"p101_error_has_error", "p101_error_has_no_error"};
    static const char *const predicate_replacements[] = {"p101_error_has_no_error", "p101_error_has_error"};
    CXCursor                 referenced;
    char                    *name;
    size_t                   index;

    referenced = clang_getCursorReferenced(cursor);
    if(clang_Cursor_isNull(referenced) != 0)
    {
        return;
    }
    name = copy_cx_string(context->env, context->err, clang_getCursorSpelling(referenced));
    if(name == NULL)
    {
        context->stopped = true;
        return;
    }
    for(index = 0U; index < sizeof(predicate_names) / sizeof(predicate_names[0]); index++)
    {
        if(p101_strcmp(context->env, name, predicate_names[index]) == 0)
        {
            CXToken *tokens;
            unsigned token_count;
            unsigned token_index;

            tokens      = NULL;
            token_count = 0U;
            clang_tokenize(context->translation_unit, clang_getCursorExtent(cursor), &tokens, &token_count);
            for(token_index = 0U; token_index < token_count; token_index++)
            {
                CXString    spelling;
                const char *token_text;

                spelling   = clang_getTokenSpelling(context->translation_unit, tokens[token_index]);
                token_text = clang_getCString(spelling);
                if(token_text != NULL && p101_strcmp(context->env, token_text, predicate_names[index]) == 0)
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

                    range = clang_getTokenExtent(context->translation_unit, tokens[token_index]);
                    clang_getSpellingLocation(clang_getRangeStart(range), &file, &start_line, &start_column, &start_offset);
                    clang_getSpellingLocation(clang_getRangeEnd(range), &file, &end_line, &end_column, &end_offset);
                    p101_memset(context->env, &record, 0, sizeof(record));
                    record.kind         = P101_C_ANALYSIS_MUTATION;
                    record.path         = path;
                    record.line         = line;
                    record.column       = column;
                    record.start_offset = start_offset;
                    record.end_offset   = end_offset;
                    record.name         = predicate_names[index];
                    record.replacement  = predicate_replacements[index];
                    record.mutation     = P101_C_MUTATION_ERROR_PREDICATE;
                    (void)emit_record(context, &record);
                }
                clang_disposeString(spelling);
            }
            clang_disposeTokens(context->translation_unit, tokens, token_count);
            p101_free(context->env, name);
            return;
        }
    }

    if(clang_getCursorKind(parent) == CXCursor_CompoundStmt)
    {
        if(mutation_cleanup_call(context->env, name))
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

            range = clang_getCursorExtent(cursor);
            clang_getSpellingLocation(clang_getRangeStart(range), &file, &start_line, &start_column, &start_offset);
            clang_getSpellingLocation(clang_getRangeEnd(range), &file, &end_line, &end_column, &end_offset);
            original = source_range_text(context->env, context->err, path, start_offset, end_offset);
            if(original != NULL)
            {
                p101_memset(context->env, &record, 0, sizeof(record));
                record.kind         = P101_C_ANALYSIS_MUTATION;
                record.path         = path;
                record.line         = line;
                record.column       = column;
                record.start_offset = start_offset;
                record.end_offset   = end_offset;
                record.name         = original;
                record.replacement  = "(void)0";
                record.mutation     = P101_C_MUTATION_SKIP_CLEANUP;
                (void)emit_record(context, &record);
                p101_free(context->env, original);
            }
        }
    }
    p101_free(context->env, name);
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

static bool command_argument_takes_ignored_value(const struct p101_env *env, const char *argument)
{
    P101_TRACE_SCOPE(env);
    if(p101_strcmp(env, argument, "-o") == 0 || p101_strcmp(env, argument, "-MF") == 0 || p101_strcmp(env, argument, "-MT") == 0 || p101_strcmp(env, argument, "-MQ") == 0)
    {
        return true;
    }
    return false;
}

static bool command_argument_takes_semantic_value(const struct p101_env *env, const char *argument)
{
    P101_TRACE_SCOPE(env);
    if(p101_strcmp(env, argument, "-D") == 0 || p101_strcmp(env, argument, "-U") == 0 || p101_strcmp(env, argument, "-I") == 0 || p101_strcmp(env, argument, "-F") == 0 || p101_strcmp(env, argument, "-include") == 0 ||
       p101_strcmp(env, argument, "-imacros") == 0 || p101_strcmp(env, argument, "-isystem") == 0 || p101_strcmp(env, argument, "-iquote") == 0 || p101_strcmp(env, argument, "-idirafter") == 0 || p101_strcmp(env, argument, "-iframework") == 0 ||
       p101_strcmp(env, argument, "-x") == 0 || p101_strcmp(env, argument, "-target") == 0 || p101_strcmp(env, argument, "--target") == 0 || p101_strcmp(env, argument, "-arch") == 0 || p101_strcmp(env, argument, "-isysroot") == 0 ||
       p101_strcmp(env, argument, "--sysroot") == 0 || p101_strcmp(env, argument, "--gcc-toolchain") == 0)
    {
        return true;
    }
    return false;
}

static bool argument_has_prefix(const struct p101_env *env, const char *argument, const char *prefix)
{
    size_t prefix_length;

    P101_TRACE_SCOPE(env);
    prefix_length = p101_strlen(env, prefix);
    return p101_strncmp(env, argument, prefix, prefix_length) == 0;
}

static bool command_argument_is_semantic(const struct p101_env *env, const char *argument)
{
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
        if(p101_strcmp(env, argument, exact_arguments[index]) == 0)
        {
            return true;
        }
    }
    for(index = 0U; index < sizeof(prefixes) / sizeof(prefixes[0]); index++)
    {
        if(argument_has_prefix(env, argument, prefixes[index]))
        {
            return true;
        }
    }
    return false;
}

static bool command_argument_is_output(const struct p101_env *env, const char *argument)
{
    P101_TRACE_SCOPE(env);
    if((argument[0] == '-' && argument[1] == 'o' && p101_strcmp(env, argument, "-ObjC") != 0) || p101_strncmp(env, argument, "-MF", sizeof("-MF") - 1U) == 0 || p101_strncmp(env, argument, "-MT", sizeof("-MT") - 1U) == 0 ||
       p101_strncmp(env, argument, "-MQ", sizeof("-MQ") - 1U) == 0)
    {
        return true;
    }
    return false;
}

static bool command_argument_is_sysroot(const struct p101_env *env, const char *argument)
{
    P101_TRACE_SCOPE(env);
    if(p101_strcmp(env, argument, "-isysroot") == 0 || p101_strcmp(env, argument, "--sysroot") == 0 || p101_strncmp(env, argument, "-isysroot=", sizeof("-isysroot=") - 1U) == 0 || p101_strncmp(env, argument, "--sysroot=", sizeof("--sysroot=") - 1U) == 0)
    {
        return true;
    }
    return false;
}

static bool scan_source(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context, const char *source, const char *directory, const char *const arguments[],
                        size_t argument_count)
{
    CXIndex                  index;
    CXTranslationUnit        translation_unit;
    enum CXErrorCode         parse_status;
    const char              *parse_arguments[ANALYSIS_MAX_ARGUMENTS];
    char                     resource_argument[ANALYSIS_PATH_SIZE];
    size_t                   parse_argument_count;
    size_t                   argument_index;
    struct scan_context      context;
    struct inclusion_context inclusion;
    char                     previous_directory[ANALYSIS_PATH_SIZE];
    bool                     changed_directory;
    bool                     has_sysroot;
    bool                     result;
    unsigned                 translation_unit_options;

    P101_TRACE_SCOPE(env);
    parse_argument_count = 0U;
    has_sysroot          = false;
    for(argument_index = 0U; argument_index < argument_count && parse_argument_count < ANALYSIS_MAX_ARGUMENTS; argument_index++)
    {
        const char *argument;

        argument = arguments[argument_index];
        if(argument_index == 0U || p101_strcmp(env, argument, "-c") == 0 || p101_strcmp(env, argument, source) == 0)
        {
            continue;
        }
        if(command_argument_takes_ignored_value(env, argument))
        {
            argument_index++;
            continue;
        }
        if(command_argument_is_output(env, argument))
        {
            continue;
        }
        if(command_argument_takes_semantic_value(env, argument))
        {
            if(argument_index + 1U < argument_count && parse_argument_count + 2U <= ANALYSIS_MAX_ARGUMENTS)
            {
                if(command_argument_is_sysroot(env, argument))
                {
                    has_sysroot = true;
                }
                parse_arguments[parse_argument_count++] = argument;
                parse_arguments[parse_argument_count++] = arguments[++argument_index];
            }
            continue;
        }
        if(!command_argument_is_semantic(env, argument))
        {
            continue;
        }
        if(command_argument_is_sysroot(env, argument))
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
        if(p101_error_has_error(err))
        {
            return false;
        }
        parse_arguments[parse_argument_count++] = resource_argument;
    }
#else
    (void)resource_argument;
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
    if(directory != NULL && directory[0] != '\0' && p101_getcwd(env, err, previous_directory, sizeof(previous_directory)) != NULL)
    {
        if(p101_chdir(env, err, directory) == 0)
        {
            changed_directory = true;
        }
    }
    if(p101_error_has_error(err))
    {
        return false;
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
        (void)emit_record(&context, &record);
        clang_disposeIndex(index);
        if(changed_directory)
        {
            (void)p101_chdir(env, err, previous_directory);
        }
        if(options->keep_going && p101_error_has_no_error(err))
        {
            return true;
        }
        return false;
    }

    p101_memset(env, &context, 0, sizeof(context));
    context.env              = env;
    context.err              = err;
    context.options          = options;
    context.observer         = observer;
    context.observer_context = observer_context;
    context.translation_unit = translation_unit;
    for(unsigned diagnostic_index = 0U; diagnostic_index < clang_getNumDiagnostics(translation_unit) && !context.stopped; diagnostic_index++)
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
            record.path     = (path == NULL || path[0] == '\0') ? source : path;
            record.name     = clang_getCString(diagnostic_text);
            record.line     = line;
            record.column   = column;
            (void)emit_record(&context, &record);
            clang_disposeString(diagnostic_text);
            clang_disposeString(diagnostic_path);
        }
        clang_disposeDiagnostic(diagnostic);
    }
    inclusion.scan = &context;
    if(!context.stopped)
    {
        clang_getInclusions(translation_unit, visit_inclusion, &inclusion);
    }
    if(!context.stopped)
    {
        clang_visitChildren(clang_getTranslationUnitCursor(translation_unit), visit_cursor, &context);
    }
    result = false;
    if(!context.stopped && p101_error_has_no_error(err))
    {
        result = true;
    }
    clang_disposeTranslationUnit(translation_unit);
    clang_disposeIndex(index);
    if(changed_directory)
    {
        (void)p101_chdir(env, err, previous_directory);
    }
    return result;
}

static bool should_skip_directory(const struct p101_env *env, const char *name)
{
    static const char *const skipped[] = {".git", ".hg", ".svn", "__pycache__", "build", "coverage", "debug", "dist", "profile"};
    size_t                   index;

    P101_TRACE_SCOPE(env);
    for(index = 0U; index < sizeof(skipped) / sizeof(skipped[0]); index++)
    {
        if(p101_strcmp(env, name, skipped[index]) == 0)
        {
            return true;
        }
    }
    if(p101_strncmp(env, name, "build-", sizeof("build-") - 1U) == 0 || p101_strncmp(env, name, "coverage-", sizeof("coverage-") - 1U) == 0 || p101_strncmp(env, name, "debug-", sizeof("debug-") - 1U) == 0 ||
       p101_strncmp(env, name, "profile-", sizeof("profile-") - 1U) == 0)
    {
        return true;
    }
    return false;
}

static bool scan_directory(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context, const char *directory)    // NOLINT(misc-no-recursion)
{
    DIR           *stream;
    struct dirent *entry;
    bool           result;

    P101_TRACE_SCOPE(env);
    result = true;
    stream = p101_opendir(env, err, directory);
    if(stream == NULL)
    {
        return false;
    }
    while((entry = p101_readdir(env, err, stream)) != NULL && p101_error_has_no_error(err))
    {
        char        path[ANALYSIS_PATH_SIZE];
        struct stat status;

        if(p101_strcmp(env, entry->d_name, ".") == 0 || p101_strcmp(env, entry->d_name, "..") == 0 || should_skip_directory(env, entry->d_name))
        {
            continue;
        }
        p101_snprintf(env, err, path, sizeof(path), "%s/%s", directory, entry->d_name);
        if(p101_error_has_error(err))
        {
            result = false;
            break;
        }
        if(p101_stat(env, err, path, &status) != 0)
        {
            result = false;
            break;
        }
        if(S_ISDIR(status.st_mode))
        {
            if(!scan_directory(env, err, options, observer, observer_context, path))
            {
                result = false;
                break;
            }
        }
        else if(S_ISREG(status.st_mode) && (path_has_source_suffix(env, path) || (options->include_headers_as_translation_units && path_has_header_suffix(env, path))))
        {
            const char *default_arguments[] = {"clang", "-D_POSIX_C_SOURCE=200809L", "-D_XOPEN_SOURCE=700"};

            if(!scan_source(env, err, options, observer, observer_context, path, directory, default_arguments, sizeof(default_arguments) / sizeof(default_arguments[0])))
            {
                result = false;
                break;
            }
        }
    }
    if(p101_error_has_error(err))
    {
        result = false;
    }
    if(p101_closedir(env, err, stream) != 0)
    {
        result = false;
    }
    return result;
}

static bool scan_compile_database(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *observer_context)
{
    char                        database_directory[ANALYSIS_PATH_SIZE];
    const char                 *separator;
    CXCompilationDatabase_Error database_error;
    CXCompilationDatabase       database;
    CXCompileCommands           commands;
    unsigned                    command_count;
    unsigned                    command_index;
    bool                        result;

    P101_TRACE_SCOPE(env);
    if(options->compile_database == NULL || p101_strlen(env, options->compile_database) >= sizeof(database_directory))
    {
        P101_ERROR_RAISE_USER(err, "The compilation-database path is too long.", 1);
        return false;
    }
    p101_snprintf(env, err, database_directory, sizeof(database_directory), "%s", options->compile_database);
    if(p101_error_has_error(err))
    {
        return false;
    }
    separator = p101_strrchr(env, database_directory, '/');
    if(separator == NULL)
    {
        p101_snprintf(env, err, database_directory, sizeof(database_directory), ".");
    }
    else
    {
        database_directory[(size_t)(separator - database_directory)] = '\0';
    }
    database = clang_CompilationDatabase_fromDirectory(database_directory, &database_error);
    if(database_error != CXCompilationDatabase_NoError)
    {
        P101_ERROR_RAISE_USER(err, "Unable to load the Clang compilation database.", 1);
        return false;
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

        command        = clang_CompileCommands_getCommand(commands, command_index);
        source         = copy_cx_string(env, err, clang_CompileCommand_getFilename(command));
        directory      = copy_cx_string(env, err, clang_CompileCommand_getDirectory(command));
        argument_count = clang_CompileCommand_getNumArgs(command);
        arguments      = (char **)p101_calloc(env, err, argument_count, sizeof(*arguments));
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
            arguments[argument_index] = copy_cx_string(env, err, clang_CompileCommand_getArg(command, argument_index));
        }
        if(p101_error_has_error(err))
        {
            result = false;
        }
        else if(path_is_admitted(env, err, options, source) && path_has_source_suffix(env, source))
        {
            result = scan_source(env, err, options, observer, observer_context, source, directory, (const char *const *)arguments, argument_count);
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
    return result;
}

bool p101_c_analysis_scan(const struct p101_env *env, struct p101_error *err, const struct p101_c_analysis_options *options, p101_c_analysis_observer observer, void *context)
{
    struct p101_c_analysis_options normalized;
    const char                   **normalized_paths;
    char (*path_storage)[ANALYSIS_PATH_SIZE];
    bool   result;
    size_t index;

    P101_TRACE_SCOPE(env);
    if(options == NULL || observer == NULL || options->paths == NULL || options->path_count == 0U)
    {
        P101_ERROR_RAISE_CHECK(err);
        return false;
    }
    for(index = 0U; index < options->path_count; index++)
    {
        if(options->paths[index] == NULL)
        {
            P101_ERROR_RAISE_CHECK(err);
            return false;
        }
    }

    normalized_paths = (const char **)p101_calloc(env, err, options->path_count, sizeof(*normalized_paths));
    path_storage     = (char (*)[ANALYSIS_PATH_SIZE])p101_calloc(env, err, options->path_count, sizeof(*path_storage));
    if(normalized_paths == NULL || path_storage == NULL)
    {
        p101_free(env, path_storage);
        p101_free(env, (void *)normalized_paths);
        return false;
    }
    normalized = *options;
    for(index = 0U; index < options->path_count; index++)
    {
        /* P101_ERROR_CONTRACT_ALLOW_NO_ERROR: a missing path remains literal. */
        if(p101_realpath(env, NULL, options->paths[index], path_storage[index]) != NULL)
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

            path = normalized.paths[index];
            if(p101_stat(env, err, path, &status) != 0)
            {
                result = false;
            }
            else if(S_ISDIR(status.st_mode))
            {
                result = scan_directory(env, err, &normalized, observer, context, path);
            }
            else if(S_ISREG(status.st_mode) && (path_has_source_suffix(env, path) || path_has_header_suffix(env, path)))
            {
                const char *default_arguments[] = {"clang", "-D_POSIX_C_SOURCE=200809L", "-D_XOPEN_SOURCE=700"};

                result = scan_source(env, err, &normalized, observer, context, path, NULL, default_arguments, sizeof(default_arguments) / sizeof(default_arguments[0]));
            }
        }
    }
    p101_free(env, path_storage);
    p101_free(env, (void *)normalized_paths);
    if(result && p101_error_has_no_error(err))
    {
        return true;
    }
    return false;
}

const char *p101_c_analysis_kind_name(enum p101_c_analysis_kind kind)
{
    static const char *const names[] = {"FILE", "INCLUDE", "FUNCTION", "CALL", "TYPE", "MACRO", "NOTE", "MUTATION", "DIAGNOSTIC"};

    if(kind < P101_C_ANALYSIS_FILE || kind > P101_C_ANALYSIS_DIAGNOSTIC)
    {
        return "UNKNOWN";
    }
    return names[kind];
}

const char *p101_c_mutation_kind_name(enum p101_c_mutation_kind kind)
{
    static const char *const names[] = {"none", "comparison-boundary", "logical-connective", "arithmetic-operator", "error-predicate", "skip-cleanup"};

    if(kind < P101_C_MUTATION_NONE || kind > P101_C_MUTATION_SKIP_CLEANUP)
    {
        return "unknown";
    }
    return names[kind];
}
