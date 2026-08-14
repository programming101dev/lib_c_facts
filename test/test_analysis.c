#include "p101_c_facts/analysis.h"
#include "p101_c_facts/compile_command.h"
#include "unity.h"
#include <errno.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum
{
    PATH_SIZE = 512
};

struct analysis_counts
{
    size_t functions;
    size_t parameters;
    size_t calls;
    size_t notes;
    size_t mutations;
    size_t diagnostics;
    size_t error_discards;
    size_t call_results_not_isolated;
    bool   saw_error_contract;
    bool   saw_context_env_contract;
    bool   saw_context_error_contract;
    bool   saw_callback_env_contract;
    bool   saw_callback_error_contract;
    bool   saw_error_check;
    bool   saw_error_discard;
    bool   saw_error_optional;
    bool   saw_error_propagated;
    bool   saw_unchecked_chain;
    bool   saw_function_return;
    bool   saw_function_early_return;
    bool   saw_labeled_function_early_return;
    bool   saw_function_return_caller;
    bool   saw_semantic_role;
    bool   saw_enum;
    bool   saw_enumerator;
    bool   saw_trace;
    bool   saw_include;
    bool   saw_local_include;
    char   include_name[PATH_SIZE];
    char   include_resolved[PATH_SIZE];
    bool   saw_type;
    bool   saw_macro;
    bool   saw_macro_definition;
    bool   saw_macro_expansion;
    bool   saw_function_extent;
    bool   saw_macro_expansion_extent;
    bool   saw_indirect;
    bool   saw_variadic;
    bool   saw_typed_parameter;
    char   function_pointer_parent_usr[PATH_SIZE];
    size_t function_pointer_parameters;
    bool   saw_annotated_error_query;
    bool   saw_non_query_error_reader;
    bool   saw_function_reference;
    bool   saw_parenthesized_direct_call;
    bool   stop;
    bool   stop_on_call;
};

struct fault_state
{
    size_t      call;
    size_t      fail_at;
    const char *target;
};

static struct p101_error *error;
static struct p101_env   *env;

void setUp(void)
{
    error = p101_error_create(false);
    env   = p101_env_create(error, NULL);
}

void tearDown(void)
{
    p101_env_destroy(env);
    p101_error_destroy(error);
}

static void write_file(const char *path, const char *text)
{
    FILE *stream;

    stream = fopen(path, "w");
    TEST_ASSERT_NOT_NULL(stream);
    if(stream != NULL)
    {
        TEST_ASSERT_TRUE(fputs(text, stream) >= 0);
        TEST_ASSERT_EQUAL_INT(0, fclose(stream));
    }
}

static bool count_record(const struct p101_env *callback_env, struct p101_error *err, const struct p101_c_analysis_record *record, void *context)
{
    struct analysis_counts *counts;

    (void)callback_env;
    (void)err;
    counts = (struct analysis_counts *)context;
    if(record->kind == P101_C_ANALYSIS_FUNCTION)
    {
        int type_comparison;

        counts->functions++;
        counts->saw_function_extent = counts->saw_function_extent || record->end_offset > record->start_offset;
        type_comparison             = strcmp(record->type, "void (void (*)(int))");
        if(type_comparison == 0)
        {
            (void)snprintf(counts->function_pointer_parent_usr, sizeof(counts->function_pointer_parent_usr), "%s", record->usr);
        }
    }
    else if(record->kind == P101_C_ANALYSIS_PARAMETER)
    {
        int parent_comparison;

        counts->parameters++;
        counts->saw_typed_parameter = counts->saw_typed_parameter || (record->type != NULL && record->canonical_type != NULL && record->caller_usr != NULL);
        parent_comparison           = strcmp(record->caller_usr, counts->function_pointer_parent_usr);
        if(counts->function_pointer_parent_usr[0] != '\0' && parent_comparison == 0)
        {
            counts->function_pointer_parameters++;
        }
    }
    else if(record->kind == P101_C_ANALYSIS_CALL)
    {
        counts->calls++;
        counts->saw_indirect                  = counts->saw_indirect || record->is_indirect;
        counts->saw_parenthesized_direct_call = counts->saw_parenthesized_direct_call || (strcmp(record->name, "target") == 0 && !record->is_indirect);
        if(strcmp(record->name, "p101_error_has_error") == 0)
        {
            counts->saw_annotated_error_query = counts->saw_annotated_error_query || record->is_error_state_query;
        }
        if(strcmp(record->name, "p101_error_is_reporting") == 0)
        {
            counts->saw_non_query_error_reader = counts->saw_non_query_error_reader || !record->is_error_state_query;
        }
    }
    else if(record->kind == P101_C_ANALYSIS_NOTE)
    {
        counts->notes++;
        counts->saw_error_contract          = counts->saw_error_contract || strcmp(record->name, "ERROR_CONTRACT") == 0;
        counts->saw_context_env_contract    = counts->saw_context_env_contract || (strcmp(record->name, "ENV_CONTRACT") == 0 && record->caller != NULL && strcmp(record->caller, "contextual") == 0);
        counts->saw_context_error_contract  = counts->saw_context_error_contract || (strcmp(record->name, "ERROR_CONTRACT") == 0 && record->caller != NULL && strcmp(record->caller, "contextual") == 0);
        counts->saw_callback_env_contract   = counts->saw_callback_env_contract || (strcmp(record->name, "ENV_CONTRACT") == 0 && record->caller != NULL && strcmp(record->caller, "semantic_callback") == 0);
        counts->saw_callback_error_contract = counts->saw_callback_error_contract || (strcmp(record->name, "ERROR_CONTRACT") == 0 && record->caller != NULL && strcmp(record->caller, "semantic_callback") == 0);
        counts->saw_error_check             = counts->saw_error_check || strcmp(record->name, "ERROR_CHECK") == 0;
        counts->saw_error_discard           = counts->saw_error_discard || strcmp(record->name, "ERROR_DISCARD") == 0;
        if(strcmp(record->name, "CALL_NOT_ISOLATED") == 0)
        {
            counts->call_results_not_isolated++;
        }
        if(strcmp(record->name, "ERROR_DISCARD") == 0)
        {
            counts->error_discards++;
        }
        counts->saw_error_optional                = counts->saw_error_optional || strcmp(record->name, "ERROR_OPTIONAL") == 0;
        counts->saw_error_propagated              = counts->saw_error_propagated || strcmp(record->name, "ERROR_PROPAGATED") == 0;
        counts->saw_unchecked_chain               = counts->saw_unchecked_chain || strcmp(record->name, "ERROR_UNCHECKED_CHAIN") == 0;
        counts->saw_function_return               = counts->saw_function_return || strcmp(record->name, "FUNCTION_RETURN") == 0;
        counts->saw_function_early_return         = counts->saw_function_early_return || strcmp(record->name, "FUNCTION_EARLY_RETURN") == 0;
        counts->saw_labeled_function_early_return = counts->saw_labeled_function_early_return || (strcmp(record->name, "FUNCTION_EARLY_RETURN") == 0 && record->caller != NULL && strcmp(record->caller, "labeled_return") == 0);
        counts->saw_function_return_caller        = counts->saw_function_return_caller || (strcmp(record->name, "FUNCTION_RETURN") == 0 && record->caller != NULL && record->caller[0] != '\0');
        counts->saw_semantic_role                 = counts->saw_semantic_role || strcmp(record->name, "SEMANTIC_ROLE:p101:test-role") == 0;
        counts->saw_trace                         = counts->saw_trace || strcmp(record->name, "TYPE_SEMANTIC_ROLE:p101:trace-scope") == 0;
        counts->saw_function_reference            = counts->saw_function_reference || strncmp(record->name, "FUNCTION_REFERENCE:", sizeof("FUNCTION_REFERENCE:") - 1U) == 0;
    }
    else if(record->kind == P101_C_ANALYSIS_MUTATION)
    {
        counts->mutations++;
    }
    else if(record->kind == P101_C_ANALYSIS_ENUM)
    {
        counts->saw_enum = counts->saw_enum || strcmp(record->name, "sample_result") == 0;
    }
    else if(record->kind == P101_C_ANALYSIS_ENUMERATOR)
    {
        counts->saw_enumerator = counts->saw_enumerator || (strcmp(record->name, "SAMPLE_RESULT_OK") == 0 && strcmp(record->type, "sample_result") == 0);
    }
    else if(record->kind == P101_C_ANALYSIS_DIAGNOSTIC)
    {
        counts->diagnostics++;
    }
    else if(record->kind == P101_C_ANALYSIS_INCLUDE)
    {
        counts->saw_include       = true;
        counts->saw_local_include = counts->saw_local_include || record->is_local_include;
        (void)snprintf(counts->include_name, sizeof(counts->include_name), "%s", record->name);
        (void)snprintf(counts->include_resolved, sizeof(counts->include_resolved), "%s", record->resolved_include == NULL ? "" : record->resolved_include);
    }
    else if(record->kind == P101_C_ANALYSIS_TYPE)
    {
        counts->saw_type = true;
    }
    else if(record->kind == P101_C_ANALYSIS_MACRO)
    {
        counts->saw_macro                  = true;
        counts->saw_macro_definition       = counts->saw_macro_definition || record->is_definition;
        counts->saw_macro_expansion        = counts->saw_macro_expansion || !record->is_definition;
        counts->saw_macro_expansion_extent = counts->saw_macro_expansion_extent || (!record->is_definition && record->end_offset > record->start_offset);
    }
    if(record->kind == P101_C_ANALYSIS_FUNCTION)
    {
        counts->saw_variadic = counts->saw_variadic || record->is_variadic;
    }
    return !counts->stop && !(counts->stop_on_call && record->kind == P101_C_ANALYSIS_CALL);
}

static bool check_command(const struct p101_env *callback_env, struct p101_error *err, const struct p101_c_compile_command *command, void *context)
{
    bool *called;

    (void)callback_env;
    (void)err;
    called  = (bool *)context;
    *called = command->directory != NULL && command->argument_count >= 2U && command->arguments != NULL;
    return *called;
}

static bool reject_command(const struct p101_env *callback_env, struct p101_error *err, const struct p101_c_compile_command *command, void *context)
{
    (void)callback_env;
    (void)err;
    (void)command;
    (void)context;
    return false;
}

static int fail_selected_call(const struct p101_env *callback_env, const char *call_name, void *user_data)
{
    struct fault_state *state;

    (void)callback_env;
    state = (struct fault_state *)user_data;
    /*
     * The broad analysis fault sweep is for failures while discovering and
     * parsing inputs. Injecting the release itself would intentionally leave
     * an acquired libc resource live and obscure the error path under test.
     * fclose/closedir have their own wrapper-level fault fixtures.
     */
    if(strcmp(call_name, "fclose") == 0 || strcmp(call_name, "closedir") == 0)
    {
        return 0;
    }
    if(state->target != NULL && strcmp(state->target, call_name) != 0)
    {
        return 0;
    }
    state->call++;
    if(state->call == state->fail_at)
    {
        return EIO;
    }
    return 0;
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:c-fact-analysis:clean")

static void test_analysis_and_compile_command(void)
{
    char                           directory[PATH_SIZE];
    char                           source[PATH_SIZE];
    char                           database[PATH_SIZE];
    char                           previous_directory[PATH_SIZE];
    char                           oversized_database[5000];
    char                           json[4096];
    const char                    *paths[1];
    struct p101_c_analysis_options options;
    struct analysis_counts         counts;
    bool                           command_called;

    (void)snprintf(directory, sizeof(directory), "/tmp/p101-c-analysis-%ld", (long)getpid());
    (void)snprintf(source, sizeof(source), "%s/demo.c", directory);
    (void)snprintf(database, sizeof(database), "%s/compile_commands.json", directory);
    TEST_ASSERT_EQUAL_INT(0, mkdir(directory, 0700));
    write_file(source,
               "#ifndef P101_GCC_DATABASE_DEFINE\n"
               "#error semantic compile-database define was discarded\n"
               "#endif\n"
               "#ifndef P101_GCC_DATABASE_SPLIT_DEFINE\n"
               "#error split semantic compile-database define was discarded\n"
               "#endif\n"
               "struct p101_env; struct p101_error;\n"
               "extern struct p101_error *const p101_error_optional_sink __attribute__((annotate(\"p101:optional-error\")));\n"
               "#define P101_ERROR_OPTIONAL p101_error_optional_sink\n"
               "typedef enum { SAMPLE_RESULT_OK, SAMPLE_RESULT_REFUSED } sample_result;\n"
               "int p101_error_has_error(struct p101_error *err) __attribute__((annotate(\"p101:error-state-query\")));\n"
               "int p101_error_is_reporting(const struct p101_error *err);\n"
               "int p101_first(const struct p101_env *env, struct p101_error *err);\n"
               "int p101_second(const struct p101_env *env, struct p101_error *err);\n"
               "const char *copy_text(struct p101_error *err, const char *value);\n"
               "#define COPY_VALUE(value) do { const char *copy = copy_text(err, (value)); if(copy == 0) return 0; } while(0)\n"
               "static int demo(const struct p101_env *env, struct p101_error *err) {\n"
               "  (void)env;\n"
               "  (void)p101_error_is_reporting(err);\n"
               "  return p101_error_has_error(err) == 0;\n"
               "}\n"
               "static int chained(const struct p101_env *env, struct p101_error *err) {\n"
               "  p101_first(env, err);\n"
               "  return p101_second(env, err);\n"
               "}\n"
               "static int optional(const struct p101_env *env) {\n"
               "  /* P101_ERROR_OPTIONAL rationale: absence is expected. */\n"
               "  return p101_first(env, P101_ERROR_OPTIONAL);\n"
               "}\n"
               "static int discarded(const struct p101_env *env) {\n"
               "  return p101_first(env, (struct p101_error *)0);\n"
               "}\n"
               "static int role_fn(void) __attribute__((annotate(\"p101:test-role\")));\n"
               "static int role_fn(void) { return 0; }\n"
               "static int labeled_return(int condition) { int result = 0; if(condition) { goto done; } done: return result; }\n"
               "static int macro_copy(struct p101_error *err, const char *value) {\n"
               "  COPY_VALUE(value);\n"
               "  return 1;\n"
               "}\n");
    (void)snprintf(json,
                   sizeof(json),
                   "[{\"directory\":\"%s\",\"file\":\"%s\","
                   "\"arguments\":[\"gcc\",\"-std=c17\",\"-pthread\",\"-DP101_GCC_DATABASE_DEFINE=1\","
                   "\"-D\",\"P101_GCC_DATABASE_SPLIT_DEFINE=1\",\"-x\",\"c\","
                   "\"-fanalyzer\",\"-fanalyzer-checker=taint\",\"-Wanalyzer-double-free\","
                   "\"-fsanitize=bounds-strict\",\"-fharden-compares\",\"-femit-class-debug-always\","
                   "\"-gstatement-frontiers\",\"-c\",\"%s\",\"-o\",\"demo.o\",\"-MFdemo.d\",\"-MT\",\"demo\",\"-MQdemo\"]}]\n",
                   directory,
                   source,
                   source);
    write_file(database, json);

    memset(&options, 0, sizeof(options));
    memset(&counts, 0, sizeof(counts));
    paths[0]                       = directory;
    options.compile_database       = database;
    options.paths                  = paths;
    options.path_count             = 1U;
    options.detailed_preprocessing = true;
    TEST_ASSERT_TRUE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_FALSE(p101_error_has_error(error));
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.functions);
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.calls);
    TEST_ASSERT_TRUE(counts.saw_function_return);
    TEST_ASSERT_TRUE(counts.saw_function_early_return);
    TEST_ASSERT_FALSE(counts.saw_labeled_function_early_return);
    TEST_ASSERT_TRUE(counts.saw_function_return_caller);
    TEST_ASSERT_TRUE(counts.saw_semantic_role);
    TEST_ASSERT_TRUE(counts.saw_function_reference);
    TEST_ASSERT_TRUE(counts.saw_enum);
    TEST_ASSERT_TRUE(counts.saw_enumerator);
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.notes);
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.mutations);
    TEST_ASSERT_TRUE(counts.saw_error_contract);
    TEST_ASSERT_TRUE(counts.saw_function_extent);
    TEST_ASSERT_TRUE(counts.saw_error_check);
    TEST_ASSERT_TRUE(counts.saw_annotated_error_query);
    TEST_ASSERT_TRUE(counts.saw_non_query_error_reader);
    TEST_ASSERT_TRUE(counts.saw_error_optional);
    TEST_ASSERT_TRUE(counts.saw_error_discard);
    TEST_ASSERT_EQUAL_UINT(1U, counts.error_discards);
    TEST_ASSERT_TRUE(counts.saw_unchecked_chain);

    command_called = false;
    TEST_ASSERT_TRUE(p101_c_facts_with_compile_command(env, error, database, source, check_command, &command_called));
    TEST_ASSERT_TRUE(command_called);
    p101_error_reset(error);
    TEST_ASSERT_FALSE(p101_c_facts_with_compile_command(env, error, database, source, reject_command, NULL));
    TEST_ASSERT_FALSE(p101_error_has_error(error));
    p101_error_reset(error);
    TEST_ASSERT_FALSE(p101_c_facts_with_compile_command(env, error, database, "/tmp", check_command, &command_called));
    TEST_ASSERT_TRUE(p101_error_has_error(error));
    p101_error_reset(error);
    TEST_ASSERT_NOT_NULL(getcwd(previous_directory, sizeof(previous_directory)));
    TEST_ASSERT_EQUAL_INT(0, chdir(directory));
    options.compile_database = "compile_commands.json";
    memset(&counts, 0, sizeof(counts));
    TEST_ASSERT_TRUE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    command_called = false;
    TEST_ASSERT_TRUE(p101_c_facts_with_compile_command(env, error, "compile_commands.json", source, check_command, &command_called));
    TEST_ASSERT_TRUE(command_called);
    TEST_ASSERT_EQUAL_INT(0, chdir(previous_directory));
    options.compile_database = database;

    paths[0] = NULL;
    memset(&counts, 0, sizeof(counts));
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_TRUE(p101_error_has_error(error));
    p101_error_reset(error);
    paths[0] = directory;

    memset(oversized_database, 'x', sizeof(oversized_database) - 1U);
    oversized_database[sizeof(oversized_database) - 1U] = '\0';
    options.compile_database                            = oversized_database;
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_TRUE(p101_error_has_error(error));
    p101_error_reset(error);
    TEST_ASSERT_FALSE(p101_c_facts_with_compile_command(env, error, oversized_database, source, check_command, &command_called));
    TEST_ASSERT_TRUE(p101_error_has_error(error));
    p101_error_reset(error);
    options.compile_database = database;

    counts.stop_on_call = true;
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_FALSE(p101_error_has_error(error));
    counts.stop_on_call = false;

    for(size_t fail_at = 1U; fail_at <= 200U; fail_at++)
    {
        struct p101_error     *fault_error;
        struct p101_env       *fault_env;
        struct fault_state     state;
        struct analysis_counts fault_counts;

        fault_error   = p101_error_create(false);
        fault_env     = p101_env_create(fault_error, NULL);
        state.call    = 0U;
        state.fail_at = fail_at;
        state.target  = "malloc";
        memset(&fault_counts, 0, sizeof(fault_counts));
        p101_env_set_fault_injector(fault_env, fail_selected_call, &state);
        (void)p101_c_analysis_scan(fault_env, fault_error, &options, count_record, &fault_counts);
        p101_env_destroy(fault_env);
        p101_error_destroy(fault_error);
    }

    {
        const char *kind_name;

        kind_name = p101_c_analysis_kind_name(P101_C_ANALYSIS_NOTE);
        TEST_ASSERT_EQUAL_STRING("NOTE", kind_name);
        kind_name = p101_c_analysis_kind_name(P101_C_ANALYSIS_ENUM);
        TEST_ASSERT_EQUAL_STRING("ENUM", kind_name);
        kind_name = p101_c_analysis_kind_name(P101_C_ANALYSIS_ENUMERATOR);
        TEST_ASSERT_EQUAL_STRING("ENUMERATOR", kind_name);
        kind_name = p101_c_analysis_kind_name((enum p101_c_analysis_kind)99);
        TEST_ASSERT_EQUAL_STRING("UNKNOWN", kind_name);
        kind_name = p101_c_mutation_kind_name(P101_C_MUTATION_COMPARISON_BOUNDARY);
        TEST_ASSERT_EQUAL_STRING("comparison-boundary", kind_name);
        kind_name = p101_c_mutation_kind_name(P101_C_MUTATION_LOGICAL_CONNECTIVE);
        TEST_ASSERT_EQUAL_STRING("logical-connective", kind_name);
        kind_name = p101_c_mutation_kind_name(P101_C_MUTATION_ARITHMETIC_OPERATOR);
        TEST_ASSERT_EQUAL_STRING("arithmetic-operator", kind_name);
        kind_name = p101_c_mutation_kind_name(P101_C_MUTATION_ERROR_PREDICATE);
        TEST_ASSERT_EQUAL_STRING("error-predicate", kind_name);
        kind_name = p101_c_mutation_kind_name(P101_C_MUTATION_SKIP_CALL);
        TEST_ASSERT_EQUAL_STRING("skip-call", kind_name);
        kind_name = p101_c_mutation_kind_name((enum p101_c_mutation_kind)99);
        TEST_ASSERT_EQUAL_STRING("unknown", kind_name);
    }

    /* Every wire name round-trips through the shared table, and text the
     * writers cannot emit is rejected rather than mapped to a kind. */
    for(int value = P101_C_MUTATION_NONE; value <= P101_C_MUTATION_SKIP_CALL; value++)
    {
        enum p101_c_mutation_kind parsed_kind;
        const char               *kind_name;
        bool                      parsed;

        kind_name = p101_c_mutation_kind_name((enum p101_c_mutation_kind)value);
        parsed    = p101_c_mutation_kind_from_name(env, kind_name, &parsed_kind);
        TEST_ASSERT_TRUE(parsed);
        TEST_ASSERT_EQUAL_INT(value, parsed_kind);
    }
    {
        enum p101_c_mutation_kind parsed_kind;
        bool                      parsed;

        parsed = p101_c_mutation_kind_from_name(env, "unknown", &parsed_kind);
        TEST_ASSERT_FALSE(parsed);
        parsed = p101_c_mutation_kind_from_name(env, "", &parsed_kind);
        TEST_ASSERT_FALSE(parsed);
        parsed = p101_c_mutation_kind_from_name(env, NULL, &parsed_kind);
        TEST_ASSERT_FALSE(parsed);
        parsed = p101_c_mutation_kind_from_name(env, "skip-call", NULL);
        TEST_ASSERT_FALSE(parsed);
    }

    TEST_ASSERT_EQUAL_INT(0, unlink(database));
    TEST_ASSERT_EQUAL_INT(0, unlink(source));
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

static void test_wrapper_conformance_smoke(void)
{
    char                           directory[PATH_SIZE];
    char                           source[PATH_SIZE];
    char                           database[PATH_SIZE];
    char                           json[1024];
    const char                    *paths[1];
    struct p101_c_analysis_options options;
    struct analysis_counts         counts;
    enum p101_c_mutation_kind      parsed_kind;
    bool                           parsed;
    bool                           command_called;

    (void)snprintf(directory, sizeof(directory), "/tmp/p101-c-analysis-conformance-%ld", (long)getpid());
    (void)snprintf(source, sizeof(source), "%s/demo.c", directory);
    (void)snprintf(database, sizeof(database), "%s/compile_commands.json", directory);
    TEST_ASSERT_EQUAL_INT(0, mkdir(directory, 0700));
    write_file(source, "static int helper(void) { return 1; }\nint demo(void) { return helper(); }\n");
    (void)snprintf(json,
                   sizeof(json),
                   "[{\"directory\":\"%s\",\"file\":\"%s\","
                   "\"arguments\":[\"clang\",\"-std=c17\",\"-c\",\"%s\"]}]\n",
                   directory,
                   source,
                   source);
    write_file(database, json);

    memset(&options, 0, sizeof(options));
    memset(&counts, 0, sizeof(counts));
    paths[0]                 = source;
    options.compile_database = database;
    options.paths            = paths;
    options.path_count       = 1U;
    TEST_ASSERT_TRUE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_FALSE(p101_error_has_error(error));
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.functions);
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.calls);

    command_called = false;
    TEST_ASSERT_TRUE(p101_c_facts_with_compile_command(env, error, database, source, check_command, &command_called));
    TEST_ASSERT_TRUE(command_called);
    TEST_ASSERT_EQUAL_STRING("FUNCTION", p101_c_analysis_kind_name(P101_C_ANALYSIS_FUNCTION));
    TEST_ASSERT_EQUAL_STRING("PARAMETER", p101_c_analysis_kind_name(P101_C_ANALYSIS_PARAMETER));
    TEST_ASSERT_EQUAL_STRING("skip-call", p101_c_mutation_kind_name(P101_C_MUTATION_SKIP_CALL));
    parsed = p101_c_mutation_kind_from_name(env, "skip-call", &parsed_kind);
    TEST_ASSERT_TRUE(parsed);
    TEST_ASSERT_EQUAL_INT(P101_C_MUTATION_SKIP_CALL, parsed_kind);

    TEST_ASSERT_EQUAL_INT(0, unlink(database));
    TEST_ASSERT_EQUAL_INT(0, unlink(source));
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:c-fact-analysis:identity_mismatch")

static void test_directory_analysis_exercises_semantic_records(void)
{
    char                           directory[PATH_SIZE];
    char                           source[PATH_SIZE];
    char                           header[PATH_SIZE];
    char                           cxx_source[PATH_SIZE];
    char                           skipped_directory[PATH_SIZE];
    char                           skipped_source[PATH_SIZE];
    char                           generated_directory[PATH_SIZE];
    char                           generated_source[PATH_SIZE];
    char                           nested_directory[PATH_SIZE];
    char                           nested_source[PATH_SIZE];
    char                           short_file[PATH_SIZE];
    const char                    *paths[1];
    const char                    *extra_arguments[1];
    struct p101_c_analysis_options options;
    struct analysis_counts         counts;

    (void)snprintf(directory, sizeof(directory), "/tmp/p101-c-analysis-directory-%ld", (long)getpid());
    (void)snprintf(source, sizeof(source), "%s/demo.c", directory);
    (void)snprintf(header, sizeof(header), "%s/demo.h", directory);
    (void)snprintf(cxx_source, sizeof(cxx_source), "%s/demo.cpp", directory);
    (void)snprintf(skipped_directory, sizeof(skipped_directory), "%s/build", directory);
    (void)snprintf(skipped_source, sizeof(skipped_source), "%s/ignored.c", skipped_directory);
    (void)snprintf(generated_directory, sizeof(generated_directory), "%s/build-generated", directory);
    (void)snprintf(generated_source, sizeof(generated_source), "%s/ignored.c", generated_directory);
    (void)snprintf(nested_directory, sizeof(nested_directory), "%s/nested", directory);
    (void)snprintf(nested_source, sizeof(nested_source), "%s/extra.c", nested_directory);
    (void)snprintf(short_file, sizeof(short_file), "%s/x", directory);
    TEST_ASSERT_EQUAL_INT(0, mkdir(directory, 0700));
    TEST_ASSERT_EQUAL_INT(0, mkdir(skipped_directory, 0700));
    TEST_ASSERT_EQUAL_INT(0, mkdir(generated_directory, 0700));
    TEST_ASSERT_EQUAL_INT(0, mkdir(nested_directory, 0700));
    write_file(header,
               "#ifndef DEMO_H\n"
               "#define DEMO_H\n"
               "struct __attribute__((annotate(\"p101:trace-scope\"))) p101_trace_scope { int value; };\n"
               "typedef int demo_alias;\n"
               "struct demo_struct { int value; };\n"
               "union demo_union { int value; long other; };\n"
               "enum demo_enum { DEMO_VALUE };\n"
               "#endif\n");
    write_file(source,
               "#include \"demo.h\"\n"
               "#define LOCAL_MACRO 1\n"
               "struct p101_env; struct p101_error;\n"
               "extern struct p101_error *const p101_error_optional_sink __attribute__((annotate(\"p101:optional-error\")));\n"
               "#define P101_ERROR_OPTIONAL p101_error_optional_sink\n"
               "int p101_error_has_error(struct p101_error *err) __attribute__((annotate(\"p101:error-state-query\")));\n"
               "int p101_error_has_no_error(struct p101_error *err) __attribute__((annotate(\"p101:error-state-query\")));\n"
               "#define NULL ((void *)0)\n"
               "int p101_first(const struct p101_env *env, struct p101_error *err);\n"
               "int p101_second(const struct p101_env *env, struct p101_error *err);\n"
               "int p101_close(const struct p101_env *env, struct p101_error *err, int fd);\n"
               "int p101_fclose(const struct p101_env *env, struct p101_error *err, void *stream);\n"
               "void p101_free(const struct p101_env *env, void *memory);\n"
               "struct analysis_context { const struct p101_env *env; struct p101_error *err; };\n"
               "typedef void *client_data;\n"
               "struct callback_context { const struct p101_env *env; struct p101_error *err; };\n"
               "static int contextual(struct analysis_context *context) {\n"
               "  int result;\n"
               "  result = p101_first(context->env, context->err);\n"
               "  return result;\n"
               "}\n"
               "static unsigned semantic_callback(int cursor, client_data data) {\n"
               "  struct callback_context *context;\n"
               "  int result;\n"
               "  context = (struct callback_context *)data;\n"
               "  result = p101_first(context->env, context->err);\n"
               "  (void)cursor;\n"
               "  return (unsigned)result;\n"
               "}\n"
               "static int variadic(int first, ...) { return first; }\n"
               "static void install(void (*handler)(int)) { (void)handler; }\n"
               "static int target(void) { return 1; }\n"
               "static int (*callback)(void) = target;\n"
               "static int demo(const struct p101_env *env, struct p101_error *err, void *memory) {\n"
               "  struct p101_trace_scope trace_scope;\n"
               "  struct p101_error *local_error = err;\n"
               "  int value = LOCAL_MACRO;\n"
               "  (void)trace_scope;\n"
               "  p101_first(env, local_error);\n"
               "  if(p101_error_has_error(local_error)) { return -1; }\n"
               "  p101_first(env, local_error);\n"
               "  p101_error_has_error(local_error);\n"
               "  p101_first(env, NULL);\n"
               "  p101_first(env, local_error);\n"
               "  /* P101_ERROR_OPTIONAL rationale: absence is expected. */\n"
               "  p101_first(env, P101_ERROR_OPTIONAL);\n"
               "  value += (1 == 1) + (1 != 2) + (1 < 2) + (1 <= 2) + (2 > 1) + (2 >= 1);\n"
               "  value += p101_error_has_no_error(local_error) ? 1 : 0;\n"
               "  value += (target)();\n"
               "  switch(value) { case 0: break; default: value += callback(); break; }\n"
               "  p101_free(env, memory);\n"
               "  p101_close(env, local_error, value);\n"
               "  p101_fclose(env, local_error, memory);\n"
               "  return p101_second(env, local_error);\n"
               "}\n");
    write_file(cxx_source,
               "struct p101_env {}; struct p101_error {};\n"
               "int p101_first(const p101_env *, p101_error *);\n"
               "class demo { public: demo() {} ~demo() {} int method(const p101_env *env) { return p101_first(env, nullptr); } };\n");
    write_file(skipped_source, "this is not C and must be skipped\n");
    write_file(generated_source, "this is not C and must be skipped\n");
    write_file(nested_source, "int nested(void) { return unknown_external(); }\n");
    write_file(short_file, "not a translation unit\n");

    memset(&options, 0, sizeof(options));
    memset(&counts, 0, sizeof(counts));
    paths[0]                                     = directory;
    extra_arguments[0]                           = "-DTEST_EXTRA_ARGUMENT=1";
    options.paths                                = paths;
    options.path_count                           = 1U;
    options.extra_arguments                      = extra_arguments;
    options.extra_argument_count                 = 1U;
    options.detailed_preprocessing               = true;
    options.include_headers_as_translation_units = true;
    TEST_ASSERT_TRUE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_TRUE(counts.saw_include);
    TEST_ASSERT_TRUE(counts.saw_local_include);
    TEST_ASSERT_EQUAL_STRING("demo.h", counts.include_name);
    /*
     * The include resolves inside the scanned directory, so the record must
     * carry the file libclang actually opened, not just the spelling.
     */
    TEST_ASSERT_TRUE(counts.include_resolved[0] != '\0');
    TEST_ASSERT_TRUE(strlen(counts.include_resolved) >= strlen("demo.h"));
    TEST_ASSERT_EQUAL_STRING("demo.h", counts.include_resolved + strlen(counts.include_resolved) - strlen("demo.h"));
    TEST_ASSERT_TRUE(counts.saw_type);
    TEST_ASSERT_TRUE(counts.saw_macro);
    TEST_ASSERT_TRUE(counts.saw_macro_definition);
    TEST_ASSERT_TRUE(counts.saw_macro_expansion);
    TEST_ASSERT_TRUE(counts.saw_macro_expansion_extent);
    TEST_ASSERT_TRUE(counts.saw_trace);
    TEST_ASSERT_TRUE(counts.saw_context_env_contract);
    TEST_ASSERT_TRUE(counts.saw_context_error_contract);
    TEST_ASSERT_TRUE(counts.saw_callback_env_contract);
    TEST_ASSERT_TRUE(counts.saw_callback_error_contract);
    TEST_ASSERT_TRUE(counts.saw_error_discard);
    TEST_ASSERT_TRUE(counts.saw_error_optional);
    TEST_ASSERT_TRUE(counts.saw_error_propagated);
    TEST_ASSERT_TRUE(counts.saw_indirect);
    TEST_ASSERT_TRUE(counts.saw_parenthesized_direct_call);
    TEST_ASSERT_TRUE(counts.saw_variadic);
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.parameters);
    TEST_ASSERT_TRUE(counts.saw_typed_parameter);
    TEST_ASSERT_EQUAL_UINT(1U, counts.function_pointer_parameters);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT(9U, counts.mutations);

    memset(&counts, 0, sizeof(counts));
    counts.stop_on_call = true;
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_FALSE(p101_error_has_error(error));

    memset(&counts, 0, sizeof(counts));
    counts.stop = true;
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_FALSE(p101_error_has_error(error));

    memset(&counts, 0, sizeof(counts));
    paths[0]                                     = source;
    options.include_headers_as_translation_units = false;
    TEST_ASSERT_TRUE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.functions);
    paths[0] = directory;

    TEST_ASSERT_EQUAL_INT(0, unlink(short_file));
    TEST_ASSERT_EQUAL_INT(0, unlink(nested_source));
    TEST_ASSERT_EQUAL_INT(0, rmdir(nested_directory));
    TEST_ASSERT_EQUAL_INT(0, unlink(generated_source));
    TEST_ASSERT_EQUAL_INT(0, rmdir(generated_directory));
    TEST_ASSERT_EQUAL_INT(0, unlink(skipped_source));
    TEST_ASSERT_EQUAL_INT(0, rmdir(skipped_directory));
    TEST_ASSERT_EQUAL_INT(0, unlink(cxx_source));
    TEST_ASSERT_EQUAL_INT(0, unlink(source));
    TEST_ASSERT_EQUAL_INT(0, unlink(header));
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:c-fact-analysis:resource_limit")

static void test_analysis_failures_and_faults(void)
{
    char                           directory[PATH_SIZE];
    char                           source[PATH_SIZE];
    char                           missing_database[PATH_SIZE];
    const char                    *paths[1];
    struct p101_c_analysis_options options;
    struct analysis_counts         counts;
    const char                    *invalid_arguments[2];
    static const char *const       fault_targets[] = {"malloc", "fopen", "fseek", "fread", "fclose", "stat", "opendir", "readdir", "closedir", "getcwd", "chdir", "snprintf"};
    size_t                         fail_at;
    size_t                         target_index;

    (void)snprintf(directory, sizeof(directory), "/tmp/p101-c-analysis-fault-%ld", (long)getpid());
    (void)snprintf(source, sizeof(source), "%s/demo.c", directory);
    (void)snprintf(missing_database, sizeof(missing_database), "%s/missing/compile_commands.json", directory);
    TEST_ASSERT_EQUAL_INT(0, mkdir(directory, 0700));
    write_file(source, "int demo(void) { return 0; }\n");

    memset(&options, 0, sizeof(options));
    paths[0]                 = directory;
    options.paths            = paths;
    options.path_count       = 1U;
    options.compile_database = missing_database;
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, NULL));
    TEST_ASSERT_TRUE(p101_error_has_error(error));
    p101_error_reset(error);
    TEST_ASSERT_FALSE(p101_c_facts_with_compile_command(env, error, missing_database, source, check_command, NULL));
    TEST_ASSERT_TRUE(p101_error_has_error(error));
    p101_error_reset(error);
    TEST_ASSERT_FALSE(p101_c_facts_with_compile_command(env, error, NULL, source, check_command, NULL));
    TEST_ASSERT_FALSE(p101_c_facts_with_compile_command(env, error, missing_database, NULL, check_command, NULL));
    TEST_ASSERT_FALSE(p101_c_facts_with_compile_command(env, error, missing_database, source, NULL, NULL));
    p101_error_reset(error);

    options.compile_database = NULL;
    for(fail_at = 1U; fail_at <= 80U; fail_at++)
    {
        struct p101_error     *fault_error;
        struct p101_env       *fault_env;
        struct fault_state     state;
        struct analysis_counts counts;

        fault_error   = p101_error_create(false);
        fault_env     = p101_env_create(fault_error, NULL);
        state.call    = 0U;
        state.fail_at = fail_at;
        state.target  = NULL;
        memset(&counts, 0, sizeof(counts));
        p101_env_set_fault_injector(fault_env, fail_selected_call, &state);
        (void)p101_c_analysis_scan(fault_env, fault_error, &options, count_record, &counts);
        p101_env_destroy(fault_env);
        p101_error_destroy(fault_error);
    }

    for(target_index = 0U; target_index < sizeof(fault_targets) / sizeof(fault_targets[0]); target_index++)
    {
        for(fail_at = 1U; fail_at <= 8U; fail_at++)
        {
            struct p101_error     *fault_error;
            struct p101_env       *fault_env;
            struct fault_state     state;
            struct analysis_counts fault_counts;

            fault_error   = p101_error_create(false);
            fault_env     = p101_env_create(fault_error, NULL);
            state.call    = 0U;
            state.fail_at = fail_at;
            state.target  = fault_targets[target_index];
            memset(&fault_counts, 0, sizeof(fault_counts));
            p101_env_set_fault_injector(fault_env, fail_selected_call, &state);
            (void)p101_c_analysis_scan(fault_env, fault_error, &options, count_record, &fault_counts);
            p101_env_destroy(fault_env);
            p101_error_destroy(fault_error);
        }
    }

    memset(&counts, 0, sizeof(counts));
    paths[0]                     = source;
    invalid_arguments[0]         = "-x";
    invalid_arguments[1]         = "not-a-language";
    options.extra_arguments      = invalid_arguments;
    options.extra_argument_count = 2U;
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_FALSE(p101_error_has_error(error));
    options.keep_going = true;
    TEST_ASSERT_TRUE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    options.keep_going           = false;
    options.extra_arguments      = NULL;
    options.extra_argument_count = 0U;

    memset(&counts, 0, sizeof(counts));
    paths[0] = NULL;
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_TRUE(p101_error_has_error(error));
    p101_error_reset(error);
    paths[0] = directory;

    TEST_ASSERT_EQUAL_INT(0, unlink(source));
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

static void test_analysis_caches_path_admission(void)
{
    char                           directory[PATH_SIZE];
    char                           source[PATH_SIZE];
    const char                    *paths[1];
    struct p101_c_analysis_options options;
    struct analysis_counts         counts;
    struct fault_state             state;
    int                            write_status;
    int                            directory_status;
    bool                           scan_result;
    bool                           has_error;
    int                            unlink_status;
    int                            remove_status;
    pid_t                          process_id;

    process_id   = getpid();
    write_status = snprintf(directory, sizeof(directory), "/tmp/p101-c-analysis-path-cache-%ld", (long)process_id);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, write_status);
    write_status = snprintf(source, sizeof(source), "%s/cache.c", directory);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, write_status);
    directory_status = mkdir(directory, 0700);
    TEST_ASSERT_EQUAL_INT(0, directory_status);
    write_file(source,
               "int function_00(void) { return 0; } int value_01; int value_02; int value_03; int value_04;\n"
               "int value_05; int value_06; int value_07; int value_08; int value_09;\n"
               "int value_10; int value_11; int value_12; int value_13; int value_14;\n"
               "int value_15; int value_16; int value_17; int value_18; int value_19;\n");

    memset(&options, 0, sizeof(options));
    memset(&counts, 0, sizeof(counts));
    paths[0]           = source;
    options.paths      = paths;
    options.path_count = 1U;
    state.call         = 0U;
    state.fail_at      = 0U;
    state.target       = "p101_realpath";
    p101_env_set_fault_injector(env, fail_selected_call, &state);
    scan_result = p101_c_analysis_scan(env, error, &options, count_record, &counts);
    has_error   = p101_error_has_error(error);
    p101_env_set_fault_injector(env, NULL, NULL);

    TEST_ASSERT_TRUE(scan_result);
    TEST_ASSERT_FALSE(has_error);
    TEST_ASSERT_EQUAL_UINT(2U, state.call);
    TEST_ASSERT_GREATER_THAN_UINT(0U, counts.functions);

    unlink_status = unlink(source);
    TEST_ASSERT_EQUAL_INT(0, unlink_status);
    remove_status = rmdir(directory);
    TEST_ASSERT_EQUAL_INT(0, remove_status);
}

static void test_call_results_must_be_isolated(void)
{
    char                           directory[PATH_SIZE];
    char                           source[PATH_SIZE];
    char                           cxx_source[PATH_SIZE];
    const char                    *paths[2];
    struct p101_c_analysis_options options;
    struct analysis_counts         counts;

    (void)snprintf(directory, sizeof(directory), "/tmp/p101-c-analysis-call-shape-%ld", (long)getpid());
    (void)snprintf(source, sizeof(source), "%s/call-shape.c", directory);
    (void)snprintf(cxx_source, sizeof(cxx_source), "%s/call-shape.cpp", directory);
    TEST_ASSERT_EQUAL_INT(0, mkdir(directory, 0700));
    write_file(source,
               "#include <errno.h>\n"
               "static int source(void) { int result; result = 1; return result; }\n"
               "static int *source_pointer(void) { static int value; return &value; }\n"
               "static int consume(int value) { return value; }\n"
               "static void sink(void) {}\n"
               "#define TRACE_CALL() ((void)sink())\n"
               "#define CLASSIFY(value) consume(value)\n"
               "#define EXPANDED_HELPER(value) ((*source_pointer()) + (value))\n"
               "static int good(void) {\n"
               "  int first;\n"
               "  int second = source();\n"
               "  first = source();\n"
               "  first = errno;\n"
               "  first = CLASSIFY(first);\n"
               "  first = EXPANDED_HELPER(first);\n"
               "  sink();\n"
               "  source();\n"
               "  TRACE_CALL();\n"
               "labeled:\n"
               "  sink();\n"
               "  first = consume(first);\n"
               "  return first + second;\n"
               "}\n"
               "static int bad_condition(void) {\n"
               "  int result = 0;\n"
               "  if(source()) { result = 1; }\n"
               "  return result;\n"
               "}\n"
               "static int bad_argument(void) {\n"
               "  int result;\n"
               "  result = consume(source());\n"
               "  return result;\n"
               "}\n"
               "static int bad_return(void) { return source(); }\n"
               "static int bad_arithmetic(void) {\n"
               "  int result;\n"
               "  result = source() + 1;\n"
               "  return result;\n"
               "}\n"
               "static bool good_implicit_conversion(void) {\n"
               "  bool result;\n"
               "  result = source();\n"
               "  return result;\n"
               "}\n"
               "static int bad_explicit_cast(void) {\n"
               "  int result;\n"
               "  result = (int)source();\n"
               "  return result;\n"
               "}\n"
               "static int bad_void_cast(void) {\n"
               "  int result = 0;\n"
               "  (void)source();\n"
               "  return result;\n"
               "}\n");
    write_file(cxx_source,
               "static int source() { int result; result = 1; return result; }\n"
               "static int consume(int value) { return value; }\n"
               "static void sink() {}\n"
               "#define TRACE_CALL() ((void)sink())\n"
               "static int good() {\n"
               "  int first;\n"
               "  int second = source();\n"
               "  first = source();\n"
               "  sink();\n"
               "  source();\n"
               "  TRACE_CALL();\n"
               "labeled:\n"
               "  sink();\n"
               "  first = consume(first);\n"
               "  return first + second;\n"
               "}\n"
               "static int bad_condition() {\n"
               "  int result = 0;\n"
               "  if(source()) { result = 1; }\n"
               "  return result;\n"
               "}\n"
               "static int bad_argument() {\n"
               "  int result;\n"
               "  result = consume(source());\n"
               "  return result;\n"
               "}\n"
               "static int bad_return() { return source(); }\n"
               "static int bad_arithmetic() {\n"
               "  int result;\n"
               "  result = source() + 1;\n"
               "  return result;\n"
               "}\n"
               "static bool good_implicit_conversion() {\n"
               "  bool result;\n"
               "  result = source();\n"
               "  return result;\n"
               "}\n"
               "static int bad_explicit_cast() {\n"
               "  int result;\n"
               "  result = (int)source();\n"
               "  return result;\n"
               "}\n"
               "static int bad_void_cast() {\n"
               "  int result = 0;\n"
               "  (void)source();\n"
               "  return result;\n"
               "}\n");

    memset(&options, 0, sizeof(options));
    memset(&counts, 0, sizeof(counts));
    paths[0]                       = source;
    paths[1]                       = cxx_source;
    options.paths                  = paths;
    options.path_count             = 2U;
    options.detailed_preprocessing = true;
    TEST_ASSERT_TRUE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_FALSE(p101_error_has_error(error));
    TEST_ASSERT_EQUAL_UINT(12U, counts.call_results_not_isolated);
    TEST_ASSERT_EQUAL_INT(0, unlink(cxx_source));
    TEST_ASSERT_EQUAL_INT(0, unlink(source));
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:c-fact-analysis:typed_refusal")

static void test_invalid_analysis_arguments(void)
{
    struct p101_c_analysis_options options;
    const char                    *paths[] = {"."};

    memset(&options, 0, sizeof(options));
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, count_record, NULL));
    TEST_ASSERT_TRUE(p101_error_has_error(error));
    p101_error_reset(error);
    options.paths      = paths;
    options.path_count = 1U;
    TEST_ASSERT_FALSE(p101_c_analysis_scan(env, error, &options, NULL, NULL));
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:c-fact-analysis:binding_swap")

static void test_clang_error_diagnostic_is_observable(void)
{
    char                           directory[PATH_SIZE];
    char                           source[PATH_SIZE];
    const char                    *paths[1];
    struct p101_c_analysis_options options;
    struct analysis_counts         counts;

    (void)snprintf(directory, sizeof(directory), "/tmp/p101-c-analysis-diagnostic-%ld", (long)getpid());
    (void)snprintf(source, sizeof(source), "%s/diagnostic.c", directory);
    TEST_ASSERT_EQUAL_INT(0, mkdir(directory, 0700));
    write_file(source, "#error intentional parser diagnostic\nint value;\n");
    memset(&options, 0, sizeof(options));
    memset(&counts, 0, sizeof(counts));
    paths[0]           = source;
    options.paths      = paths;
    options.path_count = 1U;
    options.keep_going = true;
    TEST_ASSERT_TRUE(p101_c_analysis_scan(env, error, &options, count_record, &counts));
    TEST_ASSERT_EQUAL_UINT(1U, counts.diagnostics);
    TEST_ASSERT_FALSE(p101_error_has_error(error));
    TEST_ASSERT_EQUAL_INT(0, unlink(source));
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

int main(void)
{
    UNITY_BEGIN();
    if(getenv("P101_WRAPPER_CONFORMANCE") != NULL)
    {
        /*
         * The complete repository test gate runs every case. Wrapper
         * conformance needs representative public-API evidence, not millions
         * of repeated parser events from the semantic stress fixtures.
         */
        RUN_TEST(test_wrapper_conformance_smoke);
        RUN_TEST(test_invalid_analysis_arguments);
        return UNITY_END();
    }
    RUN_TEST(test_analysis_and_compile_command);
    RUN_TEST(test_directory_analysis_exercises_semantic_records);
    RUN_TEST(test_call_results_must_be_isolated);
    RUN_TEST(test_analysis_failures_and_faults);
    RUN_TEST(test_analysis_caches_path_admission);
    RUN_TEST(test_invalid_analysis_arguments);
    RUN_TEST(test_clang_error_diagnostic_is_observable);
    return UNITY_END();
}
