#include "p101_c_facts/facts.h"
#include "p101_c_facts/project.h"
#include "unity.h"
#include <errno.h>
#include <p101_c/p101_string.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct p101_error *error;
static struct p101_env   *env;
static unsigned int       temporary_sequence;

struct fault_plan
{
    const char *call_name;
    size_t      occurrence;
};

static void make_temporary_directory(char *directory, size_t size);
static void write_text_file(const char *path, const char *text);
static int  inject_selected_fault(const struct p101_env *fault_env, const char *call_name, void *user_data);
static void create_directory(const char *path);

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

static enum p101_c_fact_status parse(char *line, struct p101_c_fact *fact)
{
    return p101_c_fact_parse_line(env, error, line, fact);
}

static void make_temporary_directory(char *directory, size_t size)
{
    (void)snprintf(directory, size, "/tmp/p101-c-facts-%ld-%u", (long)getpid(), temporary_sequence++);
    TEST_ASSERT_EQUAL_INT(0, mkdir(directory, 0700));
}

static void write_text_file(const char *path, const char *text)
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

static void create_directory(const char *path)
{
    TEST_ASSERT_EQUAL_INT(0, mkdir(path, 0700));
}

static int inject_selected_fault(const struct p101_env *fault_env, const char *call_name, void *user_data)
{
    struct fault_plan *plan;

    (void)fault_env;
    plan = (struct fault_plan *)user_data;
    if(strcmp(call_name, plan->call_name) != 0 || plan->occurrence == 0U)
    {
        return 0;
    }
    plan->occurrence--;
    return plan->occurrence == 0U ? EIO : 0;
}

static void test_parse_function_fact(void)
{
    char                    line[] = "P101FACT\t7\tFUNCTION\t/tmp/demo.c\tdemo\t0\t42\thelper\t1\t0\tc:@F@helper\t100\t200\n";
    struct p101_c_fact      fact;
    enum p101_c_fact_status status;

    status = parse(line, &fact);

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, status);
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_KIND_FUNCTION, fact.kind);
    TEST_ASSERT_EQUAL_STRING("/tmp/demo.c", fact.path);
    TEST_ASSERT_EQUAL_STRING("demo", fact.module);
    TEST_ASSERT_FALSE(fact.is_header);
    TEST_ASSERT_EQUAL_UINT64(42U, fact.line);
    TEST_ASSERT_EQUAL_STRING("helper", fact.value);
    TEST_ASSERT_TRUE(fact.is_static);
    TEST_ASSERT_FALSE(fact.is_declaration);
    TEST_ASSERT_EQUAL_STRING("c:@F@helper", fact.usr);
    TEST_ASSERT_EQUAL_UINT64(100U, fact.start);
    TEST_ASSERT_EQUAL_UINT64(200U, fact.end);
}

static void test_parse_include_fact(void)
{
    char               line[]       = "P101FACT\t7\tINCLUDE\t/tmp/demo.c\tdemo\t0\t7\tp101_c/p101_string.h\t0\t/usr/include/p101_c/p101_string.h\n";
    char               unresolved[] = "P101FACT\t7\tINCLUDE\t/tmp/demo.c\tdemo\t0\t8\tmissing.h\t1\t\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(line, &fact));
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_KIND_INCLUDE, fact.kind);
    TEST_ASSERT_EQUAL_STRING("p101_c/p101_string.h", fact.value);
    TEST_ASSERT_FALSE(fact.is_local);
    TEST_ASSERT_EQUAL_STRING("/usr/include/p101_c/p101_string.h", fact.resolved);

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(unresolved, &fact));
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_KIND_INCLUDE, fact.kind);
    TEST_ASSERT_EQUAL_STRING("missing.h", fact.value);
    TEST_ASSERT_TRUE(fact.is_local);
    TEST_ASSERT_EQUAL_STRING("", fact.resolved);
}

static void test_unescapes_fields(void)
{
    char               line[] = "P101FACT\t7\tCALL\t/tmp/a\\\\b.c\tm\t0\t3\tthing\\tname\t1\t1\t1\tcaller\\tname\tcallee-usr\tcaller-usr\t20\t30\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(line, &fact));
    TEST_ASSERT_EQUAL_STRING("/tmp/a\\b.c", fact.path);
    TEST_ASSERT_EQUAL_STRING("thing\tname", fact.value);
    TEST_ASSERT_EQUAL_STRING("caller\tname", fact.caller);
    TEST_ASSERT_EQUAL_STRING("callee-usr", fact.usr);
    TEST_ASSERT_EQUAL_STRING("caller-usr", fact.caller_usr);
    TEST_ASSERT_TRUE(fact.has_env_parameter);
    TEST_ASSERT_TRUE(fact.has_error_parameter);
    TEST_ASSERT_TRUE(fact.is_indirect);
}

static void test_parse_note_caller_and_column(void)
{
    char               line[] = "P101FACT\t7\tNOTE\t/tmp/demo.c\tdemo\t0\t9\tFUNCTION_RETURN\thelper\t17\tc:@F@helper\t40\t50\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(line, &fact));
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_KIND_NOTE, fact.kind);
    TEST_ASSERT_EQUAL_STRING("FUNCTION_RETURN", fact.value);
    TEST_ASSERT_EQUAL_STRING("helper", fact.caller);
    TEST_ASSERT_EQUAL_UINT64(17U, fact.column);
    TEST_ASSERT_EQUAL_STRING("c:@F@helper", fact.caller_usr);
}

static void test_parse_enum_facts(void)
{
    char               enum_line[]       = "P101FACT\t7\tENUM\t/tmp/demo.h\tdemo\t1\t9\tp101_result\tc:@E@p101_result\n";
    char               enumerator_line[] = "P101FACT\t7\tENUMERATOR\t/tmp/demo.h\tdemo\t1\t10\tP101_RESULT_OK\tp101_result\tc:@E@p101_result@P101_RESULT_OK\tc:@E@p101_result\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(enum_line, &fact));
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_KIND_ENUM, fact.kind);
    TEST_ASSERT_EQUAL_STRING("p101_result", fact.value);
    TEST_ASSERT_EQUAL_STRING("c:@E@p101_result", fact.usr);
    TEST_ASSERT_NULL(fact.caller);

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(enumerator_line, &fact));
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_KIND_ENUMERATOR, fact.kind);
    TEST_ASSERT_EQUAL_STRING("P101_RESULT_OK", fact.value);
    TEST_ASSERT_EQUAL_STRING("p101_result", fact.caller);
    TEST_ASSERT_EQUAL_STRING("c:@E@p101_result@P101_RESULT_OK", fact.usr);
    TEST_ASSERT_EQUAL_STRING("c:@E@p101_result", fact.caller_usr);
}

static void test_non_fact_line_is_other(void)
{
    char               line[] = "hello world\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OTHER, parse(line, &fact));
}

static void test_bad_version_is_reported(void)
{
    char               line[] = "P101FACT\t1\tFILE\t/tmp/demo.c\tdemo\t0\t0\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_BAD_VERSION, parse(line, &fact));
}

static void test_malformed_fact_is_reported(void)
{
    char               line[] = "P101FACT\t7\tFUNCTION\t/tmp/demo.c\tdemo\t0\tline\thelper\t1\t0\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_MALFORMED, parse(line, &fact));
}

static void test_non_boolean_flag_is_malformed(void)
{
    char               line[] = "P101FACT\t7\tFUNCTION\t/tmp/demo.c\tdemo\t2\t4\thelper\t1\t0\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_MALFORMED, parse(line, &fact));
}

static void test_parse_all_fact_kinds_and_names(void)
{
    static const char *const lines[] = {
        "P101FACT\t7\tFILE\t/tmp/demo.c\tdemo\t0\t1\r",
        "P101FACT\t7\tINCLUDE\t/tmp/demo.c\tdemo\t1\t2\tstdio.h\t1\t/usr/include/stdio.h\n",
        "P101FACT\t7\tFUNCTION\t/tmp/demo.c\tdemo\t0\t3\tmain\t0\t1\tc:@F@main\t0\t0\n",
        "P101FACT\t7\tCALL\t/tmp/demo.c\tdemo\t0\t4\tputs\t1\t0\t0\tmain\tc:@F@puts\tc:@F@main\t0\t0\n",
        "P101FACT\t7\tTYPE\t/tmp/demo.c\tdemo\t0\t5\twidget\tc:@S@widget\n",
        "P101FACT\t7\tENUM\t/tmp/demo.c\tdemo\t0\t6\tresult\tc:@E@result\n",
        "P101FACT\t7\tENUMERATOR\t/tmp/demo.c\tdemo\t0\t7\tRESULT_OK\tresult\tc:@E@result@RESULT_OK\tc:@E@result\n",
        "P101FACT\t7\tMACRO\t/tmp/demo.c\tdemo\t0\t8\tLIMIT\t1\t\t0\t0\n",
        "P101FACT\t7\tNOTE\t/tmp/demo.c\tdemo\t0\t9\tadvice\tmain\t11\tc:@F@main\t0\t0\n",
        "P101FACT\t7\tNOT-A-KIND\t/tmp/demo.c\tdemo\t0\t10\n",
    };

    static const enum p101_c_fact_kind kinds[] = {
        P101_C_FACT_KIND_FILE,
        P101_C_FACT_KIND_INCLUDE,
        P101_C_FACT_KIND_FUNCTION,
        P101_C_FACT_KIND_CALL,
        P101_C_FACT_KIND_TYPE,
        P101_C_FACT_KIND_ENUM,
        P101_C_FACT_KIND_ENUMERATOR,
        P101_C_FACT_KIND_MACRO,
        P101_C_FACT_KIND_NOTE,
        P101_C_FACT_KIND_UNKNOWN,
    };

    static const char *const names[] = {"FILE", "INCLUDE", "FUNCTION", "CALL", "TYPE", "ENUM", "ENUMERATOR", "MACRO", "NOTE", "UNKNOWN"};

    for(size_t index = 0U; index < sizeof(lines) / sizeof(lines[0]); index++)
    {
        char               line[512];
        struct p101_c_fact fact;

        (void)snprintf(line, sizeof(line), "%s", lines[index]);
        TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(line, &fact));
        TEST_ASSERT_EQUAL_INT(kinds[index], fact.kind);
        TEST_ASSERT_EQUAL_STRING(names[index], p101_c_fact_kind_name(kinds[index]));
    }
    TEST_ASSERT_EQUAL_STRING("unknown", p101_c_fact_kind_name((enum p101_c_fact_kind)99));
}

static void test_status_names_are_stable(void)
{
    TEST_ASSERT_EQUAL_STRING("ok", p101_c_fact_status_name(P101_C_FACT_OK));
    TEST_ASSERT_EQUAL_STRING("other", p101_c_fact_status_name(P101_C_FACT_OTHER));
    TEST_ASSERT_EQUAL_STRING("bad_version", p101_c_fact_status_name(P101_C_FACT_BAD_VERSION));
    TEST_ASSERT_EQUAL_STRING("malformed", p101_c_fact_status_name(P101_C_FACT_MALFORMED));
    TEST_ASSERT_EQUAL_STRING("unknown", p101_c_fact_status_name((enum p101_c_fact_status)99));
}

static void test_note_kind_names_round_trip(void)
{
    static const enum p101_c_note_kind kinds[] = {
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
    };

    for(size_t index = 0U; index < sizeof(kinds) / sizeof(kinds[0]); index++)
    {
        const char *name;

        name = p101_c_note_kind_name(kinds[index]);
        TEST_ASSERT_EQUAL_INT(kinds[index], p101_c_note_kind_from_name(env, name));
    }

    TEST_ASSERT_EQUAL_STRING("TYPE_SEMANTIC_ROLE:p101:trace-scope", p101_c_note_kind_name(P101_C_NOTE_TRACE_USE));
    TEST_ASSERT_EQUAL_STRING("OTHER", p101_c_note_kind_name(P101_C_NOTE_OTHER));
    TEST_ASSERT_EQUAL_STRING("OTHER", p101_c_note_kind_name((enum p101_c_note_kind)99));
    TEST_ASSERT_EQUAL_STRING("SEMANTIC_ROLE:p101:termination-adapter", p101_c_note_kind_name(P101_C_NOTE_TERMINATION_ADAPTER));
    TEST_ASSERT_EQUAL_STRING("CALLEE_SEMANTIC_ROLE:p101:ownership:error:acquire", p101_c_note_kind_name(P101_C_NOTE_OWNERSHIP_ERROR_ACQUIRE));
    TEST_ASSERT_EQUAL_STRING("CALLEE_SEMANTIC_ROLE:p101:ownership:error:release", p101_c_note_kind_name(P101_C_NOTE_OWNERSHIP_ERROR_RELEASE));
    TEST_ASSERT_EQUAL_STRING("CALLEE_SEMANTIC_ROLE:p101:ownership:env:acquire", p101_c_note_kind_name(P101_C_NOTE_OWNERSHIP_ENV_ACQUIRE));
    TEST_ASSERT_EQUAL_STRING("CALLEE_SEMANTIC_ROLE:p101:ownership:env:release", p101_c_note_kind_name(P101_C_NOTE_OWNERSHIP_ENV_RELEASE));
    TEST_ASSERT_EQUAL_INT(P101_C_NOTE_OTHER, p101_c_note_kind_from_name(env, NULL));
    TEST_ASSERT_EQUAL_INT(P101_C_NOTE_TERMINATION_ADAPTER, p101_c_note_kind_from_name(env, "SEMANTIC_ROLE:p101:termination-adapter"));
    TEST_ASSERT_EQUAL_INT(P101_C_NOTE_OTHER, p101_c_note_kind_from_name(env, "SEMANTIC_ROLE:p101:not-a-real-role"));
    TEST_ASSERT_EQUAL_INT(P101_C_NOTE_OTHER, p101_c_note_kind_from_name(env, "OTHER"));
}

static void test_rejects_invalid_fact_shapes(void)
{
    static const char *const malformed[] = {
        "P101FACT\t7\n",
        "P101FACT\t7\tFILE\t/tmp/demo.c\tdemo\t0\tnot-a-line\n",
        "P101FACT\t7\tFILE\t/tmp/demo.c\tdemo\tmaybe\t1\n",
        "P101FACT\t7\tINCLUDE\t/tmp/demo.c\tdemo\t0\t1\tstdio.h\n",
        "P101FACT\t7\tINCLUDE\t/tmp/demo.c\tdemo\t0\t1\tstdio.h\t1\n",
        "P101FACT\t7\tFUNCTION\t/tmp/demo.c\tdemo\t0\t1\tmain\t1\n",
        "P101FACT\t7\tCALL\t/tmp/demo.c\tdemo\t0\t1\tputs\t1\n",
        "P101FACT\t7\tCALL\t/tmp/demo.c\tdemo\t0\t1\tputs\t0\t0\tbad\tmain\tc:@F@puts\tc:@F@main\t0\t0\n",
        "P101FACT\t7\tTYPE\t/tmp/demo.c\tdemo\t0\t1\n",
        "P101FACT\t7\tMACRO\t/tmp/demo.c\tdemo\t0\t1\n",
        "P101FACT\t7\tNOTE\t/tmp/demo.c\tdemo\t0\t1\n",
        "P101FACT\t7\tFUNCTION\t/tmp/demo.c\tdemo\t0\t1\tmain\tbad\t0\n",
        "P101FACT\t7\tFUNCTION\t/tmp/demo.c\tdemo\t0\t1\tmain\t1\tbad\n",
        "P101FACT\t7\tFILE\t/tmp/demo.c\tdemo\t0\t1\ta\tb\tc\td\te\tf\tg\th\ti\tj\n",
    };
    struct p101_c_fact fact;
    char               valid[] = "P101FACT\t7\tFILE\t/tmp/demo.c\tdemo\t0\t1\n";

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_MALFORMED, p101_c_fact_parse_line(env, error, NULL, &fact));
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_MALFORMED, p101_c_fact_parse_line(env, error, valid, NULL));
    for(size_t index = 0U; index < sizeof(malformed) / sizeof(malformed[0]); index++)
    {
        char line[192];

        (void)snprintf(line, sizeof(line), "%s", malformed[index]);
        TEST_ASSERT_EQUAL_INT(P101_C_FACT_MALFORMED, parse(line, &fact));
    }

    {
        char maximum_fields[] = "P101FACT\t7\tUNKNOWN\t/tmp/demo.c\tdemo\t0\t1\tvalue\t0\t1\ta\tb\tc\td\te\tf\n";

        TEST_ASSERT_EQUAL_INT(P101_C_FACT_MALFORMED, parse(maximum_fields, &fact));
    }
}

static void test_finds_versioned_clang_compile_database(void)
{
    char  directory[256];
    char  build_directory[320];
    char  database[384];
    char  last_build[320];
    char  found[384];
    FILE *stream;

    snprintf(directory, sizeof(directory), "/tmp/p101-c-facts-%ld", (long)getpid());
    snprintf(build_directory, sizeof(build_directory), "%s/build-clang-22", directory);
    snprintf(database, sizeof(database), "%s/compile_commands.json", build_directory);
    snprintf(last_build, sizeof(last_build), "%s/.last-build-dir", directory);
    (void)mkdir(directory, 0700);
    TEST_ASSERT_EQUAL_INT(0, mkdir(build_directory, 0700));

    stream = fopen(database, "w");
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_TRUE(fputs("[]\n", stream) >= 0);
    TEST_ASSERT_EQUAL_INT(0, fclose(stream));
    stream = fopen(last_build, "w");
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_TRUE(fputs("build-clang-22\n", stream) >= 0);
    TEST_ASSERT_EQUAL_INT(0, fclose(stream));

    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_FALSE(p101_error_has_error(error));
    TEST_ASSERT_EQUAL_STRING(database, found);

    TEST_ASSERT_EQUAL_INT(0, unlink(last_build));
    TEST_ASSERT_EQUAL_INT(0, unlink(database));
    TEST_ASSERT_EQUAL_INT(0, rmdir(build_directory));
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

static void test_compile_database_fallbacks_and_absolute_paths(void)
{
    char directory[256];
    char build_directory[320];
    char nested_directory[320];
    char database[384];
    char fallback_directory[320];
    char fallback_database[384];
    char absolute_directory[320];
    char absolute_database[384];
    char last_build[320];
    char found[384];

    make_temporary_directory(directory, sizeof(directory));
    (void)snprintf(fallback_directory, sizeof(fallback_directory), "%s/build-clang", directory);
    (void)snprintf(fallback_database, sizeof(fallback_database), "%s/compile_commands.json", fallback_directory);
    (void)snprintf(last_build, sizeof(last_build), "%s/.last-build-dir", directory);
    create_directory(fallback_directory);
    write_text_file(fallback_database, "[]\n");
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(fallback_database, found);

    write_text_file(last_build, "build-gcc\n");
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(fallback_database, found);

    write_text_file(last_build, "build-clang");
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(fallback_database, found);

    (void)snprintf(build_directory, sizeof(build_directory), "%s/build-clang__clang++__quality-maximal", directory);
    create_directory(build_directory);
    (void)snprintf(database, sizeof(database), "%s/compile_commands.json", build_directory);
    write_text_file(database, "[]\n");
    write_text_file(last_build, "build-clang__clang++__quality-maximal\n");
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(database, found);
    TEST_ASSERT_EQUAL_INT(0, unlink(database));
    TEST_ASSERT_EQUAL_INT(0, rmdir(build_directory));

    write_text_file(last_build, "nested/build-clangx");
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(fallback_database, found);

    (void)snprintf(nested_directory, sizeof(nested_directory), "%s/nested", directory);
    create_directory(nested_directory);
    (void)snprintf(build_directory, sizeof(build_directory), "%s/nested/build-clang-23", directory);
    create_directory(build_directory);
    (void)snprintf(database, sizeof(database), "%s/compile_commands.json", build_directory);
    write_text_file(database, "[]\n");
    write_text_file(last_build, "nested/build-clang-23\r\n");
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(database, found);

    (void)snprintf(absolute_directory, sizeof(absolute_directory), "/tmp/build-clang-p101-c-facts-%ld-%u", (long)getpid(), temporary_sequence++);
    create_directory(absolute_directory);
    (void)snprintf(absolute_database, sizeof(absolute_database), "%s/compile_commands.json", absolute_directory);
    write_text_file(absolute_database, "[]\n");
    write_text_file(last_build, absolute_directory);
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(absolute_database, found);

    write_text_file(last_build, "");
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(fallback_database, found);

    {
        FILE *stream = fopen(last_build, "wb");

        TEST_ASSERT_NOT_NULL(stream);
        if(stream != NULL)
        {
            TEST_ASSERT_EQUAL_size_t(1U, fwrite("", 1U, 1U, stream));
            TEST_ASSERT_EQUAL_INT(0, fclose(stream));
        }
    }
    TEST_ASSERT_TRUE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING(fallback_database, found);

    TEST_ASSERT_EQUAL_INT(0, unlink(last_build));
    TEST_ASSERT_EQUAL_INT(0, unlink(absolute_database));
    TEST_ASSERT_EQUAL_INT(0, rmdir(absolute_directory));
    TEST_ASSERT_EQUAL_INT(0, unlink(database));
    TEST_ASSERT_EQUAL_INT(0, rmdir(build_directory));
    TEST_ASSERT_EQUAL_INT(0, rmdir(nested_directory));
    TEST_ASSERT_EQUAL_INT(0, unlink(fallback_database));
    TEST_ASSERT_EQUAL_INT(0, rmdir(fallback_directory));
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

static void test_compile_database_missing_and_invalid_arguments(void)
{
    char               directory[256];
    char               found[384];
    char               tiny[1];
    char               long_directory[5000];
    struct p101_error *local_error;
    struct p101_env   *local_env;

    make_temporary_directory(directory, sizeof(directory));
    TEST_ASSERT_FALSE(p101_c_facts_find_clang_compile_database(env, error, directory, found, sizeof(found)));
    TEST_ASSERT_EQUAL_STRING("", found);
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));

    local_error = p101_error_create(false);
    local_env   = p101_env_create(local_error, NULL);
    TEST_ASSERT_FALSE(p101_c_facts_find_clang_compile_database(local_env, local_error, NULL, found, sizeof(found)));
    TEST_ASSERT_TRUE(p101_error_has_error(local_error));
    p101_env_destroy(local_env);
    p101_error_destroy(local_error);

    local_error = p101_error_create(false);
    local_env   = p101_env_create(local_error, NULL);
    TEST_ASSERT_FALSE(p101_c_facts_find_clang_compile_database(local_env, local_error, ".", NULL, sizeof(found)));
    TEST_ASSERT_TRUE(p101_error_has_error(local_error));
    p101_env_destroy(local_env);
    p101_error_destroy(local_error);

    local_error = p101_error_create(false);
    local_env   = p101_env_create(local_error, NULL);
    TEST_ASSERT_FALSE(p101_c_facts_find_clang_compile_database(local_env, local_error, ".", found, 0U));
    TEST_ASSERT_TRUE(p101_error_has_error(local_error));
    p101_env_destroy(local_env);
    p101_error_destroy(local_error);

    make_temporary_directory(directory, sizeof(directory));
    local_error = p101_error_create(false);
    local_env   = p101_env_create(local_error, NULL);
    TEST_ASSERT_FALSE(p101_c_facts_find_clang_compile_database(local_env, local_error, directory, tiny, sizeof(tiny)));
    TEST_ASSERT_FALSE(p101_error_has_error(local_error));
    p101_env_destroy(local_env);
    p101_error_destroy(local_error);
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));

    memset(long_directory, 'x', sizeof(long_directory) - 1U);
    long_directory[sizeof(long_directory) - 1U] = '\0';
    local_error                                 = p101_error_create(false);
    local_env                                   = p101_env_create(local_error, NULL);
    TEST_ASSERT_FALSE(p101_c_facts_find_clang_compile_database(local_env, local_error, long_directory, found, sizeof(found)));
    TEST_ASSERT_FALSE(p101_error_has_error(local_error));
    p101_env_destroy(local_env);
    p101_error_destroy(local_error);
}

static void test_compile_database_wrapper_failures(void)
{
    static const struct fault_plan plans[] = {
        {"snprintf", 1U},
        {"snprintf", 2U},
        {"fopen",    1U},
        {"fgets",    1U},
        {"fclose",   1U},
        {"access",   1U},
    };

    for(size_t index = 0U; index < sizeof(plans) / sizeof(plans[0]); index++)
    {
        char               directory[256];
        char               build_directory[320];
        char               database[384];
        char               last_build[320];
        char               found[384];
        struct fault_plan  plan;
        struct p101_error *local_error;
        struct p101_env   *local_env;

        make_temporary_directory(directory, sizeof(directory));
        (void)snprintf(build_directory, sizeof(build_directory), "%s/build-clang-22", directory);
        (void)snprintf(database, sizeof(database), "%s/compile_commands.json", build_directory);
        (void)snprintf(last_build, sizeof(last_build), "%s/.last-build-dir", directory);
        create_directory(build_directory);
        write_text_file(database, "[]\n");
        write_text_file(last_build, "build-clang-22\n");

        plan        = plans[index];
        local_error = p101_error_create(false);
        local_env   = p101_env_create(local_error, NULL);
        p101_env_set_fault_injector(local_env, inject_selected_fault, &plan);
        (void)p101_c_facts_find_clang_compile_database(local_env, local_error, directory, found, sizeof(found));
        if(strcmp(plans[index].call_name, "access") == 0)
        {
            TEST_ASSERT_FALSE(p101_error_has_error(local_error));
        }
        else
        {
            TEST_ASSERT_TRUE(p101_error_has_error(local_error));
        }
        p101_env_destroy(local_env);
        p101_error_destroy(local_error);

        TEST_ASSERT_EQUAL_INT(0, unlink(last_build));
        TEST_ASSERT_EQUAL_INT(0, unlink(database));
        TEST_ASSERT_EQUAL_INT(0, rmdir(build_directory));
        TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
    }
}

static void test_compile_database_fallback_format_failure(void)
{
    char               directory[256];
    char               found[384];
    struct fault_plan  plan;
    struct p101_error *local_error;
    struct p101_env   *local_env;

    make_temporary_directory(directory, sizeof(directory));
    plan.call_name  = "snprintf";
    plan.occurrence = 2U;
    local_error     = p101_error_create(false);
    local_env       = p101_env_create(local_error, NULL);
    p101_env_set_fault_injector(local_env, inject_selected_fault, &plan);
    TEST_ASSERT_FALSE(p101_c_facts_find_clang_compile_database(local_env, local_error, directory, found, sizeof(found)));
    TEST_ASSERT_TRUE(p101_error_has_error(local_error));
    TEST_ASSERT_EQUAL_STRING("", found);
    p101_env_destroy(local_env);
    p101_error_destroy(local_error);
    TEST_ASSERT_EQUAL_INT(0, rmdir(directory));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_parse_function_fact);
    RUN_TEST(test_parse_include_fact);
    RUN_TEST(test_unescapes_fields);
    RUN_TEST(test_parse_note_caller_and_column);
    RUN_TEST(test_parse_enum_facts);
    RUN_TEST(test_non_fact_line_is_other);
    RUN_TEST(test_bad_version_is_reported);
    RUN_TEST(test_malformed_fact_is_reported);
    RUN_TEST(test_non_boolean_flag_is_malformed);
    RUN_TEST(test_parse_all_fact_kinds_and_names);
    RUN_TEST(test_status_names_are_stable);
    RUN_TEST(test_note_kind_names_round_trip);
    RUN_TEST(test_rejects_invalid_fact_shapes);
    RUN_TEST(test_finds_versioned_clang_compile_database);
    RUN_TEST(test_compile_database_fallbacks_and_absolute_paths);
    RUN_TEST(test_compile_database_missing_and_invalid_arguments);
    RUN_TEST(test_compile_database_wrapper_failures);
    RUN_TEST(test_compile_database_fallback_format_failure);
    return UNITY_END();
}
