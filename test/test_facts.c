#include "p101_c_facts/facts.h"
#include "p101_c_facts/project.h"
#include "unity.h"
#include <p101_c/p101_string.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static enum p101_c_fact_status parse(char *line, struct p101_c_fact *fact)
{
    return p101_c_fact_parse_line(env, error, line, fact);
}

static void test_parse_function_fact(void)
{
    char                    line[] = "P101FACT\t2\tFUNCTION\t/tmp/demo.c\tdemo\t0\t42\thelper\t1\t0\n";
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
    TEST_ASSERT_TRUE(fact.flag1);
    TEST_ASSERT_FALSE(fact.flag2);
}

static void test_parse_include_fact(void)
{
    char               line[] = "P101FACT\t2\tINCLUDE\t/tmp/demo.c\tdemo\t0\t7\tp101_c/p101_string.h\t0\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(line, &fact));
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_KIND_INCLUDE, fact.kind);
    TEST_ASSERT_EQUAL_STRING("p101_c/p101_string.h", fact.value);
    TEST_ASSERT_FALSE(fact.flag1);
}

static void test_unescapes_fields(void)
{
    char               line[] = "P101FACT\t2\tCALL\t/tmp/a\\\\b.c\tm\t0\t3\tthing\\tname\t1\t1\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(line, &fact));
    TEST_ASSERT_EQUAL_STRING("/tmp/a\\b.c", fact.path);
    TEST_ASSERT_EQUAL_STRING("thing\tname", fact.value);
    TEST_ASSERT_TRUE(fact.flag1);
    TEST_ASSERT_TRUE(fact.flag2);
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
    char               line[] = "P101FACT\t2\tFUNCTION\t/tmp/demo.c\tdemo\t0\tline\thelper\t1\t0\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_MALFORMED, parse(line, &fact));
}

static void test_kind_names_are_stable(void)
{
    TEST_ASSERT_EQUAL_STRING("FUNCTION", p101_c_fact_kind_name(P101_C_FACT_KIND_FUNCTION));
    TEST_ASSERT_EQUAL_STRING("bad_version", p101_c_fact_status_name(P101_C_FACT_BAD_VERSION));
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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_parse_function_fact);
    RUN_TEST(test_parse_include_fact);
    RUN_TEST(test_unescapes_fields);
    RUN_TEST(test_non_fact_line_is_other);
    RUN_TEST(test_bad_version_is_reported);
    RUN_TEST(test_malformed_fact_is_reported);
    RUN_TEST(test_kind_names_are_stable);
    RUN_TEST(test_finds_versioned_clang_compile_database);
    return UNITY_END();
}
