#include "p101_c_facts/facts.h"
#include "unity.h"
#include <p101_c/p101_string.h>
#include <string.h>

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
    char                 line[] = "P101FACT\t1\tFUNCTION\t/tmp/demo.c\tdemo\t0\t42\thelper\t1\t0\n";
    struct p101_c_fact   fact;
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
    char               line[] = "P101FACT\t1\tINCLUDE\t/tmp/demo.c\tdemo\t0\t7\tp101_c/p101_string.h\t0\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(line, &fact));
    TEST_ASSERT_EQUAL_INT(P101_C_FACT_KIND_INCLUDE, fact.kind);
    TEST_ASSERT_EQUAL_STRING("p101_c/p101_string.h", fact.value);
    TEST_ASSERT_FALSE(fact.flag1);
}

static void test_unescapes_fields(void)
{
    char               line[] = "P101FACT\t1\tCALL\t/tmp/a\\\\b.c\tm\t0\t3\tthing\\tname\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OK, parse(line, &fact));
    TEST_ASSERT_EQUAL_STRING("/tmp/a\\b.c", fact.path);
    TEST_ASSERT_EQUAL_STRING("thing\tname", fact.value);
}

static void test_non_fact_line_is_other(void)
{
    char               line[] = "hello world\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_OTHER, parse(line, &fact));
}

static void test_bad_version_is_reported(void)
{
    char               line[] = "P101FACT\t2\tFILE\t/tmp/demo.c\tdemo\t0\t0\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_BAD_VERSION, parse(line, &fact));
}

static void test_malformed_fact_is_reported(void)
{
    char               line[] = "P101FACT\t1\tFUNCTION\t/tmp/demo.c\tdemo\t0\tline\thelper\t1\t0\n";
    struct p101_c_fact fact;

    TEST_ASSERT_EQUAL_INT(P101_C_FACT_MALFORMED, parse(line, &fact));
}

static void test_kind_names_are_stable(void)
{
    TEST_ASSERT_EQUAL_STRING("FUNCTION", p101_c_fact_kind_name(P101_C_FACT_KIND_FUNCTION));
    TEST_ASSERT_EQUAL_STRING("bad_version", p101_c_fact_status_name(P101_C_FACT_BAD_VERSION));
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
    return UNITY_END();
}
