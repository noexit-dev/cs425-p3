#include "harness/unity.h"
#include "../src/lab.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_addresses(void)
{
  uint32_t addr = 42;
  char text[CIDR_STR_LEN];
  const char *bad[] = {"", "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1", "1.2.3.4x", "+1.2.3.4", " 1.2.3.4", "1.2.3.4 ", "1.2.3.", "999999999999.1.1.1", "0x.1.2.3"};
  for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
    TEST_ASSERT_FALSE(ip_parse(bad[i], &addr)); TEST_ASSERT_EQUAL_UINT32(42, addr);
  }
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr)); TEST_ASSERT_FALSE(ip_parse("0.0.0.0", NULL));
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr)); TEST_ASSERT_EQUAL_HEX32(0xc0a8010a, addr);
  ip_format(addr, text); TEST_ASSERT_EQUAL_STRING("192.168.1.10", text);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr)); TEST_ASSERT_EQUAL_UINT32(0, addr);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr)); TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, addr);
  cidr_t block = {42, 7};
  const char *bad_cidr[] = {"", "1.2.3.4", "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/", "1.2.3/24", "1.2.3.4/2x", "1.2.3.4/+2", "255.255.255.2555/2", "/0"};
  for (size_t i = 0; i < sizeof bad_cidr / sizeof *bad_cidr; ++i) {
    TEST_ASSERT_FALSE(cidr_parse(bad_cidr[i], &block)); TEST_ASSERT_EQUAL_UINT32(42, block.addr); TEST_ASSERT_EQUAL_UINT8(7, block.prefix);
  }
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block)); TEST_ASSERT_FALSE(cidr_parse("0.0.0.0/0", NULL));
  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  cidr_format(block, text); TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", text);
  block.prefix = 255; cidr_format(block, text); TEST_ASSERT_EQUAL_STRING("132.178.227.11/32", text);
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
}

static void test_subnets(void)
{
  for (unsigned p = 0; p <= 33; ++p) {
    cidr_t block = {UINT32_MAX, (uint8_t)p};
    uint32_t mask = p == 0 ? 0 : (uint32_t)(UINT64_C(0xffffffff) << (32 - (p > 32 ? 32 : p)));
    TEST_ASSERT_EQUAL_HEX32(mask, cidr_mask((uint8_t)p));
    TEST_ASSERT_EQUAL_HEX32(mask, cidr_network(block));
    TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_broadcast(block));
    TEST_ASSERT_EQUAL_HEX32(mask + (p < 31), cidr_first_host(block));
    TEST_ASSERT_EQUAL_HEX32(UINT32_MAX - (p < 31), cidr_last_host(block));
    TEST_ASSERT_EQUAL_UINT64(p >= 32 ? 1 : p == 31 ? 2 : (UINT64_C(1) << (32 - p)) - 2, cidr_host_count(block));
    TEST_ASSERT_TRUE(cidr_contains(block, UINT32_MAX));
    TEST_ASSERT_EQUAL(p >= 32, cidr_is_network(block));
  }
  cidr_t b = {0xc0a80100, 24}, out = {42, 7};
  TEST_ASSERT_FALSE(cidr_contains(b, 0)); TEST_ASSERT_TRUE(cidr_is_network(b));
  for (uint32_t i = 0; i < 4; ++i) {
    TEST_ASSERT_TRUE(cidr_subnet(b, 4, i, &out)); TEST_ASSERT_EQUAL_UINT8(26, out.prefix);
    TEST_ASSERT_EQUAL_HEX32(b.addr + i * 64, out.addr);
  }
  TEST_ASSERT_TRUE(cidr_subnet((cidr_t){0, 0}, UINT32_C(1) << 31, (UINT32_C(1) << 31) - 1, &out));
  TEST_ASSERT_EQUAL_HEX32(0xfffffffe, out.addr);
  TEST_ASSERT_TRUE(cidr_subnet((cidr_t){0, 0}, 1, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(b, 1, 0, NULL));
  TEST_ASSERT_FALSE(cidr_subnet((cidr_t){1,24}, 2, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(b, 0, 0, &out)); TEST_ASSERT_FALSE(cidr_subnet(b, 3, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(b, 2, 2, &out)); TEST_ASSERT_FALSE(cidr_subnet(b, 512, 0, &out));
  TEST_ASSERT_EQUAL_UINT32(0, out.addr); TEST_ASSERT_EQUAL_UINT8(0, out.prefix);
}

static void test_routes(void)
{
  route_t route = {.gateway = 42};
  const char *bad[] = {"", "default", "default direct", "default direct eth0 extra", "default direct 1234567890123456", "default direct 1234567890123456789", "junk direct eth0", "10.1.1.1/8 direct eth0", "default bad eth0", "default\ndirect eth0", "default direct\neth0"};
  TEST_ASSERT_FALSE(route_parse(NULL, &route)); TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
  for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
    TEST_ASSERT_FALSE(route_parse(bad[i], &route)); TEST_ASSERT_EQUAL_UINT32(42, route.gateway);
  }
  TEST_ASSERT_TRUE(route_parse(" \tdefault\t1.2.3.4 eth0 \r\n", &route));
  TEST_ASSERT_EQUAL_UINT32(0, route.dest.addr); TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0x01020304, route.gateway); TEST_ASSERT_EQUAL_STRING("eth0", route.dev);
  TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 direct eth1", &route)); TEST_ASSERT_EQUAL_UINT32(0, route.gateway);
}

static void test_tables(void)
{
  const char *lines[] = {"default 1.2.3.4 eth0", "10.0.0.0/8 direct eth1", "10.1.0.0/16 direct eth2", "10.1.2.0/24 direct eth3", "10.1.2.128/25 direct eth4"};
  TEST_ASSERT_EQUAL_UINT(0, table_count(NULL)); TEST_ASSERT_NULL(table_lookup(NULL, 0)); table_destroy(NULL);
  for (int reverse = 0; reverse < 2; ++reverse) {
    fwd_table_t *table = table_create(); TEST_ASSERT_NOT_NULL(table); TEST_ASSERT_EQUAL_UINT(0, table_count(table));
    TEST_ASSERT_NULL(table_lookup(table, 0)); TEST_ASSERT_FALSE(table_add(table, NULL));
    route_t route;
    for (int j = 0; j < 5; ++j) {
      TEST_ASSERT_TRUE(route_parse(lines[reverse ? 4-j : j], &route)); TEST_ASSERT_TRUE(table_add(table, &route));
    }
    TEST_ASSERT_TRUE(route_parse("10.0.0.0/9 direct eth9", &route)); TEST_ASSERT_TRUE(table_add(table, &route));
    TEST_ASSERT_EQUAL_UINT(6, table_count(table)); TEST_ASSERT_FALSE(table_add(table, &route));
    TEST_ASSERT_FALSE(table_add(NULL, &route)); route.dest = (cidr_t){1, 0}; TEST_ASSERT_FALSE(table_add(table, &route));
    TEST_ASSERT_EQUAL_STRING("eth4", table_lookup(table, 0x0a0102c8)->dev);
    TEST_ASSERT_EQUAL_STRING("eth3", table_lookup(table, 0x0a010205)->dev);
    TEST_ASSERT_EQUAL_STRING("eth2", table_lookup(table, 0x0a010305)->dev);
    TEST_ASSERT_EQUAL_STRING("eth1", table_lookup(table, 0x0aff0305)->dev);
    TEST_ASSERT_EQUAL_STRING("eth0", table_lookup(table, 0x08080808)->dev);
    for (uint32_t i = 0; i < 20; ++i) {
      route = (route_t){.dest = {0xc0000000 + i, 32}, .dev = "host"}; TEST_ASSERT_TRUE(table_add(table, &route));
    }
    table_destroy(table);
  }
  fwd_table_t *table = table_create(); TEST_ASSERT_NOT_NULL(table);
  FILE *in = tmpfile(); TEST_ASSERT_NOT_NULL(in);
  fputs("# comment\n \t\n10.0.0.0/8 direct eth1 # ok\nbad route\ndefault direct eth0\n", in); rewind(in);
  size_t bad = 99;
  TEST_ASSERT_FALSE(table_load(NULL, in, &bad)); TEST_ASSERT_EQUAL_UINT(0, bad);
  TEST_ASSERT_FALSE(table_load(table, NULL, NULL));
  TEST_ASSERT_FALSE(table_load(table, in, &bad)); TEST_ASSERT_EQUAL_UINT(4, bad);
  TEST_ASSERT_EQUAL_UINT(1, table_count(table)); TEST_ASSERT_NULL(table_lookup(table, 0)); fclose(in);
  in = tmpfile(); TEST_ASSERT_NOT_NULL(in); fputs("10.0.0.0/8 direct eth1\n", in); rewind(in);
  TEST_ASSERT_FALSE(table_load(table, in, NULL)); fclose(in);
  in = tmpfile(); TEST_ASSERT_NOT_NULL(in); fputs("default direct eth0", in); rewind(in);
  TEST_ASSERT_TRUE(table_load(table, in, &bad)); TEST_ASSERT_EQUAL_UINT(0, bad); fclose(in);
  in = tmpfile(); TEST_ASSERT_NOT_NULL(in); TEST_ASSERT_TRUE(table_load(table, in, NULL)); fclose(in);
  table_destroy(table);
}
int main(void)
{
  UNITY_BEGIN(); RUN_TEST(test_addresses); RUN_TEST(test_subnets); RUN_TEST(test_routes); RUN_TEST(test_tables); return UNITY_END();
}
