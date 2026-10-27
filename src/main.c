#include "lab.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void usage(void)
{
  puts("Usage: myapp info <address>/<prefix>\n       myapp split <network>/<prefix> <count>\n       myapp lookup <table-file> <address>...");
}

int main(int argc, char **argv)
{
  if (argc == 1) { usage(); return 0; }
  if (argc == 3 && !strcmp(argv[1], "info")) {
    cidr_t block;
    if (!cidr_parse(argv[2], &block)) {
      fprintf(stderr, "myapp: %s: invalid CIDR address\n", argv[2]); return 1;
    }
    char text[IP_STR_LEN];
    ip_format(block.addr, text); printf("address    %s\nprefix     /%u\n", text, block.prefix);
    ip_format(cidr_mask(block.prefix), text); printf("netmask    %s\n", text);
    ip_format(cidr_network(block), text); printf("network    %s\n", text);
    ip_format(cidr_broadcast(block), text); printf("broadcast  %s\n", text);
    ip_format(cidr_first_host(block), text); printf("first host %s\n", text);
    ip_format(cidr_last_host(block), text); printf("last host  %s\n", text);
    printf("hosts      %" PRIu64 "\n", cidr_host_count(block));
    return 0;
  }
  if (argc == 4 && !strcmp(argv[1], "split")) {
    cidr_t block, subnet;
    uint64_t count = 0;
    const char *p = argv[3];
    if (!*p) { fprintf(stderr, "myapp: empty subnet count\n"); return 1; }
    for (; *p; ++p) {
      if (*p < '0' || *p > '9' || (count = count * 10 + (unsigned)(*p - '0')) > UINT32_MAX) {
        fprintf(stderr, "myapp: %s: invalid subnet count\n", argv[3]); return 1;
      }
    }
    if (!cidr_parse(argv[2], &block) || !cidr_subnet(block, (uint32_t)count, 0, &subnet)) {
      fprintf(stderr, "myapp: invalid network or subnet count: %s %s\n", argv[2], argv[3]); return 1;
    }
    for (uint32_t i = 0; i < count; ++i) {
      char text[CIDR_STR_LEN];
      cidr_subnet(block, (uint32_t)count, i, &subnet);
      cidr_format(subnet, text); puts(text);
    }
    return 0;
  }
  if (argc >= 4 && !strcmp(argv[1], "lookup")) {
    FILE *in = fopen(argv[2], "r");
    if (!in) { fprintf(stderr, "myapp: %s: cannot open table\n", argv[2]); return 2; }
    fwd_table_t *table = table_create();
    size_t bad_line = 0;
    bool loaded = table_load(table, in, &bad_line);
    fclose(in);
    if (!loaded) {
      fprintf(stderr, "myapp: %s:%zu: %s\n", argv[2], bad_line,
              bad_line ? "not a valid route" : "cannot read or allocate table");
      table_destroy(table); return 2;
    }
    int status = 0;
    for (int i = 3; i < argc; ++i) {
      uint32_t addr;
      if (!ip_parse(argv[i], &addr)) {
        fprintf(stderr, "myapp: %s: malformed address\n", argv[i]); status = 1; continue;
      }
      const route_t *route = table_lookup(table, addr);
      if (!route) {
        printf("%s unreachable\n", argv[i]);
        if (!status) status = 3;
      } else {
        printf("%s", argv[i]);
        if (route->gateway) {
          char gateway[IP_STR_LEN]; ip_format(route->gateway, gateway);
          printf(" via %s", gateway);
        }
        printf(" dev %s\n", route->dev);
      }
    }
    table_destroy(table); return status;
  }
  fprintf(stderr, "myapp: invalid command or arguments\n");
  usage(); return 1;
}
