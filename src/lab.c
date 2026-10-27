#define _POSIX_C_SOURCE 200809L
#include "lab.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

struct fwd_table {
  route_t *routes;
  size_t count, capacity;
};

static bool decimal(const char **text, unsigned limit, unsigned *value)
{
  const char *p = *text;
  unsigned n = 0;
  if (*p < '0' || *p > '9') return false;
  if (*p == '0' && p[1] >= '0' && p[1] <= '9') return false;
  do {
    n = n * 10 + (unsigned)(*p++ - '0');
    if (n > limit) return false;
  } while (*p >= '0' && *p <= '9');
  *text = p;
  *value = n;
  return true;
}

bool ip_parse(const char *text, uint32_t *addr)
{
  uint32_t result = 0;
  if (!text || !addr) return false;
  for (unsigned i = 0; i < 4; ++i) {
    unsigned octet;
    if (!decimal(&text, 255, &octet)) return false;
    result = (result << 8) | octet;
    if (i < 3 && *text++ != '.') return false;
  }
  if (*text) return false;
  *addr = result;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  snprintf(out, IP_STR_LEN, "%u.%u.%u.%u", (unsigned)(addr >> 24),
           (unsigned)((addr >> 16) & 255), (unsigned)((addr >> 8) & 255),
           (unsigned)(addr & 255));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  char ip[IP_STR_LEN];
  cidr_t result;
  unsigned prefix;
  if (!text || !block) return false;
  const char *slash = strchr(text, '/');
  if (!slash || (size_t)(slash - text) >= sizeof ip) return false;
  memcpy(ip, text, (size_t)(slash - text));
  ip[slash - text] = '\0';
  const char *p = slash + 1;
  if (!ip_parse(ip, &result.addr) || !decimal(&p, 32, &prefix) || *p) return false;
  result.prefix = (uint8_t)prefix;
  *block = result;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char ip[IP_STR_LEN];
  ip_format(block.addr, ip);
  snprintf(out, CIDR_STR_LEN, "%s/%u", ip, block.prefix > 32 ? 32u : block.prefix);
}

uint32_t cidr_mask(uint8_t prefix)
{
  if (!prefix) return 0;
  return UINT32_MAX << (32 - (prefix > 32 ? 32 : prefix));
}
uint32_t cidr_network(cidr_t block) { return block.addr & cidr_mask(block.prefix); }
uint32_t cidr_broadcast(cidr_t block) { return block.addr | ~cidr_mask(block.prefix); }
uint32_t cidr_first_host(cidr_t block) { return cidr_network(block) + (block.prefix < 31); }
uint32_t cidr_last_host(cidr_t block) { return cidr_broadcast(block) - (block.prefix < 31); }
uint64_t cidr_host_count(cidr_t block)
{
  if (block.prefix >= 32) return 1;
  if (block.prefix == 31) return 2;
  return (UINT64_C(1) << (32 - block.prefix)) - 2;
}
bool cidr_contains(cidr_t block, uint32_t addr) { return (addr & cidr_mask(block.prefix)) == cidr_network(block); }
bool cidr_is_network(cidr_t block) { return block.addr == cidr_network(block); }

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  if (!out || !cidr_is_network(block) || !n || (n & (n - 1)) || i >= n) return false;
  unsigned prefix = block.prefix;
  for (uint32_t count = n; count > 1; count >>= 1) ++prefix;
  if (prefix > 32) return false;
  *out = (cidr_t){block.addr + (uint32_t)((uint64_t)i << (32 - prefix)), (uint8_t)prefix};
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  char fields[3][CIDR_STR_LEN];
  route_t result = {0};
  if (!line || !route) return false;
  while (isspace((unsigned char)*line)) ++line;
  for (unsigned i = 0; i < 3; ++i) {
    size_t length = 0;
    while (*line && !isspace((unsigned char)*line)) {
      if (length == sizeof fields[i] - 1) return false;
      fields[i][length++] = *line++;
    }
    if (!length) return false;
    fields[i][length] = '\0';
    if (i < 2) {
      if (*line != ' ' && *line != '\t') return false;
      while (*line == ' ' || *line == '\t') ++line;
    }
  }
  while (isspace((unsigned char)*line)) ++line;
  if (*line || strlen(fields[2]) >= DEV_NAME_LEN) return false;
  if (strcmp(fields[0], "default") && !cidr_parse(fields[0], &result.dest)) return false;
  if (!cidr_is_network(result.dest)) return false;
  if (strcmp(fields[1], "direct") && !ip_parse(fields[1], &result.gateway)) return false;
  strcpy(result.dev, fields[2]);
  *route = result;
  return true;
}

fwd_table_t *table_create(void) { return calloc(1, sizeof(fwd_table_t)); }
void table_destroy(fwd_table_t *table)
{
  if (!table) return;
  free(table->routes);
  free(table);
}
size_t table_count(const fwd_table_t *table) { return table ? table->count : 0; }
bool table_add(fwd_table_t *table, const route_t *route)
{
  if (!table || !route || !cidr_is_network(route->dest)) return false;
  for (size_t i = 0; i < table->count; ++i)
    if (table->routes[i].dest.addr == route->dest.addr && table->routes[i].dest.prefix == route->dest.prefix) return false;
  if (table->count == table->capacity) {
    // GCOVR_EXCL_START
    if (table->capacity > SIZE_MAX / sizeof(route_t) / 2) return false;
    // GCOVR_EXCL_STOP
    size_t capacity = table->capacity ? table->capacity * 2 : 8;
    route_t *routes = realloc(table->routes, capacity * sizeof *routes);
    if (!routes) return false; // GCOVR_EXCL_LINE
    table->routes = routes;
    table->capacity = capacity;
  }
  table->routes[table->count++] = *route;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  char *line = NULL;
  size_t capacity = 0, number = 0;
  bool ok = true;
  if (bad_line) *bad_line = 0;
  if (!table || !in) return false;
  while (getline(&line, &capacity, in) >= 0) {
    ++number;
    char *comment = strchr(line, '#');
    if (comment) *comment = '\0';
    char *p = line;
    while (isspace((unsigned char)*p)) ++p;
    if (!*p) continue;
    route_t route;
    if (!route_parse(p, &route) || !table_add(table, &route)) {
      if (bad_line) *bad_line = number;
      ok = false;
      break;
    }
  }
  if (ferror(in) || (!feof(in) && ok)) ok = false; // GCOVR_EXCL_LINE
  free(line);
  return ok;
}
const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  const route_t *best = NULL;
  if (!table) return NULL;
  for (size_t i = 0; i < table->count; ++i) {
    const route_t *route = &table->routes[i];
    if (cidr_contains(route->dest, dest) && (!best || route->dest.prefix > best->dest.prefix)) best = route;
  }
  return best;
}
