#include <cstdio>

int
main(int, const char **argv)
{
  int res = printf("%s\n", argv[0]);
  return res;
}