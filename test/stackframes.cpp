#include <cstdio>
#include <sys/signal.h>

static int
quux(int acc, int a)
{
  return acc * a;
}

static int
baz(int a, int b, int times)
{
  int res_a = 1;
  int res_b = 1;
  while (times > 0) {
    res_a = quux(res_a, a);
    res_b = quux(res_b, b);
    --times;
  }
  return a * b;
}

void
raise_after_baz(int a, int b)
{
  int res = baz(a, b, 3);
  std::printf("Result: %d\n", res);
}

static void
bar(int a, int b)
{
  baz(a, b, 4);
}

static void
foo()
{
  bar(1, 2);
}

int
main(int argc, const char **argv)
{
  foo();
}