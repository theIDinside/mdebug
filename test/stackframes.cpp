#include "./templated_code/template.h"
#include <cstdio>
#include <sys/signal.h>
struct Foo
{
  int foo_value;
};
struct Bar
{
  Foo foo;
  int bar_value;
};

static int
quux(int acc, int a)
{
  return acc * a; // BP4
}

static int
baz(int a, int b, int times)
{
  int res_a = 1; // BPLine1
  int res_b = 1; // BP3
  while (times > 0) {
    res_a = quux(res_a, a);
    res_b = quux(res_b, b);
    --times;
  }
  if (!equals(res_a, res_b)) {
    printf("values are not equal: a=%d, b=%d", res_a, res_b);
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
  baz(a, b, 4); // BP2
}

static void
foo()
{
  bar(1, 2); // BP1
}

int
main(int argc, const char **argv)
{
  foo();
  Bar bar{.foo = Foo{.foo_value = 1}, .bar_value = 2};
}
