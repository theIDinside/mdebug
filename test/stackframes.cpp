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

int fib(int n);

int
fib2(int n)
{
  if (n <= 1) {
    return n;
  }
  return fib(n - 1) + fib(n - 2);
}

int
fib(int n)
{
  if (n <= 1) {
    return n;
  }
  return fib2(n - 1) + fib2(n - 2);
}

int
fibonacci(int n)
{
  if (n <= 1) {
    return n;
  }
  return fibonacci(n - 1) + fibonacci(n - 2);
}

static int
quux(int acc, int a)
{
  return acc * a; // BP4 D1
}

static int
baz(int a, int b, int times)
{
  int res_a = 1; // BPLine1
  int res_b = 1; // BP3 C1
  while (times > 0) {
    res_a = quux(res_a, a); // D2
    res_b = quux(res_b, b);
    int fibOfTimes = fibonacci(times);
    int test = fib(times);
    printf("fibonacci of %d=%d", times, fibOfTimes);
    --times;
  }

  if (!equals(res_a, res_b)) {
    printf("values are not equal: a=%d, b=%d", res_a, res_b);
  }
  return a * b; // #BAZ_RET_BP
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
  baz(a, b, 4); // BP2 B1
} // C2 D3

static void
foo()
{
  bar(1, 2); // BP1 A1
} // B2 C3 D4

int
main(int argc, const char **argv)
{
  foo();
  Bar bar{.foo = Foo{.foo_value = 1}, .bar_value = 2}; // A2 B3 C4 D5
  printf("bar.bar_value=%d\n", bar.bar_value);
  printf("Hello world!\n");
  printf("bar.bar_value=%d\n", bar.bar_value);
  return -15;
}
