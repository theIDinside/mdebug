#include <cstdint>
#include <cstdio>

void
print(const char *str, int i)
{
  std::printf("%s %d\n", str, i);
}

int
baz()
{
  print("baz", 20);
  return 20;
}

int
bar()
{
  print("bar", 10); // BP3
  return 10;
}

int
foo()
{
  int j = bar();
  j += baz();
  return j;
}

int
main(int argc, const char **argv)
{
  print("Hello world: %d", 100 * argc);
  int res = foo();              // BP1 - next line should end on 36, not somewhere inside foo, bar, baz or print.
  print("Goodbye world!", res); // BP2
  print(argv[0], argc);
  return 0;
}