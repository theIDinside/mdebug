#include "template.h"
#include "template_foo.h"
int
main(int argc, const char **argv)
{
  int a = 10;
  int b = 20;

  const auto a_lt_b = less_than(a, b);
  const auto a_gt_b = greater_than(a, b);
  const auto a_eq_b = equals(a, b);

  // For future tests that involves type parsing
  TemplateType<int> a_and_b{10, 20};
  TestObject obj{30, 40};

  const auto lt = obj._less_than();
  const auto gt = obj._greater_than();
  const auto eq = obj._equals();
}