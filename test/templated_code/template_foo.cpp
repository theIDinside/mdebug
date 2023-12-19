#include "template_foo.h"
#include "template.h"

TestObject::TestObject(int a_param, int b_param) noexcept : a(a_param), b(b_param) {}

bool
TestObject::_less_than() noexcept
{
  const auto res = less_than(a, b); // BP1
  return res;
}

bool
TestObject::_greater_than() noexcept
{
  const auto res = greater_than(a, b); // BP2
  return res;
}

bool
TestObject::_equals() noexcept
{
  const auto res = equals(a, b); // BP3
  return res;
}
