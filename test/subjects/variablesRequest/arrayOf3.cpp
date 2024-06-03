#include "../include/people.h"
#include <cstdio>

using StupidEmployee = const Employee;

int
stdlib_employees()
{
  const auto employees =
    std::to_array({Employee{{0, 42, "John"}, 1}, Employee{{0, 24, "Jane"}, 2}, Employee{{0, 67, "Connor"}, 3}});
  return 0; // STDLIB_STRUCT_ARRAY_BP
}

int
employees()
{
  const Employee employees[3] = {Employee{{0, 42, "John"}, 1}, Employee{{0, 24, "Jane"}, 2},
                                 Employee{{0, 67, "Connor"}, 3}};

  StupidEmployee employees_typedef[3] = {Employee{{0, 42, "John"}, 1}, Employee{{0, 24, "Jane"}, 2},
                                         Employee{{0, 67, "Connor"}, 3}};
  return 0; // C_STRUCT_ARRAY_BP
}

int
stdlib_ints()
{
  auto arr = std::to_array({1, 2, 3});
  return 0; // STDLIB_C_ARRAY_BP;
}

int
ints()
{
  int arr[3]{1, 2, 3};
  return 0; // C_ARRAY_BP;
}

int
main()
{
  stdlib_employees();
  employees();
  stdlib_ints();
  ints();
}