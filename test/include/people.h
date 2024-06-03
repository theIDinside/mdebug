#pragma once
#include <array>

// (multi-layered) POD structs

struct Person
{
  int pid;
  int age;
  const char *name;
};

struct Employee
{
  Person person;
  int id;
};

template <std::size_t N> using EmployeeArray = Employee[N];
template <std::size_t N> using Employees = std::array<Employee, N>;