// trivial type
#include <iterator>
struct Person
{
  int pid;
  int age;
  const char *name;
};

// A multi-layered trivial type
struct Employee
{
  Person person;
  int id;
};

bool
check_if_employee(const Person &p, const Employee *employee, int employee_count)
{
  for (auto it = employee + 0; it < (employee + employee_count); ++it) {
    if (it->person.pid == p.pid)
      return true;
  }
  return false;
}

// Check to see if we can do a variablesRequest and properly return `id`, `age` and `name`
Person
person(int id, int age, const char *name)
{
  return Person{id, age, name}; // ARGS_BP
}

// test to see if we can parse and understand a C-array[3] of a structured type
bool
test(const Person &p)
{
  Employee employees[3] = {Employee{{0, 42, "John"}, 1}, Employee{{0, 24, "Jane"}, 2},
                           Employee{{0, 67, "Connor"}, 3}};
  return check_if_employee(p, employees, std::size(employees)); // ARRAY_VARS_BP
}

int
main(int argc, const char **argv)
{
  // Check if we can do a variablesRequest for locals, and get `personId`, `age`, `p`, `p2`, `pcheck_one` and
  // `pcheck_two`
  int personId = 0;
  int age = 42;
  Person p{personId, 42, "John"};
  age = 42; // LOCALS_BP
  Person p2{1337, age, "Jane"};
  bool pcheck_one = test(p);
  bool pcheck_two = test(p2);

  test({1337, age, "Jane"}); // MAIN_END
}