// trivial type
#include <iterator>
#include <optional>

class ParentA
{
public:
  ParentA(int a) noexcept : a(a) {}
  ~ParentA() noexcept = default;

protected:
  int a;
};

class ParentB
{
public:
  ParentB(int a, int b) noexcept : a(a), b(b) {}
  ~ParentB() noexcept = default;

protected:
  int a;
  int b;
};

class Derived : ParentA, ParentB
{
public:
  Derived(int aa, int ba, int bb) : ParentA(aa), ParentB(ba, bb) {}
};

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

enum class UnionTag : unsigned char
{
  None = 0,
  Some = 1
};

struct PrettyPrintMe
{
  UnionTag tag;
  Employee emp;
  Person p;

  static PrettyPrintMe
  Some(Employee e) noexcept
  {
    return PrettyPrintMe{UnionTag::Some, e};
  }

  static PrettyPrintMe
  None() noexcept
  {
    return PrettyPrintMe{UnionTag::None};
  }
};

bool
check_if_employee(const Person &p, const Employee *employee, int employee_count)
{
  for (auto it = employee + 0; it < (employee + employee_count); ++it) {
    if (it->person.pid == p.pid) {
      return true;
    }
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
  auto some = PrettyPrintMe::Some(employees[0]);
  auto none = PrettyPrintMe::None();
  return check_if_employee(p, employees, std::size(employees)); // ARRAY_VARS_BP
}

void
optionals()
{
  std::optional<Employee> hasValue = Employee{{0, 42, "John"}, 1};
  std::optional<Employee> none = std::nullopt;
  printf("Algebraic Data Types should be a first class citizen. Really. It's 2024.\n"); // TEST_OPT_BP
}

void
derived()
{
  Derived derived{1, 2, 3};
  printf("Inheritance yay\n"); // INHERITANCE_BP
}

int
main(int argc, const char **argv)
{
  derived();
  optionals();
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