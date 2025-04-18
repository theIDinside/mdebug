#include "./include/game.h"
#include "./include/inheritance.h"
#include "./include/people.h"

#include <array>
#include <iterator>
#include <memory>
#include <optional>

// This is a test-subject program for end-user-developers. We run manual debug sessions against this binary.
// For normal test suites' debug sessions, they use different test subjects (which are crafted exactly or that
// test). This binary is meant to contain a little bit of everything, and let a user do QA testing on it,
// basically.

void
variants()
{
  const auto boss = NPC::MakeBoss("Dragon", "Rat King", 10000, 2748, 999, 42);
  const auto friend_ = NPC::MakeFriend("Nobby Nobbs", 10);
  const auto critter = NPC::MakeMinion("rat", 5, 3, 22);

  printf("Can we print these using just DAP requests (particularly when using The Midas Debugger\n"); // VARIANT_BP
}

void
heap_allocated_variant()
{
  auto p = new Person{1, 2, "Three"};
  auto theLastOfUs = new NPC{.kind = NPCKind::Friend, .payload = {.buddy = {"Dina", 10000}}}; // VARIANT_POINTER
  printf("Heap allocated objects get printed correctly.");
}

enum class UnionTag : unsigned char
{
  Person,
  Employee,
  Boss
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

  const auto employees_array =
    std::to_array({Employee{{0, 42, "John"}, 1}, Employee{{0, 24, "Jane"}, 2}, Employee{{0, 67, "Connor"}, 3}});
  return check_if_employee(p, employees, std::size(employees)); // ARRAY_VARS_BP
}

void
optionals()
{
  std::optional<Employee> hasValue = Employee{{0, 42, "John"}, 1};
  std::optional<Employee> none = std::nullopt;

  std::optional<int> intHasValue = 42;
  std::optional<int> intNone = std::nullopt;

  printf("Algebraic Data Types should be a first class citizen. Really. It's 2024.\n"); // OPTIONAL_BP
}

void
derived()
{
  Derived derived{1, 2, 3};
  printf("Inheritance yay\n"); // INHERITANCE_BP
}

enum class Enum
{
  Foo,
  Bar,
  Baz
};

void
enums()
{
  const auto a = Enum::Foo;
  const auto b = Enum::Bar;
  const auto c = Enum::Baz;

  std::array<Enum, 3> arr{Enum::Baz, Enum::Bar, Enum::Foo};

  printf("Support for enums \n"); // ENUM_BP
}

int
main(int argc, const char **argv)
{
  auto ptr = std::make_unique<int>(1);
  std::unique_ptr<Person> person = std::make_unique<Person>(1, 36, "John Connor");
  std::unique_ptr<Person> null = nullptr;
  enums();
  heap_allocated_variant();
  variants();
  derived();
  optionals();
  // Check if we can do a variablesRequest for locals, and get `personId`, `age`, `p`, `p2`, `pcheck_one` and
  // `pcheck_two`
  int personId = 0;
  int age = 42;
  Person p{personId, 42, "John"};
  age = 1337; // LOCALS_BP
  printf("Hello John. Goodbye John.\n");
  Person p2{1337, age, "Jane"};
  bool pcheck_one = test(p);
  bool pcheck_two = test(p2);
  test({1337, age, "Jane"}); // MAIN_END
}