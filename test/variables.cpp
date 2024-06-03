// trivial type
#include <array>
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

enum class NPCKind : unsigned char
{
  Friend,
  Minion,
  Boss
};

struct Friend
{
  const char *name;
  int health;
};

struct Minion
{
  const char *type;
  int health;
  int damage;
  int id;
};

struct Boss
{
  const char *type;
  const char *name;
  int health;
  int damage;
  int id;
  int spells;
};

struct NPC
{
  NPCKind kind;
  union
  {
    Friend buddy;
    Minion critter;
    Boss boss;
  } payload;

  static NPC
  Boss(const char *t, const char *n, int health, int dmg, int id, int spells)
  {
    return NPC{.kind = NPCKind::Boss, .payload = {.boss = {t, n, health, dmg, id, spells}}};
  }

  static NPC
  Friend(const char *n, int h)
  {
    return NPC{.kind = NPCKind::Friend, .payload = {.buddy = {n, h}}};
  }
  static NPC
  Minion(const char *t, int h, int dmg, int id)
  {
    return NPC{.kind = NPCKind::Minion, .payload = {.critter = {t, h, dmg, id}}};
  }
};

void
variants()
{
  const auto boss = NPC::Boss("Dragon", "Rat King", 10000, 2748, 999, 42);
  const auto friend_ = NPC::Friend("Nobby Nobbs", 10);
  const auto critter = NPC::Minion("rat", 5, 3, 22);

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
  age = 42; // LOCALS_BP
  Person p2{1337, age, "Jane"};
  bool pcheck_one = test(p);
  bool pcheck_two = test(p2);

  test({1337, age, "Jane"}); // MAIN_END
}