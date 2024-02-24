#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

// sayHello fn breakpoint: should return 2 results

class Person
{
  std::string myname;

public:
  Person(std::string name) noexcept : myname(std::move(name)) {}

  std::string_view
  myName() const noexcept
  {
    return myname;
  }

  void
  sayHello(std::string_view greeting) noexcept
  {
    std::cout << myname << " says: " << greeting << std::endl;
  }
};

void
Person(int j)
{
  std::cout << " Person(" << j << ")" << std::endl;
}

void
sayHello(std::string_view greeting, const class Person &p, std::string_view greetedPerson) noexcept
{
  std::cout << p.myName() << " says to " << greetedPerson << ": " << greeting;
}

void
sayHello(std::string_view greeting, int number) noexcept
{
  std::cout << "number: " << number << " and greeting: " << std::quoted(greeting) << std::endl;
}

int
main(int argc, const char **argv)
{
  // Person is a free standing fn, Person::Person is a member function (constructor)
  // thus, a fn bkpt request should return 2 results for `Person`
  class Person me
  {
    "hello"
  };
  Person(10);

  me.sayHello("Hello");
  sayHello("Hello", me, "You");
  sayHello("Goobye", 19);
  std::cout << "hello world" << std::endl;
}