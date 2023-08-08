#include "todo.h"
#include <array>
#include <iostream>
#include <vector>

static constexpr std::array<std::string_view, 10> names{"one", "two",   "three", "four", "five",
                                                        "six", "seven", "eight", "nine", "ten"};

void
do_test_stuff(int count)
{
  Todos todos{};
  std::cout << "creating " << count << " todos" << std::endl;
  for (auto i = 0; i < count; ++i) {
    std::string name = std::string{names[i]} + ":" + std::to_string(i); // BP1
    todos.add_todo(std::move(name), "foo");
  }
  std::cout << " going over todos..." << std::endl;
  for (auto i = 0; i < count; ++i) {
    todos.set_done(i, "that was quick");
  }
}

int
main(int, const char **)
{
  do_test_stuff(names.size());
}