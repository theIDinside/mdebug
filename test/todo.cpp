#include "todo.h"
#include "dynamic_lib.h"
#include <algorithm>
#include <cmath>
#include <iostream>

Todo::Todo(int id, std::string &&name, std::string &&desc)
    : id(id), name(std::move(name)), description(std::move(desc))
{
}

Todos::Todos() noexcept : todos(), todo_ids(0) {}

double
sq(double a)
{
  const auto res = a * a; // BP1
  const auto miles = convert_kilometers_to_miles(a);
  return res;
}

double
add_squares(double a, double b)
{
  return sq(a) + sq(b);
}

double
calculate_pyth(int a, int b)
{
  double c = std::sqrt(add_squares(static_cast<double>(a), static_cast<double>(b)));
  std::cout << "pythagoras: " << c << std::endl;
  return c;
}

void
Todos::add_todo(std::string &&name, std::string &&description)
{
  std::cout << "adding " << name << std::endl;
  todos.push_back(std::make_unique<Todo>(todo_ids++, std::move(name), std::move(description)));
}

void
Todos::set_done(int id, std::string &&done_msg)
{
  auto todo_it = find_by_id(id);
  auto sz = todos.size();
  if (todo_it != std::end(todos)) {
    (*todo_it)->done_message = std::move(done_msg);
    std::move(todo_it, todo_it + 1, std::back_inserter(done));
    todos.erase(todo_it);
  }
  calculate_pyth(sz, todos.size());
}

std::vector<std::unique_ptr<Todo>>::iterator
Todos::find_by_id(int id)
{
  auto it = std::find_if(todos.begin(), todos.end(), [id](auto &todo) { return todo->id == id; });
  return it;
}