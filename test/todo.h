// stupid code, just to add a few object files (.o, i.e. compilation units) to the test files.

#pragma once
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct Todo
{
  Todo(int id, std::string &&name, std::string &&desc);
  Todo(Todo &&) = default;
  Todo &operator=(Todo &&) = default;

  int id;
  std::string name;
  std::string description;
  std::string done_message;
};

class Todos
{
public:
  Todos() noexcept;
  ~Todos() = default;
  void add_todo(std::string &&name, std::string &&description);
  void set_done(int id, std::string &&done);
  std::vector<std::unique_ptr<Todo>>::iterator find_by_id(int id);

private:
  std::vector<std::unique_ptr<Todo>> todos;
  std::vector<std::unique_ptr<Todo>> done;
  int todo_ids;
};