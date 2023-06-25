#pragma once

#include "target.h"
#include <cstdint>
#include <vector>

enum class AddObjectResult : u8
{
  OK = 0,
  MMAP_FAILED,
  FILE_NOT_EXIST,
};

class Tracer
{
public:
  Tracer() noexcept;
  void add_target(pid_t task_leader, const Path &path) noexcept;
  AddObjectResult add_object_file(const Path &path) noexcept;
  void new_thread(Pid pid, Tid tid) noexcept;
  void thread_exited(Tid tid, int status) noexcept;
  Target& get_target(pid_t pid) noexcept;
private:
  std::vector<Target> targets;
  std::vector<ObjectFile *> object_files;
};