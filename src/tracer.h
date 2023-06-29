#pragma once

#include "common.h"
#include <cstdint>
#include <unordered_map>
#include <vector>

struct ObjectFile;
struct Target;

using Pid = pid_t;
using Tid = pid_t;

enum class AddObjectResult : u8
{
  OK = 0,
  MMAP_FAILED,
  FILE_NOT_EXIST,
};

class Tracer
{
public:
  static Tracer *Instance;
  Tracer() noexcept;
  void add_target(pid_t task_leader, const Path &path) noexcept;
  AddObjectResult add_object_file(const Path &path) noexcept;
  void new_task(Pid pid, Tid tid) noexcept;
  void thread_exited(Tid tid, int status) noexcept;
  Target &get_target(pid_t pid) noexcept;
  Target *get_current() noexcept;

  /// Create & Initialize IO thread that deals with input/output between the tracee/tracer
  /// and the client
  void init_io_thread() noexcept;

private:
  std::unordered_map<pid_t, Target> targets;
  Target *current_target = nullptr;
  std::vector<ObjectFile *> object_files;
};
