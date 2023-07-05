#pragma once

#include "common.h"
#include <cstdint>
#include <unordered_map>
#include <vector>

struct ObjectFile;
struct Target;

using Pid = pid_t;
using Tid = pid_t;

struct LWP;

enum class AddObjectResult : u8
{
  OK = 0,
  MMAP_FAILED,
  FILE_NOT_EXIST
};

class Tracer
{
public:
  static Tracer *Instance;
  Tracer() noexcept;
  void add_target_set_current(pid_t task_leader, const Path &path) noexcept;
  void load_and_process_objfile(pid_t target, const Path &objfile_path) noexcept;
  AddObjectResult mmap_objectfile(const Path &path) noexcept;
  void new_task(Pid pid, Tid tid) noexcept;
  void thread_exited(LWP lwp, int status) noexcept;
  Target &get_target(pid_t pid) noexcept;
  Target *get_current() noexcept;

  /// Create & Initialize IO thread that deals with input/output between the tracee/tracer
  /// and the client
  void init_io_thread() noexcept;

private:
  std::vector<std::unique_ptr<Target>> targets;
  Target *current_target = nullptr;
  std::vector<ObjectFile *> object_files;
};
