#pragma once

#include "common.h"
#include "interface/ui_command.h"
#include "interface/ui_result.h"
#include <cstdint>
#include <nlohmann/json_fwd.hpp>
#include <queue>
#include <unordered_map>
#include <vector>

struct ObjectFile;
struct Target;

using Pid = pid_t;
using Tid = pid_t;
namespace ui::dap {
class DAP;
struct Event;
} // namespace ui::dap

namespace cmd {
class Command;
};

namespace ui {
struct UICommand;
}

struct LWP;
enum class AddObjectResult : u8
{
  OK = 0,
  MMAP_FAILED,
  FILE_NOT_EXIST
};

/** -- A Singleton instance --. There can only be one. (well, there should only be one.)*/
class Tracer
{
public:
  static Tracer *Instance;
  friend struct ui::UICommand;
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
  void interrupt(LWP lwp) noexcept;

  // This will be removed in future work
  // but it's just to get something up-and-running
  bool waiting_for_ui() const noexcept;
  void continue_current_target() noexcept;
  bool wait_for_tracee_events() noexcept;
  void set_ui(ui::dap::DAP *dap) noexcept;
  void kill_ui() noexcept;
  void post_event(ui::UIResultPtr obj) noexcept;

  /** Receives a command and places it on the command queue to be executed. Thread-safe, but if re-entrant will
   * hang. */
  void accept_command(ui::UICommand *cmd) noexcept;

private:
  std::vector<std::unique_ptr<Target>> targets;
  Target *current_target = nullptr;
  std::vector<ObjectFile *> object_files;
  // N.B. to be removed in future work when an event-processing scheme
  // has been developed
  bool ui_wait;
  ui::dap::DAP *dap;
  SpinLock command_queue_lock;
  std::queue<ui::UICommand *> command_queue;
};
